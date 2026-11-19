//! T238: `invite`, `room` and `add-member` work while `serve` runs. They reach the running server over a control socket
//! in its data directory that only the server's own account can use, and the change is live at once: an invited person
//! enrolls against the running server, and a new member sees the room. With the server stopped they open the
//! directory themselves, as before. Unix.
#![allow(clippy::unwrap_used, clippy::panic)]
#![cfg(unix)]

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::ChatSession;
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft_client_core::notify::Settings;
use crewcraft_enroll::InvitationLink;
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::request::FEATURE_LIST_ROOMS;
use crewcraft_proto::signin::SignIn;
use crewcraft_server::control::{self, SOCKET_FILE};
use crewcraft_server::server_install::{self, ServerConfig};
use crewcraft_server::server_name::ServerName;
use crewcraft_tls::{DeadlineSocket, client_config, connect};
use crewcraft_totp::{Totp, base32};
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const NAME: &str = "127.0.0.1";
const ADMIN: &str = "admin@example.org";
const PERSON: &str = "person@example.org";
const PASSWORD: &str = "synthetic admin socket password";
/// The re-run of this test binary that tries the socket as another account sets this to the socket's path.
const OTHER_ACCOUNT_PROBE: &str = "CREWCRAFT_T238_CONNECT_AS_OTHER";

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn cutoff() -> Instant {
    Instant::now() + WAIT
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        // Short: a Unix socket path has a small length limit.
        let path = std::env::temp_dir().join(format!("cc238{label}{}-{}", std::process::id(), nonce % 1_000_000_000));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// The server binary with no terminal, as a script or a service unit runs it.
fn server(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).output().unwrap()
}

fn succeeded(output: &Output) -> String {
    assert!(output.status.success(), "stdout {}\nstderr {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn install(dir: &Path) -> (PathBuf, u16) {
    let data = dir.join("data");
    // A port that was free a moment ago: the recorded listen address cannot be port zero.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let config = ServerConfig { name: ServerName::parse(NAME).unwrap(), listen: format!("127.0.0.1:{port}").parse().unwrap() };
    drop(server_install::create(&data, &config, wall_ms()).unwrap());
    (data, port)
}

/// `serve`, running, with its standard output read line by line.
struct Serving {
    child: Child,
    lines: Receiver<String>,
}

impl Serving {
    fn start(data: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_crewcraft-server"))
            .arg("serve")
            .arg(data)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let first = lines.recv_timeout(WAIT).unwrap();
        assert!(first.starts_with("CrewCraft listening on"), "{first}");
        Self { child, lines }
    }

    /// Stop it the way a service manager does, and check it stopped cleanly.
    fn terminate(mut self) {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "serve did not stop after SIGTERM");
            thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "serve exited with {status}");
        assert_eq!(self.lines.recv_timeout(Duration::from_secs(1)).unwrap(), "CrewCraft stopped.");
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn link_in(file: &Path) -> InvitationLink {
    let text = fs::read_to_string(file).unwrap();
    InvitationLink::parse(text.lines().find(|line| line.starts_with("crewcraft://")).unwrap()).unwrap()
}

fn totp_from(otpauth: &str) -> Totp {
    let secret = otpauth.split(['?', '&']).find_map(|part| part.strip_prefix("secret=")).unwrap();
    Totp::with_defaults(base32::decode(secret).unwrap()).unwrap()
}

/// Enroll a device from an invitation link, as the desktop app does, and return its client configuration and the
/// person's authenticator.
fn enroll(link: &InvitationLink) -> (Arc<ClientConfig>, Totp) {
    let endpoint = ServerEndpoint::from_invitation(link, WAIT).unwrap();
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let expected_spki = key.subject_public_key_info();
    let request =
        EnrollmentRequest { device_name: "Synthetic Test Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &expected_spki };
    let mut authenticator = None;
    let chain = endpoint
        .open_bootstrap(link.code(), WAIT)
        .unwrap()
        .enroll(request, |setup, _| {
            let totp = totp_from(setup.protected_uri());
            let code = totp.generate(wall_ms() / 1000);
            authenticator = Some(totp);
            FirstTotpCode::parse(code)
        })
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(endpoint.root_der().to_vec())).unwrap();
    let identity = (vec![chain.leaf, chain.issuer], PrivatePkcs8KeyDer::from(key.serialize_der()).into());
    (client_config(roots, Some(identity)).unwrap(), authenticator.unwrap())
}

type ClientStream = StreamOwned<ClientConnection, DeadlineSocket>;

/// Sign in and keep the session open. The code is the next step's: the enrollment code's step is spent, and the
/// server accepts one step of skew.
fn sign_in(port: u16, config: Arc<ClientConfig>, authenticator: &Totp) -> ChatSession<ClientStream, fn(&mut ClientStream, Instant)> {
    let socket = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), WAIT).unwrap();
    let tls = connect(socket, config, rustls::pki_types::ServerName::try_from(NAME.to_owned()).unwrap()).unwrap();
    let stream = StreamOwned::new(tls.conn, DeadlineSocket::new(tls.sock, cutoff()));
    let code = authenticator.generate((wall_ms() + STEP_MS) / 1000);
    let request = SignIn { email: PERSON, password: PASSWORD, code: &code };
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_LIST_ROOMS, client: "t238 test client".into() };
    let set_deadline: fn(&mut ClientStream, Instant) = |stream, deadline| stream.sock.set_deadline(deadline);
    ChatSession::connect(stream, set_deadline, &request, hello, Settings::new(PERSON), WAIT, cutoff()).unwrap()
}

fn room_slug(stdout: &str) -> String {
    stdout.trim_end().strip_prefix("Room ").unwrap().to_owned()
}

#[test]
fn the_commands_reach_the_running_server_and_its_changes_are_live() {
    let scratch = Scratch::new("a");
    let (data, port) = install(&scratch.0);
    let socket = data.join(SOCKET_FILE);
    let serving = Serving::start(&data);

    // The socket exists while serving, and only its owner can use it.
    let metadata = fs::symlink_metadata(&socket).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), fs::metadata(&data).unwrap().uid());

    // invite, while the server holds the data directory: the invitation is written to a new owner-only file.
    let invitation = scratch.0.join("invitation.txt");
    let stdout = succeeded(&server(&["invite", path(&data), PERSON, "--invitation-file", path(&invitation)]));
    assert!(stdout.contains("written to"), "{stdout}");
    assert!(!stdout.contains("crewcraft://") && !stdout.contains("Code "), "the secret went to the terminal: {stdout}");
    assert_eq!(fs::metadata(&invitation).unwrap().permissions().mode() & 0o777, 0o600);
    // invite still needs a private terminal or a file.
    let refused = server(&["invite", path(&data), "third@example.org"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--invitation-file"));

    // The link enrolls a device against the running server: no restart.
    let (device, authenticator) = enroll(&link_in(&invitation));

    // room and add-member, while serving; the new member sees the room when they sign in.
    let first = room_slug(&succeeded(&server(&["room", path(&data), ADMIN, "Pilot"])));
    assert_eq!(succeeded(&server(&["add-member", path(&data), &first, ADMIN, PERSON])).trim_end(), "Member added.");
    let mut chat = sign_in(port, device, &authenticator);
    assert_eq!(chat.list_rooms(wall_ms(), cutoff()).unwrap(), vec![first.clone()]);

    // A change made while they are signed in shows in their next room list.
    let second = room_slug(&succeeded(&server(&["room", path(&data), PERSON, "Second"])));
    let mut rooms = chat.list_rooms(wall_ms(), cutoff()).unwrap();
    rooms.sort();
    let mut expected = vec![first.clone(), second];
    expected.sort();
    assert_eq!(rooms, expected);
    drop(chat);

    // A request the server cannot do fails with the error the offline command gives.
    let online = server(&["add-member", path(&data), "no-such-room", ADMIN, PERSON]);
    assert!(!online.status.success());
    let bad_email = server(&["invite", path(&data), "not an address", "--invitation-file", path(&scratch.0.join("never.txt"))]);
    assert!(!bad_email.status.success());
    assert!(fs::symlink_metadata(scratch.0.join("never.txt")).is_err(), "a refused invitation wrote a file");

    // SIGTERM stops serving cleanly and removes the socket.
    serving.terminate();
    assert!(fs::symlink_metadata(&socket).is_err(), "the control socket outlived the server");

    // Stopped: the same commands open the directory themselves.
    let offline = server(&["add-member", path(&data), "no-such-room", ADMIN, PERSON]);
    assert!(!offline.status.success());
    assert_eq!(String::from_utf8_lossy(&offline.stderr), String::from_utf8_lossy(&online.stderr));
    let offline_bad = server(&["invite", path(&data), "not an address", "--invitation-file", path(&scratch.0.join("never.txt"))]);
    assert_eq!(String::from_utf8_lossy(&offline_bad.stderr), String::from_utf8_lossy(&bad_email.stderr));
    let third = room_slug(&succeeded(&server(&["room", path(&data), ADMIN, "Offline"])));
    succeeded(&server(&["add-member", path(&data), &third, ADMIN, PERSON]));
    let later = scratch.0.join("later.txt");
    succeeded(&server(&["invite", path(&data), "later@example.org", "--invitation-file", path(&later)]));
    assert!(link_in(&later).to_string().starts_with("crewcraft://enroll?"));
}

#[test]
fn a_socket_left_by_a_crash_is_replaced_and_never_blocks_the_commands() {
    let scratch = Scratch::new("b");
    let (data, _) = install(&scratch.0);
    let socket = data.join(SOCKET_FILE);
    // What a killed server leaves behind: the socket file, with nothing listening.
    drop(UnixListener::bind(&socket).unwrap());
    assert!(fs::symlink_metadata(&socket).unwrap().file_type().is_socket());

    // No server answers, so the command opens the directory itself.
    let offline = room_slug(&succeeded(&server(&["room", path(&data), ADMIN, "Before"])));
    assert!(!offline.is_empty());

    // serve replaces the stale socket and answers on the new one.
    let serving = Serving::start(&data);
    assert!(UnixStream::connect(&socket).is_ok());
    let online = room_slug(&succeeded(&server(&["room", path(&data), ADMIN, "During"])));
    assert_ne!(online, offline);
    serving.terminate();
    assert!(fs::symlink_metadata(&socket).is_err());

    // Something at the socket's path that is not a socket is never removed; the server serves without it, and the
    // commands then say the directory is in use.
    fs::write(&socket, b"not a socket").unwrap();
    let serving = Serving::start(&data);
    let refused = server(&["room", path(&data), ADMIN, "Blocked"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("in use"), "{}", String::from_utf8_lossy(&refused.stderr));
    serving.terminate();
    assert_eq!(fs::read(&socket).unwrap(), b"not a socket");
}

#[test]
fn another_account_is_refused_by_the_socket() {
    let scratch = Scratch::new("c");
    // Changing to another account needs the superuser; elsewhere the permissions are still checked above.
    if fs::metadata(&scratch.0).unwrap().uid() != 0 {
        eprintln!("not the superuser: the other-account check is skipped");
        return;
    }
    let (data, _) = install(&scratch.0);
    let serving = Serving::start(&data);
    let socket = data.join(SOCKET_FILE);
    let probe = |label: &str| {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "other_account_probe", "--test-threads=1", "--quiet"])
            .env(OTHER_ACCOUNT_PROBE, &socket)
            .uid(65534)
            .gid(65534)
            .stdout(Stdio::null())
            .status();
        match status {
            Ok(status) => assert_eq!(status.code(), Some(13), "{label}: another account reached the control socket ({status})"),
            // The test binary itself is out of that account's reach here; the modes are still checked above.
            Err(error) => eprintln!("{label}: could not run as another account ({error}); skipped"),
        }
    };
    // The test binary's folders must be reachable by that account.
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o711)).unwrap();
    // Through the private data directory.
    probe("private directory");
    // With the directory opened up, the socket's own mode still refuses.
    fs::set_permissions(&data, fs::Permissions::from_mode(0o711)).unwrap();
    probe("socket mode");
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    // The owner still gets in.
    assert!(UnixStream::connect(&socket).is_ok());
    serving.terminate();
}

/// Run only by `another_account_is_refused_by_the_socket`, as another account: exits 13 when the kernel refuses.
#[test]
fn other_account_probe() {
    let Some(socket) = std::env::var_os(OTHER_ACCOUNT_PROBE) else { return };
    let code = match UnixStream::connect(&socket) {
        Ok(_) => 0,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => 13,
        Err(_) => 1,
    };
    std::process::exit(code);
}

#[test]
fn messages_are_small_framed_and_strict() {
    let fields = [control::VERSION, "room", ADMIN, "General"];
    let payload = control::encode(&fields).unwrap();
    assert_eq!(payload[0], 4);
    assert_eq!(control::decode(&payload).unwrap(), fields);

    assert!(control::encode(&[]).is_err());
    assert!(control::encode(&["x"; control::MAX_FIELDS + 1]).is_err());
    let long = "x".repeat(control::MAX_FRAME);
    assert!(control::encode(&[&long]).is_err());

    let mut trailing = payload.clone();
    trailing.push(0);
    for refused in [&[][..], &[0][..], &[1, 0][..], &[1, 0, 2, b'a'][..], &[1, 0, 1, 0xff][..], &trailing[..], &[9, 0, 0][..]] {
        assert!(control::decode(refused).is_err(), "{refused:?}");
    }
}
