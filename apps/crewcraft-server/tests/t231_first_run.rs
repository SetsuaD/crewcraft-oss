//! The server's first-run setup, its recorded settings and the commands that read them. Task T231.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_enroll::EnrollmentCode;
use crewcraft_server::server_install::{self, CONFIG_FILE, DEFAULT_PORT, PUBLIC_ROOT, ServerConfig};
use crewcraft_server::server_name::ServerName;

const NOW_MS: u64 = 1_800_000_000_000;
const NAME: &str = "chat.example.org";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t231-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(listen: &str) -> ServerConfig {
    ServerConfig { name: ServerName::parse(NAME).unwrap(), listen: listen.parse().unwrap() }
}

#[test]
fn settings_round_trip_and_anything_unclear_is_refused() {
    for listen in ["0.0.0.0:7443", "127.0.0.1:9000", "[::]:7443", "[2001:db8::5]:443"] {
        let recorded = config(listen);
        assert_eq!(ServerConfig::decode(&recorded.encode()).unwrap(), recorded);
    }
    let by_hand = "# written by hand\n\n  name =  Chat.Example.Org \nlisten=192.0.2.10:7443\n";
    assert_eq!(ServerConfig::decode(by_hand).unwrap(), config("192.0.2.10:7443"));
    assert_eq!(ServerConfig::default_listen(), SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)));

    for refused in [
        "",
        "name = chat.example.org\n",
        "listen = 0.0.0.0:7443\n",
        "name = chat.example.org\nlisten = 0.0.0.0:0\n",
        "name = chat.example.org\nlisten = 0.0.0.0\n",
        "name = chat.example.org\nlisten = chat.example.org:7443\n",
        "name = *.example.org\nlisten = 0.0.0.0:7443\n",
        "name = chat.example.org\nname = chat.example.org\nlisten = 0.0.0.0:7443\n",
        "name = chat.example.org\nlisten = 0.0.0.0:7443\nport = 1\n",
        "name chat.example.org\nlisten = 0.0.0.0:7443\n",
    ] {
        assert_eq!(ServerConfig::decode(refused).err().map(|error| error.kind()), Some(io::ErrorKind::InvalidData), "{refused:?}");
    }
}

#[test]
fn links_carry_the_server_with_its_port_the_code_and_the_root_pin() {
    let code = EnrollmentCode::from_bytes([7; 20]).to_display();
    let pin = [0xab; 32];
    let server = config("0.0.0.0:7443").public_server();
    assert_eq!(server, "chat.example.org:7443");
    assert_eq!(
        server_install::enrollment_link(&server, &code, &pin),
        format!("crewcraft://enroll?server={server}&code={code}&root_sha256={}", "ab".repeat(32))
    );

    let v6 = ServerConfig { name: ServerName::parse("2001:db8::1").unwrap(), listen: "[::]:8443".parse().unwrap() };
    assert_eq!(v6.public_server(), "[2001:db8::1]:8443");
    let link = server_install::enrollment_link(&v6.public_server(), &code, &[0; 32]);
    assert_eq!(link, format!("crewcraft://enroll?server=%5B2001:db8::1%5D:8443&code={code}&root_sha256={}", "0".repeat(64)));
}

#[test]
fn create_records_the_settings_and_root_and_never_touches_an_existing_installation() {
    let directory = TestDirectory::new();
    let data = directory.0.join("server");
    let recorded = config("0.0.0.0:7443");
    let (installation, root) = server_install::create(&data, &recorded, NOW_MS).unwrap();
    assert_eq!(server_install::read_config(&data).unwrap(), recorded);
    assert_eq!(fs::read(data.join(PUBLIC_ROOT)).unwrap(), root.certificate_der);
    assert_eq!(server_install::root_sha256(&data).unwrap(), root.sha256);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&data).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(data.join(CONFIG_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
    }
    drop(installation);

    let settings = fs::read(data.join(CONFIG_FILE)).unwrap();
    let again = server_install::create(&data, &config("127.0.0.1:9000"), NOW_MS).err().unwrap();
    assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(data.join(CONFIG_FILE)).unwrap(), settings);
    let empty = directory.0.join("empty");
    fs::create_dir(&empty).unwrap();
    assert_eq!(server_install::create(&empty, &recorded, NOW_MS).err().unwrap().kind(), io::ErrorKind::AlreadyExists);
    assert!(fs::read_dir(&empty).unwrap().next().is_none());

    let (reopened, read_back) = server_install::open(&data, NOW_MS).unwrap();
    assert_eq!(read_back, recorded);
    // The settings are checked while the state is held, so a second opener is refused.
    assert_eq!(server_install::open(&data, NOW_MS).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    drop(reopened);

    // State from another installation does not open with this root.
    let other = directory.0.join("other");
    drop(server_install::create(&other, &recorded, NOW_MS).unwrap());
    fs::copy(other.join(PUBLIC_ROOT), data.join(PUBLIC_ROOT)).unwrap();
    assert!(server_install::open(&data, NOW_MS).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(other.join(CONFIG_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(server_install::read_config(&other).err().unwrap().kind(), io::ErrorKind::PermissionDenied);
    }
}

#[test]
fn the_commands_refuse_unsafe_first_runs_and_serve_the_recorded_settings() {
    let executable = env!("CARGO_BIN_EXE_crewcraft-server");
    let help = Command::new(executable).arg("--help").output().unwrap();
    assert!(help.status.success());
    let usage = String::from_utf8(help.stdout).unwrap();
    for command in ["first-run", "serve", "invite", "room", "add-member", "lab init"] {
        assert!(usage.contains(&format!("crewcraft-server {command} ")), "{command}");
    }

    let directory = TestDirectory::new();
    let first_run = |data: &PathBuf, extra: &[&str]| {
        let mut command = Command::new(executable);
        command.arg("first-run").arg(data).args(["--name", NAME, "--admin", "admin@example.org"]).args(extra);
        command.stdin(Stdio::null()).output().unwrap()
    };
    let existing = directory.0.join("existing");
    fs::create_dir(&existing).unwrap();
    let refused = first_run(&existing, &[]);
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr).unwrap().contains("already exists"));
    assert!(fs::read_dir(&existing).unwrap().next().is_none());

    // The administrator's code is shown only in a private terminal, so nothing is created without one.
    let fresh = directory.0.join("fresh");
    let refused = first_run(&fresh, &["--listen", "0.0.0.0:7443"]);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8(refused.stderr).unwrap().contains("private interactive terminal"));
    assert!(fs::symlink_metadata(&fresh).is_err());
    for bad in [&["--listen", "0.0.0.0:0"][..], &["--listen", "nowhere"], &["--name", "second.example.org"], &["--colour", "blue"], &["--listen"]] {
        let refused = first_run(&fresh, bad);
        assert!(!refused.status.success(), "{bad:?}");
        assert!(fs::symlink_metadata(&fresh).is_err());
    }
    let bad_name =
        Command::new(executable).arg("first-run").arg(&fresh).args(["--name", "*.example.org", "--admin", "admin@example.org"]).output().unwrap();
    assert!(!bad_name.status.success());
    assert!(fs::symlink_metadata(&fresh).is_err());

    // Without a terminal, set the installation up through the library and drive the other commands.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let data = directory.0.join("server");
    // The commands run on the wall clock, so the certificate authority must already be valid.
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    drop(server_install::create(&data, &config(&format!("127.0.0.1:{port}")), now_ms).unwrap());
    let invite = Command::new(executable).arg("invite").arg(&data).arg("peer@example.org").stdin(Stdio::null()).output().unwrap();
    assert!(!invite.status.success());
    assert!(invite.stdout.is_empty());
    let room = Command::new(executable).arg("room").arg(&data).args(["admin@example.org", "Pilot"]).output().unwrap();
    assert!(room.status.success(), "{}", String::from_utf8_lossy(&room.stderr));
    let output = String::from_utf8(room.stdout).unwrap();
    let slug = output.trim_end().strip_prefix("Room ").unwrap().to_owned();
    let member =
        Command::new(executable).arg("add-member").arg(&data).args([slug.as_str(), "admin@example.org", "peer@example.org"]).output().unwrap();
    assert!(member.status.success(), "{}", String::from_utf8_lossy(&member.stderr));

    let child = Command::new(executable).arg("serve").arg(&data).stdout(Stdio::piped()).spawn().unwrap();
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(result.map(|_| line));
    });
    let line = rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
    assert_eq!(line.trim_end(), format!("CrewCraft listening on 127.0.0.1:{port} as {NAME}:{port}"));
    let _peer = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(1)).unwrap();
}
