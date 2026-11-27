//! T239: the newcomer path from zero, as the README tells it. The real `crewcraft-server` binary runs `first-run`
//! (scripted, with `--invitation-file`), `serve` and `room`; the real desktop-app stack (controller, `join_from_link`,
//! enrollment, saved device, connection worker) joins from the invitation link in the file, sets up the authenticator
//! from the `otpauth://` entry the app shows (as an authenticator app would read it), signs in with a fresh code and
//! sends a message. The server is then stopped the way a service manager stops it and started again, and the message
//! is still there for an app opened afresh. Only wall time, nothing injected: the server makes its own secrets.
//! Unix only, because the stop is a SIGTERM (as in T235) and `room` reaches the running server over its control
//! socket (T238).
#![allow(clippy::unwrap_used, clippy::panic)]

#[cfg(unix)]
mod from_zero {
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::Arc;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crewcraft::app::{Controller, Wake, join_from_link};
    use crewcraft::key_vault::MemoryVault;
    use crewcraft::worker::WorkerConfig;
    use crewcraft_client_core::room_view::Shown;
    use crewcraft_desktop_ui::{Action, Update};
    use crewcraft_enroll::InvitationLink;
    use crewcraft_server_core::activation::ISSUER;
    use crewcraft_totp::{Totp, base32};
    use crewcraft_ui_model::Command as RoomCommand;
    use zeroize::Zeroizing;

    const WAIT: Duration = Duration::from_secs(20);
    const ADMIN: &str = "admin@example.org";
    const PASSWORD: &str = "synthetic from-zero test password";
    const MESSAGE: &str = "hello from a server built from zero";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("crewcraft-t239-{}-{now}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn path(p: &Path) -> &str {
        p.to_str().unwrap()
    }

    /// A one-shot server command with no terminal, as in a script.
    fn server(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).output().unwrap()
    }

    /// `crewcraft-server serve` as a child process; killed if the test fails before stopping it.
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

        /// Stop it as a service manager does (SIGTERM) and check it stopped cleanly.
        fn stop(mut self) {
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
            // The reader thread forwards the last lines after the process has gone; the channel closes at end of output.
            let rest: Vec<String> = self.lines.iter().collect();
            assert!(rest.iter().any(|line| line == "CrewCraft stopped."), "{rest:?}");
        }
    }

    impl Drop for Serving {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    fn quick() -> WorkerConfig {
        WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(400) }
    }

    fn no_wake() -> Wake {
        Arc::new(|| {})
    }

    fn poll_until(controller: &mut Controller, what: &str, want: impl Fn(&Update) -> bool) -> Vec<Update> {
        let deadline = Instant::now() + WAIT;
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let updates = controller.poll();
            let found = updates.iter().any(&want);
            seen.extend(updates);
            if found {
                return seen;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}; saw {seen:?}");
    }

    /// The first update `want` matched in what `poll_until` saw (more updates can follow it in the same batch).
    fn first<'a>(seen: &'a [Update], want: impl Fn(&Update) -> bool) -> Option<&'a Update> {
        seen.iter().find(|&update| want(update))
    }

    fn shows_text(update: &Update, room: &str, text: &str) -> bool {
        matches!(update, Update::Snapshot { room: shown_room, shown } if shown_room == room
            && shown.iter().any(|entry| matches!(entry, Shown::Line(line) if line.html.contains(text))))
    }

    /// What an authenticator app does with the entry: read the secret out of the `otpauth://` URI.
    fn authenticator_from(uri: &str) -> Totp {
        let query = uri.split_once('?').unwrap().1;
        let secret = query.split('&').find_map(|pair| pair.strip_prefix("secret=")).unwrap();
        let totp = Totp::with_defaults(base32::decode(secret).unwrap()).unwrap();
        // The entry is exactly the default one for this account, so the codes below are the ones a person would type.
        assert_eq!(totp.otpauth_uri(ISSUER, ADMIN), uri);
        totp
    }

    fn unix_seconds() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn a_newcomer_installs_a_server_joins_chats_and_the_message_survives_a_restart() {
        let scratch = Scratch::new();
        let data = scratch.0.join("server");
        let invitation_file = scratch.0.join("admin-invitation.txt");
        // A port that was free a moment ago: first-run records a fixed port, as invitations carry it.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");

        // 1. first-run: a new installation and the administrator's invitation, written to a new private file.
        let out = server(&[
            "first-run",
            path(&data),
            "--name",
            "localhost",
            "--admin",
            ADMIN,
            "--listen",
            &listen,
            "--invitation-file",
            path(&invitation_file),
        ]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let text = fs::read_to_string(&invitation_file).unwrap();
        let link = text.lines().find(|line| line.starts_with("crewcraft://")).unwrap().to_owned();
        assert_eq!(InvitationLink::parse(&link).unwrap().server(), format!("localhost:{port}"));

        // 2. serve, then create a room while it runs, as the README orders the commands.
        let serving = Serving::start(&data);
        let out = server(&["room", path(&data), ADMIN, "General"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8(out.stdout).unwrap();
        let room = stdout.trim().strip_prefix("Room ").unwrap_or_else(|| panic!("{stdout}")).to_owned();

        // 3. Join: the app parses the pasted link, fetches the root against its fingerprint and enrolls.
        let app_dir = scratch.0.join("app");
        // The app's key store outlives the app, as the operating system's does (T313).
        let vault = MemoryVault::new();
        let (mut app, updates) = Controller::start_with_vault(Some(app_dir.clone()), vault.opener(), join_from_link(WAIT), no_wake(), quick());
        assert_eq!(updates, vec![Update::NeedsEnrollment]);
        let action = Action::Enroll { link: Zeroizing::new(format!("{link}\n")), password: Zeroizing::new(PASSWORD.to_owned()) };
        assert!(app.act(action).is_empty(), "joining must not block the window");
        let setup = |update: &Update| matches!(update, Update::AuthenticatorSetup { .. } | Update::Failed(_));
        let seen = poll_until(&mut app, "the authenticator setup", setup);
        let totp = match first(&seen, setup) {
            Some(Update::AuthenticatorSetup { otpauth_uri }) => authenticator_from(otpauth_uri),
            other => panic!("expected the authenticator setup, got {other:?}"),
        };

        // 4. Authenticator: the current code confirms it. The server accepts one step either side and never the same
        // step twice, so the sign-in uses the next step's code instead of waiting 30 seconds for it.
        let step = totp.counter(unix_seconds());
        assert!(app.act(Action::ConfirmAuthenticator { code: Zeroizing::new(totp.generate_at_counter(step)) }).is_empty());
        let enrolled = |update: &Update| matches!(update, Update::Enrolled { .. } | Update::Failed(_));
        let seen = poll_until(&mut app, "enrollment", enrolled);
        assert!(matches!(first(&seen, enrolled), Some(Update::Enrolled { .. })), "{seen:?}");

        // 5. Sign in with email, password and a fresh code; the room the administrator made is listed.
        let code = Zeroizing::new(totp.generate_at_counter(step + 1));
        assert!(app.act(Action::SignIn { email: ADMIN.to_owned(), password: Zeroizing::new(PASSWORD.to_owned()), code }).is_empty());
        let signed_in = |update: &Update| matches!(update, Update::SignedIn { .. } | Update::Failed(_));
        let seen = poll_until(&mut app, "sign-in", signed_in);
        match first(&seen, signed_in) {
            Some(Update::SignedIn { email, rooms }) => {
                assert_eq!(email, ADMIN);
                assert!(rooms.contains(&room), "{room} not in {rooms:?}");
            }
            other => panic!("expected SignedIn, got {other:?}"),
        }

        // 6. Send a message and see it come back from the server.
        assert!(app.act(Action::Room(RoomCommand::Sync { room: room.clone() })).is_empty());
        assert!(app.act(Action::Room(RoomCommand::Post { room: room.clone(), text: MESSAGE.into() })).is_empty());
        poll_until(&mut app, "the message on screen", |update| shows_text(update, &room, MESSAGE));

        // 7. Restart the server. The open app loses the connection, stays signed in and resumes on its own (T240).
        serving.stop();
        let seen = poll_until(&mut app, "the lost connection", |update| matches!(update, Update::Failed(_)));
        assert!(!seen.contains(&Update::SignedOut), "{seen:?}");
        let serving = Serving::start(&data);
        let seen = poll_until(&mut app, "the resumed session", |update| matches!(update, Update::SignedIn { .. }));
        assert!(!seen.contains(&Update::SignedOut), "{seen:?}");
        drop(app);

        // 8. An app opened afresh holds no messages in memory and keeps none on disk, so what it shows comes from the
        // restarted server: the message is there.
        let (mut app, updates) = Controller::start_with_vault(Some(app_dir), vault.opener(), join_from_link(WAIT), no_wake(), quick());
        assert!(matches!(updates.first(), Some(Update::Enrolled { .. })), "{updates:?}");
        assert!(updates.contains(&Update::LastEmail(ADMIN.to_owned())), "{updates:?}");
        let seen = poll_until(&mut app, "the session resumed at start", signed_in);
        assert!(matches!(first(&seen, signed_in), Some(Update::SignedIn { .. })), "{seen:?}");
        assert!(app.act(Action::Room(RoomCommand::Sync { room: room.clone() })).is_empty());
        poll_until(&mut app, "the message after the restart", |update| shows_text(update, &room, MESSAGE));

        drop(app);
        serving.stop();
    }
}
