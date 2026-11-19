//! T235: `crewcraft-server serve` stops cleanly when a service manager sends SIGTERM (Unix).
#![allow(clippy::unwrap_used, clippy::panic)]

#[cfg(unix)]
#[test]
fn serve_exits_cleanly_on_sigterm() {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crewcraft_server::server_install::{self, ServerConfig};
    use crewcraft_server::server_name::ServerName;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let scratch = std::env::temp_dir().join(format!("crewcraft-t235-{}-{now}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let data = scratch.join("server");
    // A port that was free a moment ago: the recorded listen address cannot be port zero.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let config = ServerConfig { name: ServerName::parse("chat.example.org").unwrap(), listen: format!("127.0.0.1:{port}").parse().unwrap() };
    drop(server_install::create(&data, &config, now).unwrap());

    let mut child = Command::new(env!("CARGO_BIN_EXE_crewcraft-server"))
        .arg("serve")
        .arg(&data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (lines, received) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let first = received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(first.starts_with("CrewCraft listening on"), "{first}");

    let pid = child.id().to_string();
    assert!(Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("serve did not stop within 5 s of SIGTERM");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "serve exited with {status}");
    assert_eq!(received.recv_timeout(Duration::from_secs(1)).unwrap(), "CrewCraft stopped.");
    // The state lock was released: the installation opens again at once.
    drop(server_install::open(&data, now).unwrap());
    let _ = std::fs::remove_dir_all(&scratch);
}
