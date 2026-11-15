#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_server::lab_installation::LabInstallation;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn installed_server_command_binds_only_loopback_and_keeps_original_version_output() {
    let executable = env!("CARGO_BIN_EXE_crewcraft-server");
    let version = Command::new(executable).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8(version.stdout).unwrap().starts_with("crewcraft-server "));

    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let directory = std::env::temp_dir().join(format!("crewcraft-command-{}-{}", std::process::id(), elapsed.as_nanos()));
    fs::create_dir(&directory).unwrap();
    let directory = TestDirectory(directory);
    let data = directory.0.join("state");
    let root = directory.0.join("root.der");
    let installation = LabInstallation::initialize(&data, u64::try_from(elapsed.as_millis()).unwrap()).unwrap();
    fs::write(&root, installation.issuer.root_certificate()).unwrap();
    drop(installation);

    let child = Command::new(executable)
        .args(["lab", "serve"]).arg(&data).arg(&root).arg("0")
        .stdout(Stdio::piped()).spawn().unwrap();
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(result.map(|_| line));
    });
    let line = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    let address: SocketAddr = line.trim_end().strip_prefix("CrewCraft lab listening on ").unwrap().parse().unwrap();
    assert!(address.is_ipv4() && address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let _peer = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
}
