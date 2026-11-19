#![allow(clippy::unwrap_used)]

use std::process::{Command, Stdio};

#[test]
fn keeps_version_and_refuses_redirected_credential_prompts() {
    let executable = env!("CARGO_BIN_EXE_crewcraft");
    let version = Command::new(executable).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8(version.stdout).unwrap().starts_with("crewcraft "));

    let output = Command::new(executable)
        .args(["lab", "chat", "127.0.0.1:1", "absent.der", "invalid", "pilot@example.org", "pilot"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("private interactive terminal"));
    assert!(!error.contains("Invitation code"));
}
