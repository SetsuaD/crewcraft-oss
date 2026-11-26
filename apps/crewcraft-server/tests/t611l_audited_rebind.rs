//! T611l: an administrator re-binds an enrolled person to another identity at the organization's provider with
//! `crewcraft-server rebind`, and every re-bind is written to a tamper-evident audit log in the data directory, which
//! `crewcraft-server audit` shows and checks; a changed log no longer checks out, and refused re-binds record nothing.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_server::audit_file::{self, AUDIT_FILE};
use crewcraft_server::server_install;
use crewcraft_server_core::account_store::{Activation, FirstDevice};
use crewcraft_server_core::invites::Invite;

const ISSUER: &str = "https://id.example.org/application/o/chat/";

fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t611l-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn server(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).env("USER", "admin").output().unwrap()
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// A server data directory with two enrolled people, `one` bound to `sub-1`.
fn installation(dir: &Path) -> PathBuf {
    let data = dir.join("server");
    let first = dir.join("admin.txt");
    let out = server(&["first-run", path(&data), "--name", "chat.example.org", "--admin", "admin@example.org", "--invitation-file", path(&first)]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let (mut installation, _) = server_install::open(&data, now()).unwrap();
    for (email, n) in [("one@example.org", 1u8), ("two@example.org", 2u8)] {
        installation.accounts.issue_invite(Invite { email: email.into(), bootstrap_pub: [n; 32], expires_ms: now() + 600_000 }, now()).unwrap();
        installation
            .accounts
            .activate(
                Activation {
                    bootstrap_pub: [n; 32],
                    device_name: "laptop",
                    certificate: Box::leak(vec![0x30, 0x82, n, n].into_boxed_slice()),
                    spki_sha256: [n + 100; 32],
                    counter: 1000,
                    first_device: Some(FirstDevice { password_phc: None, totp_secret: b"synthetic-totp-AAAAA" }),
                    expected_device_id: None,
                },
                now(),
            )
            .unwrap();
    }
    installation.accounts.bind_external("one@example.org", ISSUER, "sub-1").unwrap();
    data
}

#[test]
fn a_rebind_is_done_and_audited() {
    let dir = scratch("rebind");
    let data = installation(&dir);
    let out = server(&["audit", path(&data)]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("The audit log is empty."));

    let out = server(&["rebind", path(&data), "one@example.org", "--issuer", ISSUER, "--subject", "sub-1-new"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let (installation, _) = server_install::open(&data, now()).unwrap();
    assert_eq!(installation.accounts.external_of("one@example.org"), Some((ISSUER, "sub-1-new")));
    assert_eq!(installation.accounts.person_for_external(ISSUER, "sub-1"), None, "the old identity signs in as no one");
    drop(installation);

    let entries = audit_file::read(&data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].actor, "operator admin");
    assert_eq!(entries[0].action, format!("identity.rebind one@example.org to {ISSUER} sub-1-new was {ISSUER} sub-1"));

    // Refusals change nothing and record nothing.
    for (email, subject) in [("nobody@example.org", "sub-x"), ("two@example.org", "sub-1-new")] {
        let out = server(&["rebind", path(&data), email, "--issuer", ISSUER, "--subject", subject]);
        assert!(!out.status.success(), "{email}");
    }
    assert_eq!(audit_file::read(&data).unwrap().len(), 1);

    // A second re-bind chains onto the first, and `audit` shows both and checks them.
    let out = server(&["rebind", path(&data), "two@example.org", "--issuer", ISSUER, "--subject", "sub-2"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = server(&["audit", path(&data)]);
    assert!(out.status.success());
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(shown.contains("2 entries; the chain checks out"), "{shown}");
    assert!(shown.contains("identity.rebind two@example.org to"), "{shown}");
}

#[test]
fn a_changed_log_no_longer_checks_out() {
    let dir = scratch("tamper");
    fs::create_dir_all(&dir).unwrap();
    audit_file::append(&dir, "operator", "identity.rebind a@example.org to x y was none", 1_000).unwrap();
    audit_file::append(&dir, "operator", "identity.rebind b@example.org to x z was none", 2_000).unwrap();
    assert_eq!(audit_file::read(&dir).unwrap().len(), 2);
    let file = dir.join(AUDIT_FILE);
    let text = fs::read_to_string(&file).unwrap();
    fs::write(&file, text.replace("b@example.org", "c@example.org")).unwrap();
    assert!(audit_file::read(&dir).is_err(), "an edited entry breaks the chain");
    // Removing the first entry breaks it too.
    let lines: Vec<&str> = text.lines().collect();
    fs::write(&file, format!("{}\n", lines[1])).unwrap();
    assert!(audit_file::read(&dir).is_err());
    // And appending refuses to build on a broken log.
    assert!(audit_file::append(&dir, "operator", "anything", 3_000).is_err());
    assert!(audit_file::append(&scratch("fields"), "operator", "two\tlines", 1).is_err(), "no control characters");
}
