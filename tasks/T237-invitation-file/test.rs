//! T237: a scripted install. `first-run` and `invite` write the invitation to a new owner-only file instead of the
//! terminal, so they run without one; nothing secret is printed, and an existing file is never overwritten.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_enroll::InvitationLink;

/// A private folder per test. The tag keeps parallel tests apart: clocks on some systems (macOS) tick in
/// microseconds, so two tests starting together could otherwise share one folder and remove each other's files.
fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t237-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The server binary with no terminal: stdin, stdout and stderr are pipes, as in a script or a service unit.
fn server(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).output().unwrap()
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn link_in(file: &Path) -> InvitationLink {
    let text = fs::read_to_string(file).unwrap();
    let line = text.lines().find(|line| line.starts_with("crewcraft://")).unwrap();
    InvitationLink::parse(line).unwrap()
}

#[test]
fn first_run_and_invite_write_the_invitation_to_a_new_private_file() {
    let dir = scratch("files");
    let data = dir.join("server");
    let admin_file = dir.join("admin-invitation.txt");

    let out = server(&[
        "first-run",
        path(&data),
        "--name",
        "chat.example.org",
        "--admin",
        "admin@example.org",
        "--listen",
        "127.0.0.1:7443",
        "--invitation-file",
        path(&admin_file),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("written to"), "{stdout}");
    assert!(!stdout.contains("crewcraft://") && !stdout.contains("Code "), "the secret went to the terminal: {stdout}");
    let link = link_in(&admin_file);
    assert_eq!(link.server(), "chat.example.org:7443");
    assert!(fs::read_to_string(&admin_file).unwrap().contains("Private invitation for admin@example.org"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&admin_file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // invite: the same, for another person, into another new file.
    let person_file = dir.join("person-invitation.txt");
    let out = server(&["invite", path(&data), "person@example.org", "--invitation-file", path(&person_file)]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_ne!(link_in(&person_file).to_string(), link_in(&admin_file).to_string());

    // An existing invitation file is never overwritten, and invite without a terminal or a file is refused.
    let before = fs::read(&person_file).unwrap();
    let out = server(&["invite", path(&data), "third@example.org", "--invitation-file", path(&person_file)]);
    assert!(!out.status.success());
    assert_eq!(fs::read(&person_file).unwrap(), before);
    let out = server(&["invite", path(&data), "third@example.org"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--invitation-file"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_invitation_file_is_refused_before_the_server_is_created() {
    let dir = scratch("refused");
    let taken = dir.join("taken.txt");
    fs::write(&taken, "something").unwrap();
    for (tag, file) in [("exists", taken.clone()), ("no-folder", dir.join("missing").join("invite.txt"))] {
        let data = dir.join(format!("server-{tag}"));
        let out = server(&["first-run", path(&data), "--name", "chat.example.org", "--admin", "admin@example.org", "--invitation-file", path(&file)]);
        assert!(!out.status.success(), "{tag}");
        assert!(!data.exists(), "{tag}: the server was created although its invitation could not be written");
    }
    assert_eq!(fs::read_to_string(&taken).unwrap(), "something");
    let _ = fs::remove_dir_all(&dir);
}
