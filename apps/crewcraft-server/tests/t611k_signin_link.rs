//! T611k: an invitation link can name how the person signs in (`signin=org` or `signin=password`); a server with an
//! identity provider writes `signin=org` into every invitation, and one without writes nothing, so the app offers the
//! right way in. Old links without `signin` still parse.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_enroll::invitation::{InvitationLink, LinkError, PREFIX};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_enroll::{EnrollmentCode, SignInWay};

const IDENTITY: &str = "[identity]\nsource = \"oidc\"\nissuer = \"https://id.example.org/application/o/chat/\"\nclient-id = \"chat\"\n";

fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t611k-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn server(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).output().unwrap()
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn base() -> String {
    let code = EnrollmentCode::from_bytes([7; 20]).to_display();
    let root = RootFingerprint::from_der(b"synthetic root certificate bytes");
    format!("{PREFIX}server=chat.example.org:7443&code={code}&root_sha256={root}")
}

#[test]
fn a_link_names_the_way_in_or_leaves_it() {
    let old = InvitationLink::parse(&base()).unwrap();
    assert_eq!(old.signin(), None, "an older link still parses");
    assert!(!old.to_string().contains("signin"));
    for (value, way) in [("org", SignInWay::Organization), ("password", SignInWay::Password)] {
        let link = InvitationLink::parse(&format!("{}&signin={value}", base())).unwrap();
        assert_eq!(link.signin(), Some(way));
        assert_eq!(InvitationLink::parse(&link.to_string()).unwrap(), link, "written back as read");
        assert!(link.to_string().ends_with(&format!("&signin={value}")));
    }
    assert_eq!(old.clone().with_signin(Some(SignInWay::Organization)).to_string(), format!("{}&signin=org", base()));
    for bad in ["&signin=sso", "&signin=", "&signin=org&signin=org", "&signin=ORG"] {
        assert_eq!(InvitationLink::parse(&format!("{}{bad}", base())), Err(LinkError::Parameter), "{bad}");
    }
}

fn invite(data: &Path, dir: &Path, email: &str) -> String {
    let file = dir.join(format!("{email}.txt"));
    let out = server(&["invite", path(data), email, "--invitation-file", path(&file)]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = fs::read_to_string(&file).unwrap();
    text.lines().find(|line| line.starts_with("crewcraft://")).unwrap().to_owned()
}

#[test]
fn a_server_with_an_identity_provider_says_org() {
    let dir = scratch("server");
    let data = dir.join("server");
    let first = dir.join("admin.txt");
    let out = server(&["first-run", path(&data), "--name", "chat.example.org", "--admin", "admin@example.org", "--invitation-file", path(&first)]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let plain = invite(&data, &dir, "one@example.org");
    assert_eq!(InvitationLink::parse(&plain).unwrap().signin(), None, "no provider: the person chooses");

    fs::write(data.join("identity.toml"), IDENTITY).unwrap();
    let org = invite(&data, &dir, "two@example.org");
    assert_eq!(InvitationLink::parse(&org).unwrap().signin(), Some(SignInWay::Organization));

    // A provider file that does not parse stops invitations, as it stops the server.
    fs::write(data.join("identity.toml"), "[identity]\nsource = \"magic\"\n").unwrap();
    let file = dir.join("three.txt");
    assert!(!server(&["invite", path(&data), "three@example.org", "--invitation-file", path(&file)]).status.success());
}
