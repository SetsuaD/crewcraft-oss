//! T350b: `crewcraft-server import` (docs/IMPORT.md): it reads a bundle directory strictly, imports it into a stopped
//! server's data directory, writes import-report.json beside the bundle, and exits non-zero when any part was refused;
//! a dry run changes nothing, and a second run adds nothing.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_server::import_bundle::{parse_domain_map, read_bundle};
use serde_json::{Value, json};

fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t350b-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn server(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).output().unwrap()
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A new server data directory under `dir`.
fn data_directory(dir: &Path) -> PathBuf {
    let data = dir.join("server");
    let invitation = dir.join("admin-invitation.txt");
    let out = server(&["first-run", path(&data), "--name", "chat.example.org", "--admin", "admin@example.org", "--invitation-file", path(&invitation)]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    data
}

fn bundle_json() -> Value {
    json!({
        "format": "crewcraft-import/1",
        "source": "teams",
        "rooms": [
            {"key": "dm1", "kind": "direct", "name": "", "members": ["Ana@Example.org", "bo@example.org"]},
            {"key": "ch1", "kind": "channel", "name": "Project launch", "members": ["ana@example.org", "bo@example.org"]}
        ],
        "messages": [
            {"room": "dm1", "key": "d1", "author": "ana@example.org", "sent_ms": 1_700_000_060_000u64, "text": "hello Bo"},
            {"room": "ch1", "key": "m1", "author": "ana@example.org", "sent_ms": 1_700_000_120_000u64, "text": "launch on Friday?"},
            {"room": "ch1", "key": "m2", "author": "bo@example.org", "sent_ms": 1_700_000_180_000u64, "text": "Agreed",
             "reply_to": "m1", "edited_ms": null, "deleted": false,
             "files": [{"name": "plan.pdf", "size": 3, "sha256": null, "path": "plan.pdf"}, {"name": "lost.png", "size": 9}]}
        ]
    })
}

/// A bundle directory under `dir` holding `value` as bundle.json, and one captured file.
fn bundle_directory(dir: &Path, name: &str, value: &Value) -> PathBuf {
    let bundle = dir.join(name);
    fs::create_dir_all(bundle.join("files")).unwrap();
    fs::write(bundle.join("bundle.json"), serde_json::to_vec_pretty(value).unwrap()).unwrap();
    fs::write(bundle.join("files").join("plan.pdf"), b"pdf").unwrap();
    bundle
}

fn report(bundle: &Path) -> Value {
    serde_json::from_slice(&fs::read(bundle.join("import-report.json")).unwrap()).unwrap()
}

#[test]
fn a_bundle_imports_once_and_a_dry_run_changes_nothing() {
    let dir = scratch("runs");
    let data = data_directory(&dir);
    let bundle = bundle_directory(&dir, "export", &bundle_json());

    let dry = server(&["import", path(&data), "--bundle", path(&bundle), "--dry-run"]);
    assert!(dry.status.success(), "{}", String::from_utf8_lossy(&dry.stderr));
    assert!(String::from_utf8_lossy(&dry.stdout).contains("Dry run: nothing was changed"));
    let first = report(&bundle);
    assert_eq!((first["dry_run"].clone(), first["rooms_created"].clone(), first["messages_added"].clone()), (json!(true), json!(2), json!(3)));
    // Nobody here has signed in yet: everyone is skipped, by room.
    assert_eq!(first["people_skipped"]["ch1"], json!(["ana@example.org", "bo@example.org"]), "addresses normalized");
    assert_eq!(first["files_not_imported"], json!(2));

    let real = server(&["import", path(&data), "--bundle", path(&bundle)]);
    assert!(real.status.success(), "{}", String::from_utf8_lossy(&real.stderr));
    let second = report(&bundle);
    assert_eq!((second["dry_run"].clone(), second["rooms_created"].clone(), second["ok"].clone()), (json!(false), json!(2), json!(true)));

    let again = server(&["import", path(&data), "--bundle", path(&bundle)]);
    assert!(again.status.success());
    let third = report(&bundle);
    assert_eq!((third["rooms_created"].clone(), third["rooms_found"].clone(), third["messages_added"].clone()), (json!(0), json!(2), json!(0)));
    assert_eq!(third["messages_unchanged"], json!(3));
}

#[test]
fn a_refused_part_is_reported_and_fails_the_run() {
    let dir = scratch("refused");
    let data = data_directory(&dir);
    let mut value = bundle_json();
    value["messages"].as_array_mut().unwrap().push(json!({"room": "ch1", "key": "m3", "author": "nobody", "sent_ms": 1, "text": "?"}));
    let bundle = bundle_directory(&dir, "export", &value);
    let out = server(&["import", path(&data), "--bundle", path(&bundle)]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 parts of the bundle were refused"));
    let written = report(&bundle);
    assert_eq!(written["refusals"], json!([{"at": "message 3", "reason": "the author is not an email address"}]));
    assert_eq!(written["messages_added"], json!(3), "the rest still imported");
}

#[test]
fn the_bundle_is_read_strictly() {
    let dir = scratch("strict");
    let mut unknown = bundle_json();
    unknown["rooms"][0]["topic"] = json!("not a field");
    let error = read_bundle(&bundle_directory(&dir, "unknown", &unknown)).unwrap_err().to_string();
    assert!(error.contains("room 0: unknown field \"topic\""), "{error}");

    let mut missing = bundle_json();
    missing["messages"][0].as_object_mut().unwrap().remove("sent_ms");
    let error = read_bundle(&bundle_directory(&dir, "missing", &missing)).unwrap_err().to_string();
    assert!(error.contains("message 0: missing field \"sent_ms\""), "{error}");

    let mut format = bundle_json();
    format["format"] = json!("crewcraft-import/2");
    assert!(read_bundle(&bundle_directory(&dir, "format", &format)).is_err());

    let mut escape = bundle_json();
    escape["messages"][2]["files"][0]["path"] = json!("../outside.pdf");
    let error = read_bundle(&bundle_directory(&dir, "escape", &escape)).unwrap_err().to_string();
    assert!(error.contains("message 2 file 0: path must be a plain relative path inside files/"), "{error}");

    // Captured only when the bytes are in the bundle.
    let bundle = read_bundle(&bundle_directory(&dir, "good", &bundle_json())).unwrap();
    let files: Vec<(&str, bool)> = bundle.messages[2].files.iter().map(|f| (f.name.as_str(), f.captured)).collect();
    assert_eq!(files, vec![("plan.pdf", true), ("lost.png", false)]);
    assert_eq!(bundle.rooms[0].members[0], "ana@example.org");
}

#[test]
fn domain_maps_and_options_are_checked() {
    assert_eq!(parse_domain_map("Old.Example.org=example.com"), Some(("old.example.org".into(), "example.com".into())));
    assert_eq!(parse_domain_map("a@b=c"), None);
    assert_eq!(parse_domain_map("nothing"), None);
    let dir = scratch("options");
    let data = data_directory(&dir);
    let bundle = bundle_directory(&dir, "export", &bundle_json());
    assert!(!server(&["import", path(&data)]).status.success(), "--bundle is required");
    assert!(!server(&["import", path(&data), "--bundle", path(&bundle), "--map-domain", "bad"]).status.success());
    assert!(!server(&["import", path(&data), "--bundle", path(&bundle), "--surprise"]).status.success());
    let moved = server(&["import", path(&data), "--bundle", path(&bundle), "--map-domain", "example.org=example.com", "--dry-run"]);
    assert!(moved.status.success(), "{}", String::from_utf8_lossy(&moved.stderr));
    assert_eq!(report(&bundle)["people_skipped"]["ch1"], json!(["ana@example.com", "bo@example.com"]));
}
