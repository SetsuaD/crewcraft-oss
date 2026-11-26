//! T350c: the Teams reader (docs/IMPORT.md): saved Graph `chat`, `channel`, `conversationMember`, `user` and
//! `chatMessage` pages become an import bundle that `import` reads: one-to-one chats, group chats and channels with
//! expanded replies, senders mapped through users.json, HTML turned into plain text, original and edited times,
//! deletions, captured and uncaptured attachments, and system messages left out. Senders users.json does not name are
//! left out, counted, and fail the command after the bundle is written.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_server::import_bundle::read_bundle;
use crewcraft_server::import_teams::{html_to_text, iso_ms, read_teams};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::import::RoomKind;
use serde_json::{Value, json};

fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t350c-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn from(id: &str) -> Value {
    json!({"user": {"id": id, "displayName": "someone", "userIdentityType": "aadUser"}, "application": null, "device": null})
}

/// An export as the documented calls return it, plus the fields Graph adds that the reader ignores.
fn export(dir: &Path, with_stranger: bool) -> PathBuf {
    let export = dir.join("export");
    // Two pages, as `GET /users` returns them with @odata.nextLink.
    write(
        &export.join("users.json"),
        &json!([
            {"@odata.context": "users", "value": [{"id": "u-ana", "mail": "ANA@EXAMPLE.ORG", "displayName": "Ana"}]},
            {"value": [{"id": "u-bo", "mail": null, "userPrincipalName": "bo@example.org"}, {"id": "u-cy", "mail": "cy@example.org"}]}
        ]),
    );
    let mut chat_messages = vec![
        json!({"id": "1001", "messageType": "message", "createdDateTime": "2024-03-05T14:07:09.123Z", "lastModifiedDateTime": "2024-03-05T14:07:09.123Z",
               "deletedDateTime": null, "from": from("u-ana"), "body": {"contentType": "html", "content": "<p>Hi Bo &amp; welcome!</p><p>Plan:</p><ul><li>one</li><li>two&nbsp;&#8212; done</li></ul>"},
               "attachments": [{"id": "a1", "contentType": "reference", "name": "plan.pdf"}, {"id": "a2", "name": "lost.png"}], "importance": "normal"}),
        json!({"id": "1002", "messageType": "message", "createdDateTime": "2024-03-05T16:08:00+02:00", "lastModifiedDateTime": "2024-03-05T15:00:00Z",
               "deletedDateTime": null, "from": from("u-bo"), "body": {"contentType": "text", "content": "  thanks  "}}),
        json!({"id": "1003", "messageType": "message", "createdDateTime": "2024-03-05T15:01:00Z", "deletedDateTime": "2024-03-06T09:00:00Z",
               "from": from("u-bo"), "body": {"contentType": "html", "content": ""}}),
        json!({"id": "1004", "messageType": "systemEventMessage", "createdDateTime": "2024-03-05T15:02:00Z", "from": null,
               "body": {"contentType": "html", "content": "<systemEventMessage/>"}}),
    ];
    if with_stranger {
        chat_messages.push(json!({"id": "1005", "messageType": "message", "createdDateTime": "2024-03-05T15:03:00Z", "from": from("u-gone"),
                                  "body": {"contentType": "text", "content": "who am I?"}}));
    }
    write(
        &export.join("conversations").join("chat-ana-bo.json"),
        &json!({
            "chat": {"id": "19:ana-bo-chat", "topic": null, "chatType": "oneOnOne", "createdDateTime": "2024-03-01T00:00:00Z"},
            "members": [{"userId": "u-ana", "email": "ana@example.org"}, {"userId": "u-bo", "email": null}],
            "pages": [{"value": chat_messages}]
        }),
    );
    write(
        &export.join("conversations").join("team-launch.json"),
        &json!({
            "team": {"id": "team-1", "displayName": "Launch"},
            "channel": {"id": "19:general-channel", "displayName": "General"},
            "members": [{"userId": "u-ana"}, {"userId": "u-bo"}, {"userId": "u-cy"}],
            "pages": [{"value": [
                {"id": "2001", "messageType": "message", "createdDateTime": "2024-03-07T09:00:00Z", "from": from("u-cy"),
                 "body": {"contentType": "html", "content": "<div>Ship it <b>Friday</b>?</div>"},
                 "replies": [{"id": "2002", "replyToId": "2001", "messageType": "message", "createdDateTime": "2024-03-07T09:05:00Z",
                              "from": from("u-ana"), "body": {"contentType": "text", "content": "Yes"}}]}
            ]}]
        }),
    );
    fs::create_dir_all(export.join("files").join("1001")).unwrap();
    fs::write(export.join("files").join("1001").join("plan.pdf"), b"%PDF-1.7 plan").unwrap();
    export
}

#[test]
fn times_are_read_as_graph_writes_them() {
    assert_eq!(iso_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(iso_ms("2024-03-05T14:07:09.123Z"), Some(1_709_647_629_123));
    assert_eq!(iso_ms("2024-03-05T16:07:09.5+02:00"), Some(1_709_647_629_500));
    assert_eq!(iso_ms("2023-12-31T23:59:59Z"), Some(1_704_067_199_000));
    assert_eq!(iso_ms("2000-02-29T00:00:00-05:30"), Some(951_802_200_000));
    assert_eq!(iso_ms("2024-03-05T14:07:09.1234567Z"), Some(1_709_647_629_123), "Graph's seven fraction digits");
    for bad in ["", "2024-03-05", "2024-13-05T00:00:00Z", "2024-03-05 14:07:09Z", "1969-12-31T23:59:59Z", "2024-03-05T14:07:09"] {
        assert_eq!(iso_ms(bad), None, "{bad}");
    }
}

#[test]
fn html_becomes_plain_text() {
    assert_eq!(html_to_text("<p>a</p><p>b</p>"), "a\nb");
    assert_eq!(html_to_text("one<br>two<br/>three"), "one\ntwo\nthree");
    assert_eq!(html_to_text("<ul><li>x</li><li>y</li></ul>after"), "- x\n- y\nafter");
    assert_eq!(html_to_text("<style>p{color:red}</style><script>alert(1)</script>safe"), "safe");
    assert_eq!(html_to_text("&lt;tag&gt; &quot;q&quot; &#39;s&#39; &#x41; &unknown; & alone"), "<tag> \"q\" 's' A &unknown; & alone");
    assert_eq!(html_to_text("<p>a</p><p></p><p></p><p>b</p>"), "a\nb");
}

#[test]
fn an_export_becomes_a_bundle_that_imports() {
    let dir = scratch("chain");
    let out = dir.join("bundle");
    let report = read_teams(&export(&dir, false), &out).unwrap();
    assert_eq!((report.conversations, report.messages, report.system_messages), (2, 5, 1));
    assert_eq!((report.files_captured, report.files_not_captured), (1, 1));
    assert!(report.unmapped_senders.is_empty());
    assert_eq!(fs::read(out.join("files").join("1001").join("plan.pdf")).unwrap(), b"%PDF-1.7 plan");

    let bundle = read_bundle(&out).unwrap();
    assert_eq!(bundle.source, "teams");
    let chat = &bundle.rooms[0];
    assert_eq!(
        (chat.kind, chat.name.as_str(), chat.members.clone()),
        (RoomKind::Direct, "", vec!["ana@example.org".to_owned(), "bo@example.org".to_owned()])
    );
    let channel = &bundle.rooms[1];
    assert_eq!((channel.kind, channel.key.as_str(), channel.name.as_str()), (RoomKind::Channel, "team-1/19:general-channel", "Launch / General"));
    assert_eq!(channel.members.len(), 3, "members through users.json");

    let first = &bundle.messages[0];
    assert_eq!(first.author, "ana@example.org");
    assert_eq!(first.text, "Hi Bo & welcome!\nPlan:\n- one\n- two \u{2014} done");
    assert_eq!(first.sent_ms, 1_709_647_629_123);
    assert_eq!(first.edited_ms, None, "same as created");
    let files: Vec<(&str, bool)> = first.files.iter().map(|f| (f.name.as_str(), f.captured)).collect();
    assert_eq!(files, vec![("plan.pdf", true), ("lost.png", false)]);
    let thanks = &bundle.messages[1];
    assert_eq!((thanks.author.as_str(), thanks.text.as_str(), thanks.edited_ms), ("bo@example.org", "thanks", Some(1_709_650_800_000)));
    assert!(bundle.messages[2].deleted);
    let reply = bundle.messages.iter().find(|m| m.key == "2002").unwrap();
    assert_eq!((reply.reply_to.as_deref(), reply.room.as_str()), (Some("2001"), "team-1/19:general-channel"));

    // And the server imports it: the reply lands in its thread.
    let journal = dir.join("rooms.journal");
    let mut ds = DurableServer::open(&journal).unwrap();
    let imported = ds.import(&bundle, &|_| true, false).unwrap();
    assert!(imported.ok(), "{:?}", imported.refusals);
    assert_eq!((imported.rooms_created, imported.messages_added, imported.members_added), (2, 5, 5));
    assert!(imported.made_top_level.is_empty());
    assert_eq!(ds.found("cy@example.org", "Friday").len(), 1);
}

#[test]
fn unknown_senders_are_left_out_and_fail_the_command() {
    let dir = scratch("stranger");
    let report = read_teams(&export(&dir, true), &dir.join("bundle")).unwrap();
    assert_eq!(report.unmapped_senders.into_iter().collect::<Vec<_>>(), vec![("u-gone".to_owned(), 1)]);
    assert_eq!(report.messages, 5);

    let run = |export: &Path, out: &Path| {
        Command::new(env!("CARGO_BIN_EXE_crewcraft-server"))
            .args(["import-teams", "--export", export.to_str().unwrap(), "--out", out.to_str().unwrap()])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let failed = run(&dir.join("export"), &dir.join("bundle-2"));
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stdout).contains("sender \"u-gone\" is not in users.json: 1 messages left out"));
    assert!(dir.join("bundle-2").join("bundle.json").is_file(), "the bundle is still written");

    let clean = scratch("clean");
    let passed = run(&export(&clean, false), &clean.join("bundle"));
    assert!(passed.status.success(), "{}", String::from_utf8_lossy(&passed.stderr));
    // The output directory must be new.
    assert!(!run(&clean.join("export"), &clean.join("bundle")).status.success());
}
