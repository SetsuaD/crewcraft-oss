//! T350a: the import engine (docs/IMPORT.md): a bundle becomes read-only archive rooms holding its messages with their
//! original authors, times and threads; members without an account are reported and skipped; a re-run adds nothing;
//! a later run brings edits and deletions in, adds what is new and the people who now have accounts, and never
//! un-deletes; a dry run changes nothing; everything survives a restart; and every refusal is reported.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use crewcraft_server_core::cursor_log::Since;
use crewcraft_server_core::durable::{DurableError, DurableServer};
use crewcraft_server_core::import::{ARCHIVE_OWNER, Bundle, BundleFile, BundleMessage, BundleRoom, Report, RoomKind};
use crewcraft_server_core::room_service::{EventKind, ServiceError};
use crewcraft_server_core::server::ServerError;

const T0: u64 = 1_700_000_000_000;
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const CY: &str = "cy@example.org";

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t350a-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn message(room: &str, key: &str, author: &str, minute: u64, text: &str) -> BundleMessage {
    BundleMessage {
        room: room.into(),
        key: key.into(),
        author: author.into(),
        sent_ms: T0 + minute * 60_000,
        text: text.into(),
        reply_to: None,
        edited_ms: None,
        deleted: false,
        files: Vec::new(),
    }
}

/// Two conversations: Ana and Bo's direct chat, and a channel where Bo replies in a thread and Cy (no account yet)
/// writes too.
fn bundle() -> Bundle {
    let mut reply = message("ch1", "m3", BO, 3, "Agreed, Friday");
    reply.reply_to = Some("m2".into());
    let mut nested = message("ch1", "m4", ANA, 4, "a reply to the reply");
    nested.reply_to = Some("m3".into());
    let mut gone = message("ch1", "m5", CY, 5, "");
    gone.deleted = true;
    let mut with_file = message("dm1", "d2", BO, 2, "here is the plan");
    with_file.files = vec![BundleFile { name: "plan.pdf".into(), size: 1200, captured: false }];
    Bundle {
        source: "teams".into(),
        rooms: vec![
            BundleRoom { key: "dm1".into(), kind: RoomKind::Direct, name: String::new(), members: vec![ANA.into(), BO.into()] },
            BundleRoom { key: "ch1".into(), kind: RoomKind::Channel, name: "Project launch".into(), members: vec![ANA.into(), BO.into(), CY.into()] },
        ],
        // Out of time order on purpose: the engine imports oldest first.
        messages: vec![
            reply,
            message("dm1", "d1", ANA, 1, "hello Bo"),
            message("ch1", "m2", ANA, 2, "launch on Friday?"),
            with_file,
            nested,
            gone,
        ],
    }
}

fn has_account(people: &[&str]) -> impl Fn(&str) -> bool {
    let people: Vec<String> = people.iter().map(|p| (*p).to_owned()).collect();
    move |email: &str| people.iter().any(|p| p == email)
}

/// The room's messages as `(cursor, author, html)` with edits applied, read as `reader`, oldest first.
fn posts(ds: &DurableServer, slug: &str, reader: &str) -> Vec<(u64, String, String)> {
    let Since::Events(events) = ds.server().room(slug).unwrap().sync(reader, 0).unwrap() else { panic!("gap") };
    let mut out: Vec<(u64, String, String)> = Vec::new();
    for (cursor, event) in events {
        match event.kind {
            EventKind::Posted => out.push((cursor, event.actor, event.html)),
            EventKind::Edited { target } => {
                if let Some(post) = out.iter_mut().find(|(c, _, _)| *c == target) {
                    post.2 = event.html;
                }
            }
            _ => {}
        }
    }
    out
}

#[test]
fn a_bundle_becomes_read_only_archive_rooms() {
    let p = journal("first");
    let mut ds = DurableServer::open(&p).unwrap();
    let report = ds.import(&bundle(), &has_account(&[ANA, BO]), false).unwrap();
    assert!(report.ok(), "{:?}", report.refusals);
    assert_eq!((report.rooms_created, report.rooms_found, report.members_added), (2, 0, 4));
    assert_eq!((report.messages_added, report.messages_updated, report.messages_unchanged), (6, 0, 0));
    assert_eq!(report.files_not_imported, 1);
    assert_eq!(report.people_skipped.get("ch1"), Some(&BTreeSet::from([CY.to_owned()])), "no account yet");
    assert_eq!(report.made_top_level, vec!["m4".to_owned()], "a reply to a reply");

    let dm = ds.archive_room("teams", "dm1").unwrap().to_owned();
    let channel = ds.archive_room("teams", "ch1").unwrap().to_owned();
    let names: Vec<String> = ds.server().rooms_of(ANA).into_iter().map(|r| r.name).collect();
    assert_eq!(names, vec!["ana and bo", "Project launch"], "a direct conversation is named after its people");
    assert!(ds.server().rooms_of(CY).is_empty());

    // Original authors, in time order; the deleted message is held redacted.
    let channel_posts = posts(&ds, &channel, ANA);
    let authors: Vec<&str> = channel_posts.iter().map(|(_, a, _)| a.as_str()).collect();
    assert_eq!(authors, vec![ANA, BO, ANA, CY]);
    assert_eq!(channel_posts[3].2, "", "deleted in the source");
    let (launch, agreed) = (channel_posts[0].0, channel_posts[1].0);
    assert_eq!((ds.parent_of(&channel, agreed), ds.parent_of(&channel, channel_posts[2].0)), (Some(launch), None));
    assert_eq!(ds.imported_sent_ms(&channel, launch), Some(T0 + 2 * 60_000));
    assert_eq!(posts(&ds, &dm, BO).iter().map(|(_, _, h)| h.as_str()).collect::<Vec<_>>(), vec!["hello Bo", "here is the plan"]);
    // Search covers archive rooms.
    assert_eq!(ds.found(BO, "Friday").len(), 2);

    // Read-only: nothing can be written there, by anyone, and nothing is unread.
    let not_allowed = Err(DurableError::Server(ServerError::Service(ServiceError::NotAllowed)));
    assert_eq!(ds.post(&channel, ANA, "a new message", T0 * 2), not_allowed);
    assert_eq!(ds.edit(&channel, ANA, launch, "changed", T0 * 2), not_allowed);
    assert_eq!(ds.delete(&channel, ANA, launch), not_allowed);
    assert_eq!(ds.react(&channel, BO, launch, 1, true, T0 * 2), not_allowed);
    assert!(ds.reply(&channel, BO, launch, "in the thread", T0 * 2).is_err());
    assert_eq!(ds.delete(&channel, ARCHIVE_OWNER, launch), not_allowed, "not even its owner");
    assert_eq!(ds.server().room(&channel).unwrap().unread(BO), Ok(0));
    fs::remove_file(&p).unwrap();
}

#[test]
fn re_runs_add_nothing_and_later_runs_bring_changes_in() {
    let p = journal("again");
    let mut ds = DurableServer::open(&p).unwrap();
    ds.import(&bundle(), &has_account(&[ANA, BO]), false).unwrap();
    let again = ds.import(&bundle(), &has_account(&[ANA, BO]), false).unwrap();
    assert_eq!(
        again,
        Report {
            rooms_found: 2,
            messages_unchanged: 6,
            files_not_imported: 1,
            people_skipped: [("ch1".to_owned(), BTreeSet::from([CY.to_owned()]))].into(),
            ..Report::default()
        },
        "the same bundle twice"
    );

    // A later export: an edit, a deletion, a new message, the deleted one "back", and Cy now has an account.
    let mut later = bundle();
    later.messages[1].text = "hello Bo!".into();
    later.messages[1].edited_ms = Some(T0 + 10 * 60_000);
    later.messages[2].deleted = true;
    later.messages[5].deleted = false;
    later.messages[5].text = "I am back".into();
    later.messages.push(message("ch1", "m6", CY, 6, "new since the last export"));
    let report = ds.import(&later, &has_account(&[ANA, BO, CY]), false).unwrap();
    assert!(report.ok(), "{:?}", report.refusals);
    assert_eq!((report.messages_added, report.messages_updated, report.messages_unchanged), (1, 2, 4));
    assert_eq!(report.members_added, 1, "Cy");
    assert!(report.people_skipped.is_empty());

    let dm = ds.archive_room("teams", "dm1").unwrap().to_owned();
    let channel = ds.archive_room("teams", "ch1").unwrap().to_owned();
    assert_eq!(posts(&ds, &dm, ANA)[0].2, "hello Bo!", "the edit");
    let channel_posts = posts(&ds, &channel, CY);
    assert_eq!(channel_posts[0].2, "", "deleted since");
    assert_eq!(channel_posts[3].2, "", "never un-deleted");
    assert_eq!(channel_posts.last().unwrap().2, "new since the last export");
    drop(ds);

    // Everything survives a restart, and a re-run after it still adds nothing.
    let mut ds = DurableServer::open(&p).unwrap();
    assert_eq!(ds.archive_room("teams", "ch1"), Some(channel.as_str()));
    assert_eq!(posts(&ds, &dm, ANA)[0].2, "hello Bo!");
    assert_eq!(ds.parent_of(&channel, channel_posts[1].0), Some(channel_posts[0].0));
    assert_eq!(ds.imported_sent_ms(&channel, channel_posts[1].0), Some(T0 + 3 * 60_000));
    let after = ds.import(&later, &has_account(&[ANA, BO, CY]), false).unwrap();
    assert_eq!((after.messages_added, after.messages_updated, after.members_added), (0, 0, 0));
    fs::remove_file(&p).unwrap();
}

#[test]
fn a_dry_run_changes_nothing_and_reports_the_same() {
    let p = journal("dry");
    let mut ds = DurableServer::open(&p).unwrap();
    let dry = ds.import(&bundle(), &has_account(&[ANA, BO]), true).unwrap();
    assert!(ds.archive_room("teams", "ch1").is_none() && ds.server().rooms_of(ANA).is_empty());
    let size = fs::metadata(&p).unwrap().len();
    let real = ds.import(&bundle(), &has_account(&[ANA, BO]), false).unwrap();
    assert_eq!(dry, real);
    assert!(fs::metadata(&p).unwrap().len() > size);
    fs::remove_file(&p).unwrap();
}

#[test]
fn every_refusal_is_reported_and_skips_only_its_part() {
    let p = journal("refusals");
    let mut ds = DurableServer::open(&p).unwrap();
    let mut bad = bundle();
    bad.source = "Teams Export".into();
    let report = ds.import(&bad, &has_account(&[ANA]), false).unwrap();
    assert!(!report.ok() && report.refusals[0].at == "bundle" && report.rooms_created == 0);

    let mut bad = bundle();
    bad.rooms.push(BundleRoom { key: "dm1".into(), kind: RoomKind::Group, name: "again".into(), members: vec![] });
    bad.rooms.push(BundleRoom { key: "g2".into(), kind: RoomKind::Group, name: "Bad".into(), members: vec!["not an address".into()] });
    bad.rooms.push(BundleRoom { key: "g3".into(), kind: RoomKind::Direct, name: String::new(), members: vec![ANA.into()] });
    bad.messages.push(message("nowhere", "x1", ANA, 7, "lost"));
    bad.messages.push(message("ch1", "m2", ANA, 8, "the same key twice"));
    bad.messages.push(message("ch1", "x3", "nobody", 9, "who wrote this?"));
    bad.messages.push(message("ch1", "x4", ANA, 10, &"long ".repeat(1000)));
    bad.messages.push(message("ch1", "x5", ANA, 11, "   "));
    let report = ds.import(&bad, &has_account(&[ANA, BO]), false).unwrap();
    let at: Vec<&str> = report.refusals.iter().map(|r| r.at.as_str()).collect();
    assert_eq!(at, vec!["room 2", "room 3", "room 4", "message 6", "message 7", "message 8", "message 9", "message 10"]);
    assert_eq!((report.rooms_created, report.messages_added), (2, 6), "the good parts still imported");
    fs::remove_file(&p).unwrap();
}

#[test]
fn domains_can_be_remapped_first() {
    let mut moved = bundle();
    moved.map_domains(&[("EXAMPLE.org".into(), "example.com".into())]);
    assert_eq!(moved.rooms[1].members, vec!["ana@example.com", "bo@example.com", "cy@example.com"]);
    assert!(moved.messages.iter().all(|m| m.author.ends_with("@example.com")));
    let p = journal("domains");
    let mut ds = DurableServer::open(&p).unwrap();
    let report = ds.import(&moved, &has_account(&["ana@example.com"]), false).unwrap();
    assert_eq!(report.members_added, 2, "Ana in both rooms, under her new address");
    fs::remove_file(&p).unwrap();
}
