//! T350e: imported media (docs/IMPORT.md): a captured file is stored as an upload is (checked against the bundle's
//! size and SHA-256) and attached to its imported message, where members can download it; a file the export did not
//! capture is attached by name and size only, with the "not archived" id; a later run stores what is newly captured
//! and never drops a file already stored; it all survives a restart; and a dry run stores nothing.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::push::{Push, decode_push};
use crewcraft_proto::request::{FEATURE_FILES, Request, encode_request};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::{DownloadError, DurableServer};
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::import::{Bundle, BundleFile, BundleMessage, BundleRoom, RoomKind};
use crewcraft_server_core::import_media::NOT_ARCHIVED;
use sha2::{Digest, Sha256};

const T0: u64 = 1_700_000_000_000;
const ANA: &str = "ana@example.org";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("t350e-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(dir: &Path) -> DurableServer {
    DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap()
}

fn captured(dir: &Path, name: &str, bytes: &[u8], declare: bool) -> BundleFile {
    let path = dir.join("export").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    let sha256 = declare.then(|| <[u8; 32]>::from(Sha256::digest(bytes)));
    BundleFile { name: name.into(), size: bytes.len() as u64, captured: true, source: Some(path), sha256 }
}

fn lost(name: &str, size: u64) -> BundleFile {
    BundleFile { name: name.into(), size, captured: false, source: None, sha256: None }
}

fn bundle(files: Vec<BundleFile>) -> Bundle {
    Bundle {
        source: "teams".into(),
        rooms: vec![BundleRoom { key: "c1".into(), kind: RoomKind::Group, name: "Old team".into(), members: vec![ANA.into()] }],
        messages: vec![BundleMessage {
            room: "c1".into(),
            key: "m1".into(),
            author: "bo@example.org".into(),
            sent_ms: T0,
            text: "the files".into(),
            reply_to: None,
            edited_ms: None,
            deleted: false,
            files,
        }],
    }
}

/// The imported message's cursor: the room's first event is Ana joining.
const MESSAGE: u64 = 2;

#[test]
fn captured_files_are_stored_and_the_rest_are_not_archived() {
    let scratch = Scratch::new("store");
    let plan = b"%PDF-1.7 the plan".to_vec();
    let mut ds = open(&scratch.0);
    let files = vec![captured(&scratch.0, "plan.pdf", &plan, true), lost("photo.jpg", 2048)];
    let dry = ds.import(&bundle(files.clone()), &|_| true, true).unwrap();
    assert_eq!((dry.files_stored, dry.files_not_archived), (1, 1));
    let report = ds.import(&bundle(files), &|_| true, false).unwrap();
    assert!(report.ok(), "{:?}", report.refusals);
    assert_eq!((report.files_stored, report.files_not_archived), (1, 1));
    assert_eq!(report, dry, "the dry run said the same");

    let slug = ds.archive_room("teams", "c1").unwrap().to_owned();
    let attached = ds.attachments(&slug, MESSAGE);
    let shown: Vec<(&str, u64, bool)> = attached.iter().map(|f| (f.name.as_str(), f.size, f.file == NOT_ARCHIVED)).collect();
    assert_eq!(shown, vec![("plan.pdf", plan.len() as u64, false), ("photo.jpg", 2048, true)]);
    assert_eq!(ds.download(ANA, &attached[0].file, 0, 1024).unwrap(), plan, "a member downloads it");
    assert_eq!(ds.download("eve@example.org", &attached[0].file, 0, 1024), Err(DownloadError::NotFound));
    assert_eq!(ds.download(ANA, &NOT_ARCHIVED, 0, 1024), Err(DownloadError::NotFound));

    // A client that agreed to files is sent both, after the message.
    let sync = encode(&encode_request(1, &Request::Sync { room: slug.clone(), cursor: 0 }).unwrap()).unwrap();
    let out = Connection::with_features(ANA, FEATURE_FILES).receive_durable(&mut ds, &sync, T0).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let mut pushes = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        pushes.push(frame);
    }
    let pushed: Vec<Push> = pushes.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect();
    assert!(pushed.iter().any(|push| matches!(push, Push::Attached { cursor: MESSAGE, files, .. } if files.len() == 2)));
}

#[test]
fn a_later_run_stores_what_is_newly_captured_and_never_drops_a_file() {
    let scratch = Scratch::new("later");
    let photo = vec![7u8; 2048];
    let mut ds = open(&scratch.0);
    ds.import(&bundle(vec![captured(&scratch.0, "plan.pdf", b"plan", false), lost("photo.jpg", 2048)]), &|_| true, false).unwrap();

    // The next export captured the photo too.
    let later = bundle(vec![captured(&scratch.0, "plan.pdf", b"plan", false), captured(&scratch.0, "photo.jpg", &photo, true)]);
    let report = ds.import(&later, &|_| true, false).unwrap();
    assert!(report.ok(), "{:?}", report.refusals);
    assert_eq!((report.files_stored, report.files_not_archived, report.messages_updated), (1, 0, 1), "only the photo is new");
    let slug = ds.archive_room("teams", "c1").unwrap().to_owned();
    let ids: Vec<[u8; 16]> = ds.attachments(&slug, MESSAGE).iter().map(|f| f.file).collect();
    assert!(ids.iter().all(|id| *id != NOT_ARCHIVED));

    // An export that no longer captures them, or no longer lists one, drops nothing.
    let report = ds.import(&bundle(vec![lost("plan.pdf", 4)]), &|_| true, false).unwrap();
    assert_eq!((report.files_stored, report.messages_unchanged), (0, 1));
    assert_eq!(ds.attachments(&slug, MESSAGE).iter().map(|f| f.file).collect::<Vec<_>>(), ids);
    drop(ds);

    // And after a restart.
    let ds = open(&scratch.0);
    let after = ds.attachments(&slug, MESSAGE);
    assert_eq!(after.iter().map(|f| f.file).collect::<Vec<_>>(), ids);
    assert_eq!(ds.download(ANA, &after[1].file, 0, 4096).unwrap(), photo);
}

#[test]
fn bytes_that_do_not_match_are_refused_and_not_archived() {
    let scratch = Scratch::new("refused");
    let mut ds = open(&scratch.0);
    let mut wrong = captured(&scratch.0, "plan.pdf", b"plan", true);
    wrong.sha256 = Some([9; 32]);
    let mut short = captured(&scratch.0, "notes.txt", b"notes", false);
    short.size = 999;
    let report = ds.import(&bundle(vec![wrong, short]), &|_| true, false).unwrap();
    let refused: Vec<(&str, &str)> = report.refusals.iter().map(|r| (r.at.as_str(), r.reason.as_str())).collect();
    assert_eq!(
        refused,
        vec![
            ("message 0 file 0", "its bytes do not match the bundle's sha256"),
            ("message 0 file 1", "its bytes are not the size the bundle gives")
        ]
    );
    assert_eq!((report.files_stored, report.files_not_archived, report.messages_added), (0, 2, 1), "the message itself still imported");

    // A server that keeps no files says so.
    let bare = Scratch::new("bare");
    let mut ds = DurableServer::open(&bare.0.join("rooms.journal")).unwrap();
    let report = ds.import(&bundle(vec![captured(&bare.0, "plan.pdf", b"plan", false)]), &|_| true, false).unwrap();
    assert_eq!(report.refusals[0].reason, "this server keeps no files");
}
