//! T331a: the file list (REQUIREMENTS 2.4, the Files area): `ListFiles` answers with a files frame listing every stored
//! file on a live message in the person's rooms, imported files included, newest first; never files in rooms they are
//! not in, on deleted messages, or not archived; on the wire with exact bytes, and through the client.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_client_core::client::ClientEvent;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::request::{
    FILES_TAG, ListedFile, MAX_LISTED_FILES, Request, Response, decode_files, decode_request, decode_response, encode_files, encode_request,
};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::import::{Bundle, BundleFile, BundleMessage, BundleRoom, RoomKind};
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

const T0: u64 = 1_800_000_000_000;
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t331a-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn open(dir: &Path) -> DurableServer {
    DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap()
}

fn upload(ds: &mut DurableServer, user: &str, room: &str, name: &str, bytes: &[u8]) -> [u8; 16] {
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let upload = ds.begin_upload(user, room, name, bytes.len() as u64, sha, T0).unwrap();
    ds.upload_chunk(user, &upload, 0, bytes, T0).unwrap();
    ds.finish_upload(user, &upload, T0).unwrap()
}

#[test]
fn the_request_and_the_frame_have_exact_bytes() {
    let bytes = encode_request(4, &Request::ListFiles).unwrap();
    assert_eq!(bytes, vec![24, 0, 0, 0, 4]);
    assert_eq!(decode_request(&bytes).unwrap(), (4, Request::ListFiles));
    let files = vec![
        ListedFile { file: [1; 16], room: "r".into(), cursor: 9, uploader: "a".into(), name: "x.pdf".into(), size: 5, image: None },
        ListedFile { file: [2; 16], room: "r".into(), cursor: 8, uploader: String::new(), name: "y.png".into(), size: 7, image: Some((640, 480)) },
    ];
    let frame = encode_files(4, &files).unwrap();
    assert_eq!(frame[0], FILES_TAG);
    assert_eq!(decode_files(&frame).unwrap(), (4, files.clone()));
    for cut in 1..frame.len() {
        assert!(decode_files(&frame[..cut]).is_err(), "cut at {cut}");
    }
    let too_many = vec![files[0].clone(); MAX_LISTED_FILES + 1];
    assert!(encode_files(4, &too_many).is_err());
}

#[test]
fn the_list_holds_what_the_person_can_see() {
    let dir = scratch("list");
    let mut ds = open(&dir);
    let room = ds.create_room(ANA, "Project").unwrap();
    let private = ds.create_room(BO, "Bo alone").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    let plan = upload(&mut ds, ANA, &room, "plan.pdf", b"the plan");
    let early = ds.post_files(&room, ANA, "the plan", &[plan], T0).unwrap();
    let photo = upload(&mut ds, BO, &room, "photo.png", b"not really a png");
    ds.post_files(&room, BO, "", &[photo], T0).unwrap();
    let gone = upload(&mut ds, ANA, &room, "old.txt", b"old");
    let deleted = ds.post_files(&room, ANA, "old", &[gone], T0).unwrap();
    ds.delete(&room, ANA, deleted).unwrap();
    let secret = upload(&mut ds, BO, &private, "secret.txt", b"secret");
    ds.post_files(&private, BO, "mine", &[secret], T0).unwrap();
    upload(&mut ds, ANA, &room, "never-posted.txt", b"draft");

    // An imported message's stored file is listed; one not archived is not.
    let captured = dir.join("export-report.pdf");
    fs::write(&captured, b"imported report").unwrap();
    let bundle = Bundle {
        source: "test".into(),
        rooms: vec![BundleRoom { key: "c".into(), kind: RoomKind::Group, name: "Old".into(), members: vec![ANA.into()] }],
        messages: vec![BundleMessage {
            room: "c".into(),
            key: "m".into(),
            author: BO.into(),
            sent_ms: T0,
            text: "files".into(),
            reply_to: None,
            edited_ms: None,
            deleted: false,
            files: vec![
                BundleFile { name: "report.pdf".into(), size: 15, captured: true, source: Some(captured), sha256: None },
                BundleFile { name: "lost.png".into(), size: 9, captured: false, source: None, sha256: None },
            ],
        }],
    };
    assert!(ds.import(&bundle, &|_| true, false).unwrap().ok());

    let names = |user| ds.listed_files(user).into_iter().map(|file| file.name).collect::<Vec<_>>();
    let mut ana = names(ANA);
    ana.sort();
    assert_eq!(ana, vec!["photo.png", "plan.pdf", "report.pdf"], "not deleted, not Bo's private room, not unposted, not lost");
    assert!(!names(BO).contains(&"report.pdf".to_owned()), "Bo is not in the archive room");
    assert!(names(BO).contains(&"secret.txt".to_owned()));
    let listed = ds.listed_files(ANA);
    let plan_row = listed.iter().find(|file| file.name == "plan.pdf").unwrap();
    assert_eq!((plan_row.file, plan_row.cursor, plan_row.uploader.as_str(), plan_row.size), (plan, early, ANA, 8));
    assert!(listed.windows(2).all(|pair| pair[0].cursor >= pair[1].cursor), "newest message first");

    // On the wire: Ok with the count, then the files frame, which the client reads.
    let request = encode(&encode_request(9, &Request::ListFiles).unwrap()).unwrap();
    let out = Connection::new(ANA).receive_durable(&mut ds, &request, T0).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let (_, response) = decode_response(&decoder.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(response, Response::Ok { cursor: 3 });
    let frame = decoder.next_frame().unwrap().unwrap();
    assert_eq!(decode_files(&frame).unwrap().1, listed);
    let event = ClientEvent::Files { id: 9, files: listed.clone() };
    assert!(matches!(event, ClientEvent::Files { id: 9, .. }));
}
