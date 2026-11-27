//! T347 activity feed over enrolled, password-and-TOTP signed-in network clients.
//! Fixture provenance: CrewCraft's T344 enrolled-device fixture. The first devices use network bootstrap.
//! The second Alice device uses a distinct key and issuer-signed certificate through the existing activation
//! transaction. This is authentication compatibility evidence, so it may exceed one second (testing F5).
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::ChatError;
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::{Credentials, SignedInSession};
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::Claims;
use crewcraft_proto::activity::{ActivityFilter, ActivityKind};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{
    FEATURE_ACTIVITY, FEATURE_ARCHIVE, FEATURE_CALLS, FEATURE_LIST_ROOMS, FEATURE_PINS_SAVED, FEATURE_REACTIONS, FEATURE_THREADS, Request,
};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::account_store::Activation;
use crewcraft_server_core::import::{Bundle, BundleMessage, BundleRoom, RoomKind};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::room::Role;
use crewcraft_tls::client_config;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const ENROLL_SPACING_MS: u64 = 1_000;
const PASSWORD: &str = "synthetic activity test password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.org";
const ALICE_PRIMARY: usize = 0;
const BOB_DEVICE: usize = 1;
const CAROL_DEVICE: usize = 2;
const ALICE_SECONDARY: usize = 3;

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t347-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestEnvironment {
    clock: Arc<AtomicU64>,
    secrets: VecDeque<[u8; 20]>,
}

impl Environment for TestEnvironment {
    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn totp_secret(&mut self) -> Option<[u8; 20]> {
        self.secrets.pop_front()
    }
}

struct Running {
    address: SocketAddr,
    clock: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Running {
    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, milliseconds: u64) {
        self.clock.fetch_add(milliseconds, Ordering::SeqCst);
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start(state: LabInstallation, now_ms: u64, secrets: Vec<[u8; 20]>) -> Running {
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide {
            min_version: 1,
            max_version: 1,
            features: FEATURE_LIST_ROOMS
                | FEATURE_THREADS
                | FEATURE_REACTIONS
                | FEATURE_ARCHIVE
                | FEATURE_CALLS
                | FEATURE_PINS_SAVED
                | FEATURE_ACTIVITY,
            name: "activity test server".into(),
        },
    };
    // LabRuntime signs its TLS certificate during bind. Keep certificate validity on wall time,
    // then use the controlled clock for authenticated requests and call timestamps.
    let clock = Arc::new(AtomicU64::new(wall_ms()));
    let server_clock = clock.clone();
    let server = LabRuntime::bind(state, options, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    clock.store(now_ms, Ordering::SeqCst);
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from(secrets) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || server.serve(&shutdown, |accounts, issuer| Ok(bootstrap_handler(accounts, issuer, environment))));
    Running { address, clock, stop, thread: Some(thread) }
}

struct Person {
    email: &'static str,
    secret: [u8; 20],
    invitation: EnrollmentCode,
}

impl Person {
    fn totp(&self) -> Totp {
        Totp::with_defaults(self.secret.to_vec()).unwrap()
    }

    fn enroll(&self, endpoint: &ServerEndpoint, running: &Running) -> Arc<dyn ResolvesClientCert> {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let spki = key.subject_public_key_info();
        let request = EnrollmentRequest { device_name: "Primary Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &spki };
        let chain = endpoint
            .open_bootstrap(&self.invitation, WAIT)
            .unwrap()
            .enroll(request, |_, _| FirstTotpCode::parse(self.totp().generate(running.now() / 1000)))
            .unwrap();
        device_resolver(endpoint.root_der(), vec![chain.leaf, chain.issuer], key)
    }
}

fn device_resolver(root_der: &[u8], chain: Vec<CertificateDer<'static>>, key: KeyPair) -> Arc<dyn ResolvesClientCert> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der.to_vec())).unwrap();
    let identity = (chain, PrivatePkcs8KeyDer::from(key.serialize_der()).into());
    client_config(roots, Some(identity)).unwrap().client_auth_cert_resolver.clone()
}

struct Fixture {
    directory: Scratch,
    fingerprint: [u8; 32],
    root_der: Vec<u8>,
    room: String,
    changing_room: String,
    archive_room: String,
    people: [Person; 3],
    devices: Vec<Arc<dyn ResolvesClientCert>>,
}

impl Fixture {
    fn new() -> (Self, Running) {
        let directory = Scratch::new();
        let people = [
            Person { email: ALICE, secret: [17; 20], invitation: EnrollmentCode::from_bytes([1; 20]) },
            Person { email: BOB, secret: [19; 20], invitation: EnrollmentCode::from_bytes([2; 20]) },
            Person { email: CAROL, secret: [21; 20], invitation: EnrollmentCode::from_bytes([3; 20]) },
        ];
        // Bootstrap also uses the controlled clock to issue device certificates. Allow rate-limit
        // refill for the three enrollments while keeping every issued certificate valid on wall time.
        let setup_time = wall_ms().saturating_sub(people.len() as u64 * ENROLL_SPACING_MS);
        let mut state = LabInstallation::initialize(&directory.0.join("server"), setup_time).unwrap();
        let fingerprint = state.issuer.root_fingerprint();
        let root_der = state.issuer.root_certificate().to_vec();
        for person in &people {
            let invite =
                Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
            state.accounts.issue_invite(invite, setup_time).unwrap();
        }
        let room = state.rooms.create_room(ALICE, "Project").unwrap();
        state.rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
        state.rooms.add_member(&room, ALICE, CAROL, Role::Member).unwrap();
        let changing_room = state.rooms.create_room(BOB, "Changing membership").unwrap();
        state.rooms.add_member(&changing_room, BOB, ALICE, Role::Member).unwrap();
        let first = start(state, setup_time, people.iter().map(|person| person.secret).collect());
        let mut fixture = Self { directory, fingerprint, root_der, room, changing_room, archive_room: String::new(), people, devices: Vec::new() };
        let endpoint = fixture.endpoint(&first);
        for person in &fixture.people {
            first.advance(ENROLL_SPACING_MS);
            fixture.devices.push(person.enroll(&endpoint, &first));
        }
        first.stop();

        let LabInstallation { ownership, issuer, mut accounts, mut rooms } = fixture.reopen();
        let archive = Bundle {
            source: "fixture".into(),
            rooms: vec![BundleRoom { key: "archive".into(), kind: RoomKind::Group, name: "Archive".into(), members: vec![ALICE.into(), BOB.into()] }],
            messages: vec![BundleMessage {
                room: "archive".into(),
                key: "archived-mention".into(),
                author: BOB.into(),
                sent_ms: setup_time,
                text: "An archived mention for @alice".into(),
                reply_to: None,
                edited_ms: None,
                deleted: false,
                files: Vec::new(),
            }],
        };
        assert!(rooms.import(&archive, &|email| accounts.person(email).is_some(), false).unwrap().refusals.is_empty());
        fixture.archive_room = rooms.archive_room("fixture", "archive").unwrap().to_owned();

        let (root_der, mut authority) = issuer.into_parts();
        let registration_time = wall_ms().saturating_add(STEP_MS);
        let bootstrap_pub = EnrollmentCode::from_bytes([4; 20]).bootstrap_public_key();
        accounts.issue_invite(Invite { email: ALICE.into(), bootstrap_pub, expires_ms: registration_time + 600_000 }, registration_time).unwrap();
        let (email, device_id) = accounts.preview_activation(&bootstrap_pub, registration_time).unwrap();
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let issued = authority.issue_device(csr.der(), &Claims { person: &email, device_id }, wall_ms()).unwrap();
        let totp = fixture.people[ALICE_PRIMARY].totp();
        let counter = totp.verify(&totp.generate(registration_time / 1000), registration_time / 1000, 0, None).unwrap();
        accounts
            .activate(
                Activation {
                    bootstrap_pub,
                    device_name: "Secondary Device",
                    certificate: &issued.certificate,
                    spki_sha256: issued.key_id,
                    counter,
                    first_device: None,
                    expected_device_id: Some(device_id),
                },
                registration_time,
            )
            .unwrap();
        let alice_devices = accounts.devices_of(ALICE);
        assert_eq!(alice_devices.len(), 2);
        assert_ne!(alice_devices[0].id, alice_devices[1].id);
        fixture.devices.push(device_resolver(&root_der, issued.chain.into_iter().map(CertificateDer::from).collect(), key));
        drop((authority, accounts, rooms, ownership));
        let running = start(fixture.reopen(), registration_time, Vec::new());
        (fixture, running)
    }

    fn endpoint(&self, running: &Running) -> ServerEndpoint {
        ServerEndpoint::new(&running.address.to_string(), "localhost", RootFingerprint::from_der(&self.root_der), &self.root_der).unwrap()
    }

    fn sign_in(&self, running: &Running, device: usize) -> SignedInSession {
        running.advance(STEP_MS);
        let person = &self.people[if device == ALICE_SECONDARY { ALICE_PRIMARY } else { device }];
        let code = person.totp().generate(running.now() / 1000);
        let credentials = Credentials::new(person.email, PASSWORD, &code).unwrap();
        let session = self.endpoint(running).sign_in(self.devices[device].clone(), &credentials);
        assert!(session.is_ok(), "enrolled device {device} failed to sign in: {:?}", session.as_ref().err());
        session.unwrap()
    }

    fn reopen(&self) -> LabInstallation {
        LabInstallation::open(&self.directory.0.join("server"), self.fingerprint, wall_ms()).unwrap()
    }
}

#[test]
fn enrolled_devices_share_activity_and_seen_state_across_restarts() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, ALICE_PRIMARY);
    let mut bob = fixture.sign_in(&running, BOB_DEVICE);
    let mut carol = fixture.sign_in(&running, CAROL_DEVICE);
    let mut other_alice = fixture.sign_in(&running, ALICE_SECONDARY);
    let room = &fixture.room;
    let changing_room = &fixture.changing_room;

    let (_, archive_messages) = alice.sync(&fixture.archive_room).unwrap();
    assert!(archive_messages.iter().any(|message| matches!(message, Shown::Line(line) if line.html.contains("archived mention"))));
    assert!(alice.activity(ActivityFilter::All).unwrap().items.is_empty(), "an accessible archived mention is excluded");

    let parent = alice.post(room, "An original plan").unwrap();
    let mention = bob.post(room, "Please review @alice").unwrap();
    let reply = bob.reply(room, parent, "An answer for @alice").unwrap();
    let plain_reply = carol.reply(room, parent, "Another answer").unwrap();
    alice.reply(room, parent, "My own reply for @alice").unwrap();
    alice.react(room, parent, 1, true).unwrap();
    bob.react(room, parent, 1, true).unwrap();
    bob.react(room, parent, 1, true).unwrap();
    let old_room_post = bob.post(changing_room, "Visible while @alice is a member").unwrap();

    let call_started = running.now();
    let call = bob.call_start(room, false).unwrap();
    carol.call(room, call, |room, call| Request::CallJoin { room, call }).unwrap();
    assert!(!alice.activity(ActivityFilter::All).unwrap().items.iter().any(|item| item.kind == ActivityKind::MissedCall));
    running.advance(1_000);
    carol.call(room, call, |room, call| Request::CallLeave { room, call }).unwrap();
    assert!(!alice.activity(ActivityFilter::All).unwrap().items.iter().any(|item| item.kind == ActivityKind::MissedCall));
    running.advance(1_000);
    let call_ended = running.now();
    bob.call(room, call, |room, call| Request::CallLeave { room, call }).unwrap();

    let all = alice.activity(ActivityFilter::All).unwrap();
    assert_eq!(all.items.len(), 6, "{all:?}");
    assert_eq!(usize::from(all.unread), all.items.len());
    assert_eq!(other_alice.activity(ActivityFilter::All).unwrap(), all);
    assert!(all.items.iter().any(|item| {
        item.room == *room && item.actor == BOB && item.target == mention && item.kind == ActivityKind::Message { mentioned: true, replied: false }
    }));
    let combined: Vec<_> = all.items.iter().filter(|item| item.room == *room && item.target == reply).collect();
    assert_eq!(combined.len(), 1, "the same reply and mention make a single item");
    assert_eq!(combined[0].actor, BOB);
    assert_eq!(combined[0].parent, Some(parent));
    assert_eq!(combined[0].kind, ActivityKind::Message { mentioned: true, replied: true });
    assert!(all.items.iter().any(|item| {
        item.room == *room
            && item.actor == CAROL
            && item.target == plain_reply
            && item.parent == Some(parent)
            && item.kind == ActivityKind::Message { mentioned: false, replied: true }
    }));
    assert!(
        all.items
            .iter()
            .any(|item| { item.room == *room && item.actor == BOB && item.target == parent && item.kind == ActivityKind::Reaction { reaction: 1 } })
    );
    let missed = all.items.iter().find(|item| item.kind == ActivityKind::MissedCall).unwrap();
    assert_eq!((&missed.room, missed.actor.as_str(), missed.target), (room, BOB, call));
    assert!(missed.at_ms > call_started);
    assert_eq!(missed.at_ms, call_ended, "a missed call is dated by its end");
    assert!(all.items.iter().any(|item| item.room == *changing_room && item.target == old_room_post));
    for other_person in [&mut bob, &mut carol] {
        assert!(other_person.activity(ActivityFilter::All).unwrap().items.is_empty(), "actors and callers who joined do not receive these items");
    }

    let mentions = alice.activity(ActivityFilter::Mentions).unwrap();
    assert_eq!(mentions.items.len(), 3);
    assert!(mentions.items.iter().any(|item| item.id == combined[0].id), "a combined item remains visible in Mentions");
    assert_eq!(alice.activity(ActivityFilter::Unread).unwrap().items, all.items);
    assert!(alice.activity(ActivityFilter::Saved).unwrap().items.is_empty());
    alice.save_message(room, reply, true).unwrap();
    let saved = other_alice.activity(ActivityFilter::Saved).unwrap();
    assert_eq!(saved.items, vec![(*combined[0]).clone()]);
    let badge = alice.activity(ActivityFilter::Badge).unwrap();
    assert_eq!((badge.head, badge.seen, badge.unread), (all.head, all.seen, all.unread));
    assert!(badge.items.is_empty());

    bob.react(room, parent, 1, false).unwrap();
    let withdrawn = alice.activity(ActivityFilter::All).unwrap();
    assert_eq!(withdrawn.head, all.head, "withdrawing a reaction does not create activity");
    assert_eq!(withdrawn.unread, all.unread - 1);
    assert!(!withdrawn.items.iter().any(|item| matches!(item.kind, ActivityKind::Reaction { .. })));

    let newer = bob.post(room, "A newer mention for @alice").unwrap();
    assert_eq!(alice.mark_activity_seen(all.head).unwrap(), all.head, "mark only the snapshot the device saw");
    let after_stale_mark = other_alice.activity(ActivityFilter::Unread).unwrap();
    assert_eq!(after_stale_mark.items.len(), 1);
    assert_eq!(after_stale_mark.items[0].target, newer);
    assert_eq!(after_stale_mark.unread, 1);
    assert!(after_stale_mark.head > all.head);
    assert_eq!(alice.mark_activity_seen(after_stale_mark.head + 1), Err(LabError::Chat(ChatError::Rejected(17))));
    assert_eq!(alice.mark_activity_seen(after_stale_mark.head).unwrap(), after_stale_mark.head);
    assert_eq!(other_alice.mark_activity_seen(all.head).unwrap(), after_stale_mark.head, "an older device cannot move Seen backwards");
    let cleared = other_alice.activity(ActivityFilter::Unread).unwrap();
    assert!(cleared.items.is_empty());
    assert_eq!(cleared.unread, 0);

    let later = bob.post(room, "A fresh mention for @alice").unwrap();
    let before_restart = alice.activity(ActivityFilter::Unread).unwrap();
    assert_eq!(before_restart.seen, after_stale_mark.head);
    assert_eq!(before_restart.unread, 1);
    assert_eq!(before_restart.items.len(), 1);
    assert_eq!(before_restart.items[0].target, later);
    assert_eq!(other_alice.activity(ActivityFilter::Unread).unwrap(), before_restart);

    let primary_ticket = alice.resume_ticket().unwrap();
    let secondary_ticket = other_alice.resume_ticket().unwrap();
    let bob_ticket = bob.resume_ticket().unwrap();
    let carol_ticket = carol.resume_ticket().unwrap();
    let now = running.now();
    drop((alice, other_alice, bob, carol));
    running.stop();

    let mut state = fixture.reopen();
    state.rooms.remove_member(changing_room, BOB, ALICE).unwrap();
    let running = start(state, now, Vec::new());
    let endpoint = fixture.endpoint(&running);
    let mut alice = endpoint.resume(fixture.devices[ALICE_PRIMARY].clone(), &primary_ticket).unwrap();
    let mut other_alice = endpoint.resume(fixture.devices[ALICE_SECONDARY].clone(), &secondary_ticket).unwrap();
    let mut bob = endpoint.resume(fixture.devices[BOB_DEVICE].clone(), &bob_ticket).unwrap();
    assert_eq!(alice.activity(ActivityFilter::Unread).unwrap(), before_restart);
    assert_eq!(other_alice.activity(ActivityFilter::Unread).unwrap(), before_restart);
    assert_eq!(alice.activity(ActivityFilter::Saved).unwrap().items, saved.items);
    let after_removal = alice.activity(ActivityFilter::All).unwrap();
    assert!(after_removal.items.iter().all(|item| item.room != *changing_room && item.room != fixture.archive_room));
    assert!(after_removal.items.iter().any(|item| item == missed), "the finished call survives replay");

    // Post while Alice is absent, and start a call before she joins the room again.
    bob.post(changing_room, "An absent mention for @alice").unwrap();
    let started_before_rejoin = bob.call_start(changing_room, false).unwrap();
    let primary_ticket = alice.resume_ticket().unwrap();
    let bob_ticket = bob.resume_ticket().unwrap();
    let now = running.now();
    drop((alice, other_alice, bob));
    running.stop();

    let mut state = fixture.reopen();
    state.rooms.add_member(changing_room, BOB, ALICE, Role::Member).unwrap();
    let running = start(state, now + 1_000, Vec::new());
    let endpoint = fixture.endpoint(&running);
    let mut alice = endpoint.resume(fixture.devices[ALICE_PRIMARY].clone(), &primary_ticket).unwrap();
    let mut bob = endpoint.resume(fixture.devices[BOB_DEVICE].clone(), &bob_ticket).unwrap();
    bob.call(changing_room, started_before_rejoin, |room, call| Request::CallLeave { room, call }).unwrap();
    let after_rejoin = alice.activity(ActivityFilter::All).unwrap();
    assert!(
        after_rejoin.items.iter().all(|item| item.room != *changing_room),
        "old membership, absence and a call started before rejoining produce no activity"
    );
    let rejoined = bob.post(changing_room, "A mention after @alice rejoined").unwrap();
    let after_new_post = alice.activity(ActivityFilter::Unread).unwrap();
    assert!(after_new_post.items.iter().any(|item| item.room == *changing_room && item.target == rejoined));
    bob.delete(changing_room, rejoined).unwrap();
    let after_delete = alice.activity(ActivityFilter::All).unwrap();
    assert_eq!(after_delete.head, after_new_post.head);
    assert!(after_delete.items.iter().all(|item| item.room != *changing_room), "deletion removes a message's activity");

    bob.edit(room, reply, "A revised answer for @alice").unwrap();
    let after_reply_edit = alice.activity(ActivityFilter::All).unwrap();
    assert_eq!(after_reply_edit.head, after_delete.head, "keeping a mention on a reply issues no new activity");
    let edited_replies: Vec<_> = after_reply_edit.items.iter().filter(|item| item.room == *room && item.target == reply).collect();
    assert_eq!(edited_replies.len(), 1);
    assert_eq!(edited_replies[0].id, combined[0].id);
    assert_eq!(edited_replies[0].kind, ActivityKind::Message { mentioned: true, replied: true });
    assert!(edited_replies[0].snippet.contains("A revised answer"));

    let ordinary = bob.post(room, "A note without a mention").unwrap();
    assert_eq!(alice.activity(ActivityFilter::All).unwrap(), after_reply_edit);
    bob.edit(room, ordinary, "A note for @alice").unwrap();
    let first_mention = alice.activity(ActivityFilter::All).unwrap();
    assert!(first_mention.head > after_reply_edit.head);
    assert_eq!(first_mention.items.len(), after_reply_edit.items.len() + 1);
    let added = first_mention.items.iter().find(|item| item.room == *room && item.target == ordinary).unwrap();
    assert_eq!(added.kind, ActivityKind::Message { mentioned: true, replied: false });

    bob.edit(room, ordinary, "A revised note for @alice").unwrap();
    let after_mention_edit = alice.activity(ActivityFilter::All).unwrap();
    assert_eq!(after_mention_edit.head, first_mention.head, "keeping an existing mention does not issue it again");
    let edited_mentions: Vec<_> = after_mention_edit.items.iter().filter(|item| item.room == *room && item.target == ordinary).collect();
    assert_eq!(edited_mentions.len(), 1);
    assert_eq!(edited_mentions[0].id, added.id);
    assert!(edited_mentions[0].snippet.contains("A revised note"));

    let mut carol = endpoint.resume(fixture.devices[CAROL_DEVICE].clone(), &carol_ticket).unwrap();
    let mentioned_in_thread = bob.reply(room, parent, "An update for @carol").unwrap();
    let on_reply = carol.activity(ActivityFilter::Mentions).unwrap();
    assert_eq!(on_reply.items.len(), 1);
    assert_eq!(on_reply.items[0].target, mentioned_in_thread);
    assert_eq!(on_reply.items[0].kind, ActivityKind::Message { mentioned: true, replied: false });
    assert_eq!(on_reply.items[0].parent, Some(parent), "the mentioned person can open the real thread");

    let later_thread_reply = bob.reply(room, parent, "A follow-up in the thread").unwrap();
    assert_eq!(carol.activity(ActivityFilter::Mentions).unwrap(), on_reply);
    bob.edit(room, later_thread_reply, "A follow-up for @carol").unwrap();
    let on_edit = carol.activity(ActivityFilter::Mentions).unwrap();
    assert_eq!(on_edit.items.len(), 2);
    let new_mention = on_edit.items.iter().find(|item| item.target == later_thread_reply).unwrap();
    assert_eq!(new_mention.kind, ActivityKind::Message { mentioned: true, replied: false });
    assert_eq!(new_mention.parent, Some(parent), "a mention introduced by an edit retains the thread too");
    drop((alice, bob, carol));
    running.stop();
}
