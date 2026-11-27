//! T370a: staff meetings on the chat server (docs/MEETINGS.md). Real device connections (loopback TCP, the server's
//! session code, the client-core `Client`) schedule and list meetings in a week window, edit them with version checks
//! (a stale version is a conflict; an edit that changes nothing records nothing), cannot change a meeting once it has
//! a call, cancel, and join by meeting id into the room's ordinary call; a non-member sees no meeting and joins none;
//! a staff meeting stays staff; an older client is refused the requests and sees the lines as `Other`; and it all
//! survives a restart.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{Datelike, NaiveDate, Weekday};
use crewcraft_client_core::calendar::work_week;
use crewcraft_client_core::client::{Client, ClientEvent};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::requests::Reply;
use crewcraft_proto::frame::{encode, read_frame};
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::meeting::{Audience, MAX_WINDOW_MS, Meeting, MeetingChange, MeetingPage, MeetingState, decode_meetings, encode_meetings};
use crewcraft_proto::push::{Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_CALLS, FEATURE_MEETINGS, Request, Response, decode_request, encode_request};
use crewcraft_proto::signin::{self, SignIn, TOKEN_LEN};
use crewcraft_server::device_session::{AuthError, CommittedSignIn, DeviceAuth, serve};
use crewcraft_server_core::dispatch::{E_BAD_TEXT, E_CONFLICT, E_NO_SUCH_MEETING, E_NO_SUCH_ROOM, E_NOT_ALLOWED};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;

const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const CY: &str = "cy@example.org";
const OLD: &str = "old@example.org";
const WAIT: Duration = Duration::from_secs(10);
const HOUR: u64 = 60 * 60 * 1000;
const DAY: u64 = 24 * HOUR;

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t370a-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The transport has verified this device; signing in always succeeds (the sign-in itself is tested elsewhere).
struct Device {
    user: &'static str,
}

impl DeviceAuth for Device {
    type Session = ();

    fn sign_in(&self, _credentials: SignIn<'_>, _now_ms: u64) -> Result<Option<CommittedSignIn<()>>, AuthError> {
        Ok(Some(CommittedSignIn { user: self.user.to_owned(), token: "A".repeat(TOKEN_LEN), session: () }))
    }

    fn with_live_session<T>(&self, _session: &(), _now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        Ok(Some(action()))
    }

    fn device(&self) -> Option<u64> {
        None
    }
}

/// One person's device connection, through client-core.
struct Person {
    stream: TcpStream,
    client: Client,
}

impl Person {
    fn connect(address: SocketAddr, user: &str, features: u32) -> Person {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream
            .write_all(&encode(&signin::encode_request(&SignIn { email: user, password: "fixture password", code: "123456" }).unwrap()).unwrap())
            .unwrap();
        read_frame(&mut stream, 4096).unwrap().unwrap();
        let hello = Hello { min_version: 1, max_version: 1, features, client: "test".into() };
        stream.write_all(&encode(&handshake::encode_hello(&hello).unwrap()).unwrap()).unwrap();
        read_frame(&mut stream, 4096).unwrap().unwrap();
        Person { stream, client: Client::new(user, Settings::default()) }
    }

    /// Send `request`, then a `Ping`; return the request's answer and every event that came before the ping's.
    fn ask(&mut self, request: Request) -> (Response, Vec<ClientEvent>) {
        for request in [request, Request::Ping] {
            let bytes = self.client.send(request, now_ms()).unwrap();
            self.stream.write_all(&bytes).unwrap();
        }
        let (mut response, mut events) = (None, Vec::new());
        loop {
            let frame = read_frame(&mut self.stream, 1 << 21).unwrap().unwrap();
            for event in self.client.receive(frame.as_bytes(), now_ms(), 0).unwrap() {
                match event {
                    ClientEvent::Reply(Reply::Done { request: Request::Ping, .. }) => return (response.unwrap(), events),
                    ClientEvent::Reply(Reply::Done { response: answered, .. }) => response = Some(answered),
                    other => events.push(other),
                }
            }
        }
    }

    /// The meetings frame among `events`.
    fn page(events: &[ClientEvent]) -> MeetingPage {
        events.iter().find_map(|event| if let ClientEvent::Meetings { page, .. } = event { Some(page.clone()) } else { None }).unwrap()
    }

    fn list(&mut self, from_ms: u64, to_ms: u64) -> MeetingPage {
        let (answer, events) = self.ask(Request::MeetingList { from_ms, to_ms });
        let page = Person::page(&events);
        assert_eq!(answer, Response::Ok { cursor: page.meetings.len() as u64 });
        page
    }

    fn save(&mut self, request: Request) -> Result<Meeting, u16> {
        match self.ask(request) {
            (Response::Ok { cursor }, events) => {
                let page = Person::page(&events);
                assert_eq!(page.meetings.len(), 1);
                assert_eq!(page.meetings[0].id, cursor);
                Ok(page.meetings[0].clone())
            }
            (Response::Error { code, .. }, _) => Err(code),
        }
    }
}

/// The meeting lines among `events`, as `(change, author, text)`.
fn meeting_lines(events: &[ClientEvent]) -> Vec<(MeetingChange, String, String)> {
    let mut lines = Vec::new();
    for event in events {
        if let ClientEvent::MeetingLine { change, author, text, .. } = event {
            lines.push((*change, author.clone(), text.clone()));
        }
    }
    lines
}

fn code(answer: &Response) -> u16 {
    match answer {
        Response::Error { code, .. } => *code,
        other => panic!("not refused: {other:?}"),
    }
}

fn schedule(room: &str, start_ms: u64, title: &str) -> Request {
    Request::MeetingSave { room: room.into(), meeting: 0, version: 0, start_ms, duration: 30, title: title.into(), agenda: "Notes".into() }
}

fn edit(room: &str, meeting: &Meeting, version: u64, title: &str) -> Request {
    Request::MeetingSave {
        room: room.into(),
        meeting: meeting.id,
        version,
        start_ms: meeting.start_ms,
        duration: meeting.duration,
        title: title.into(),
        agenda: meeting.agenda.clone(),
    }
}

#[test]
fn requests_push_and_frame_round_trip_and_refuse_damage() {
    let requests = [
        schedule("room", 1_800_000_000_000, "Planning"),
        Request::MeetingSave { room: "room".into(), meeting: 4, version: 2, start_ms: 1, duration: 1, title: "t".into(), agenda: String::new() },
        Request::MeetingCancel { room: "room".into(), meeting: 4, version: 2 },
        Request::MeetingList { from_ms: 1, to_ms: 2 },
        Request::MeetingJoin { meeting: 4 },
    ];
    for request in requests {
        let bytes = encode_request(9, &request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), (9, request));
        for cut in 1..bytes.len() {
            assert!(decode_request(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }
    // A new meeting has no version, and an edit always has one.
    for (meeting, version) in [(0, 1), (3, 0)] {
        let bad = Request::MeetingSave { room: "r".into(), meeting, version, start_ms: 1, duration: 1, title: "t".into(), agenda: String::new() };
        assert!(encode_request(1, &bad).is_err());
    }

    let line = Push::MeetingLine {
        room: "room".into(),
        cursor: 5,
        meeting: 4,
        change: MeetingChange::Edited,
        version: 2,
        author: ANA.into(),
        text: "edited the meeting".into(),
    };
    let bytes = encode_push(&line).unwrap();
    assert_eq!(decode_push(&bytes).unwrap(), line);
    for cut in 1..bytes.len() {
        assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
    }

    let meeting = Meeting {
        id: 4,
        room: "room".into(),
        version: 2,
        owner: ANA.into(),
        audience: Audience::Staff,
        start_ms: 1_800_000_000_000,
        duration: 45,
        title: "Planning".into(),
        agenda: "One\nTwo".into(),
        state: MeetingState::Held,
    };
    let page = MeetingPage { meetings: vec![meeting.clone(), Meeting { id: 5, state: MeetingState::Cancelled, ..meeting }], more: true };
    let bytes = encode_meetings(3, &page).unwrap();
    assert_eq!(decode_meetings(&bytes).unwrap(), (3, page));
    for cut in 1..bytes.len() {
        assert!(decode_meetings(&bytes[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn a_work_week_is_monday_to_saturday_in_local_time() {
    let wednesday = NaiveDate::from_ymd_opt(2026, 12, 2).unwrap();
    assert_eq!(wednesday.weekday(), Weekday::Wed);
    let (utc_from, utc_to) = work_week(wednesday, 0).unwrap();
    let (east_from, east_to) = work_week(wednesday, 120).unwrap();
    // Five days, inside the server's window limit, with the asked-for day inside.
    assert_eq!(utc_to - utc_from, 5 * DAY);
    assert!(utc_to - utc_from <= MAX_WINDOW_MS);
    let noon = u64::try_from(wednesday.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp_millis()).unwrap();
    assert!(utc_from < noon && noon < utc_to);
    // A zone east of UTC reaches its Monday midnight earlier in UTC.
    assert!(east_from < utc_from && east_to < utc_to);
    // Every day of one week gives the same window.
    let monday = NaiveDate::from_ymd_opt(2026, 11, 30).unwrap();
    let sunday = NaiveDate::from_ymd_opt(2026, 12, 6).unwrap();
    assert_eq!(work_week(monday, 0), work_week(sunday, 0));
}

#[test]
fn staff_meetings_over_real_sessions() {
    let files = Scratch::new();
    let journal = files.0.join("rooms.journal");
    let rooms = Arc::new(Mutex::new(DurableServer::open(&journal).unwrap()));
    let room = {
        let mut rooms = rooms.lock().unwrap();
        let room = rooms.create_room(ANA, "Project").unwrap();
        rooms.add_member(&room, ANA, BO, Role::Member).unwrap();
        rooms.add_member(&room, ANA, OLD, Role::Member).unwrap();
        room
    };
    let devices = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = devices.local_addr().unwrap();
    let accepting = {
        let rooms = rooms.clone();
        std::thread::spawn(move || {
            let mut served = Vec::new();
            for user in [ANA, BO, CY, OLD] {
                let (mut stream, _) = devices.accept().unwrap();
                let rooms = rooms.clone();
                served.push(std::thread::spawn(move || {
                    let side = ServerSide { min_version: 1, max_version: 1, features: FEATURE_CALLS | FEATURE_MEETINGS, name: "chat".into() };
                    let _ = serve(&mut stream, &Device { user }, &rooms, side, |_| Ok(()), now_ms);
                }));
            }
            served
        })
    };
    let both = FEATURE_CALLS | FEATURE_MEETINGS;
    let mut ana = Person::connect(address, ANA, both);
    let mut bo = Person::connect(address, BO, both);
    let mut cy = Person::connect(address, CY, both);
    let mut old = Person::connect(address, OLD, FEATURE_CALLS);
    let served = accepting.join().unwrap();

    // Ana schedules two meetings tomorrow and one next month. Each is staff, at version 1, scheduled.
    let start = now_ms() + DAY;
    let first = ana.save(schedule(&room, start, "  Planning  ")).unwrap();
    let second = ana.save(schedule(&room, start + 2 * HOUR, "Review")).unwrap();
    let later = ana.save(schedule(&room, start + 30 * DAY, "Later")).unwrap();
    assert_eq!(first.title, "Planning", "the title is trimmed");
    for meeting in [&first, &second, &later] {
        assert_eq!((meeting.version, meeting.audience, meeting.state, meeting.owner.as_str()), (1, Audience::Staff, MeetingState::Scheduled, ANA));
    }
    assert!(first.id != second.id && second.id != later.id);
    // A meeting that would end in the past, an empty title and a member with no rights in the room are refused.
    assert_eq!(ana.save(schedule(&room, now_ms() - 2 * HOUR, "Gone")), Err(E_BAD_TEXT));
    assert_eq!(ana.save(schedule(&room, start, "   ")), Err(E_BAD_TEXT));
    assert_eq!(cy.save(schedule(&room, start, "Intruder")), Err(E_NO_SUCH_ROOM));

    // The week window holds tomorrow's meetings, by start, and not next month's; a non-member sees none.
    let (from, to) = (start - HOUR, start + 5 * DAY);
    let week = bo.list(from, to);
    assert_eq!(week.meetings.iter().map(|m| m.id).collect::<Vec<_>>(), vec![first.id, second.id]);
    assert!(!week.more);
    assert!(cy.list(from, to).meetings.is_empty());
    assert_eq!(code(&bo.ask(Request::MeetingList { from_ms: from, to_ms: from + MAX_WINDOW_MS + 1 }).0), E_BAD_TEXT, "too wide a window");

    // Bo is neither the owner nor a room admin: he cannot change Ana's meeting. Cy cannot even find it.
    assert_eq!(bo.save(edit(&room, &first, 1, "Bo's title")), Err(E_NOT_ALLOWED));
    assert_eq!(cy.save(edit(&room, &first, 1, "Cy's title")), Err(E_NO_SUCH_MEETING));

    // A fresh version saves and moves the version on; the stale one is now a conflict and changes nothing.
    let edited = ana.save(edit(&room, &first, 1, "Planning, moved")).unwrap();
    assert!(edited.version > first.version);
    assert_eq!(ana.save(edit(&room, &first, first.version, "Stale")), Err(E_CONFLICT));
    let shown = bo.list(from, to).meetings.into_iter().find(|m| m.id == first.id).unwrap();
    assert_eq!((shown.title.as_str(), shown.version), ("Planning, moved", edited.version));

    // An edit that changes nothing succeeds at the same version and adds nothing to the room.
    let (head, _) = bo.ask(Request::Sync { room: room.clone(), cursor: 0 });
    let same = ana.save(edit(&room, &edited, edited.version, "Planning, moved")).unwrap();
    assert_eq!(same.version, edited.version);
    assert_eq!(bo.ask(Request::Sync { room: room.clone(), cursor: 0 }).0, head, "a no-change edit wrote history");

    // The room's system lines were built by the server: scheduled three times, edited once, all by Ana.
    bo.client.inbox_mut().follow(&room, false);
    let (_, events) = bo.ask(Request::Sync { room: room.clone(), cursor: 0 });
    let lines = meeting_lines(&events);
    assert_eq!(lines.iter().filter(|(change, ..)| *change == MeetingChange::Scheduled).count(), 3);
    assert_eq!(lines.iter().filter(|(change, ..)| *change == MeetingChange::Edited).count(), 1);
    assert!(lines.iter().all(|(_, author, _)| author == ANA));
    assert!(lines.iter().any(|(change, _, text)| *change == MeetingChange::Edited && text.contains("Planning, moved")));
    // An older client advances past them as `Other` and cannot use the requests.
    old.client.inbox_mut().follow(&room, false);
    let (_, events) = old.ask(Request::Sync { room: room.clone(), cursor: 0 });
    assert!(events.iter().all(|e| !matches!(e, ClientEvent::MeetingLine { .. })));
    assert_eq!(code(&old.ask(Request::MeetingList { from_ms: from, to_ms: to }).0), E_NOT_ALLOWED);
    assert_eq!(code(&old.ask(Request::MeetingJoin { meeting: first.id }).0), E_NOT_ALLOWED);

    // Join by id: a non-member is refused as if there were no meeting; members join the room's one call.
    assert_eq!(code(&cy.ask(Request::MeetingJoin { meeting: first.id }).0), E_NO_SUCH_MEETING);
    assert_eq!(code(&cy.ask(Request::MeetingJoin { meeting: 9_999 }).0), E_NO_SUCH_MEETING);
    let (joined, _) = bo.ask(Request::MeetingJoin { meeting: first.id });
    let Response::Ok { cursor: call } = joined else { panic!("{joined:?}") };
    assert_eq!(ana.ask(Request::MeetingJoin { meeting: first.id }).0, Response::Ok { cursor: call });
    {
        let rooms = rooms.lock().unwrap();
        let open = rooms.open_call(&room).unwrap();
        assert_eq!(open.id, call, "the meeting's call is the room's call");
        assert!(open.present.contains_key(ANA) && open.present.contains_key(BO));
        assert!(rooms.meeting(first.id).unwrap().calls.contains(&call));
    }
    let state_of = |person: &mut Person, id: u64| person.list(from, to).meetings.into_iter().find(|m| m.id == id).unwrap().state;
    assert_eq!(state_of(&mut bo, first.id), MeetingState::InProgress);

    // Once it has a call it can no longer change, while the call is open and after it has ended.
    assert_eq!(ana.save(edit(&room, &edited, edited.version, "Too late")), Err(E_NOT_ALLOWED));
    assert_eq!(code(&ana.ask(Request::MeetingCancel { room: room.clone(), meeting: first.id, version: edited.version }).0), E_NOT_ALLOWED);
    for person in [&mut ana, &mut bo] {
        assert_eq!(person.ask(Request::CallLeave { room: room.clone(), call }).0, Response::Ok { cursor: call });
    }
    assert!(rooms.lock().unwrap().open_call(&room).is_none());
    assert_eq!(state_of(&mut bo, first.id), MeetingState::Held);
    assert_eq!(ana.save(edit(&room, &edited, edited.version, "Still too late")), Err(E_NOT_ALLOWED));

    // Cancelling: a stale version is a conflict; the fresh one cancels; a cancelled meeting cannot be joined or edited.
    let renamed = ana.save(edit(&room, &second, 1, "Review, renamed")).unwrap();
    assert_eq!(code(&ana.ask(Request::MeetingCancel { room: room.clone(), meeting: second.id, version: 1 }).0), E_CONFLICT);
    let (cancelled, _) = ana.ask(Request::MeetingCancel { room: room.clone(), meeting: second.id, version: renamed.version });
    assert!(matches!(cancelled, Response::Ok { cursor } if cursor > renamed.version), "{cancelled:?}");
    assert_eq!(code(&bo.ask(Request::MeetingJoin { meeting: second.id }).0), E_NOT_ALLOWED);
    assert_eq!(state_of(&mut bo, second.id), MeetingState::Cancelled);

    // No request ever made a meeting anything but staff.
    let all = bo.list(from - DAY, from - DAY + MAX_WINDOW_MS);
    assert!(all.meetings.iter().all(|m| m.audience == Audience::Staff));

    // A restart keeps every meeting, version, state, call link and system line.
    let (before, head_before) = {
        let rooms = rooms.lock().unwrap();
        (rooms.meetings_between(BO, from, to).unwrap(), rooms.server().room(&room).unwrap().head())
    };
    drop((ana, bo, cy, old));
    for thread in served {
        thread.join().unwrap();
    }
    drop(Arc::try_unwrap(rooms).ok().unwrap());
    let reopened = DurableServer::open(&journal).unwrap();
    assert_eq!(reopened.meetings_between(BO, from, to).unwrap(), before);
    assert_eq!(reopened.server().room(&room).unwrap().head(), head_before);
    assert!(reopened.meeting(first.id).unwrap().calls.contains(&call));
    assert_eq!(reopened.meeting(later.id).unwrap().audience, Audience::Staff);
}
