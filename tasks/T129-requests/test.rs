#![allow(clippy::unwrap_used)]

use crewcraft_client_core::requests::{Reply, Requests, TIMEOUT_MS};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::{Request, Response, encode_request, encode_response};

#[test]
fn new_starts_ids_at_one() {
    let mut reqs = Requests::new();
    let (id, bytes) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id, 1);
    let expected = encode_request(1, &Request::Ping).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(reqs.in_flight(), 1);
}

#[test]
fn starting_at_zero_is_treated_as_one() {
    let mut reqs = Requests::starting_at(0);
    let (id, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id, 1);
}

#[test]
fn starting_at_n_starts_at_n() {
    let mut reqs = Requests::starting_at(42);
    let (id1, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id1, 42);
    let (id2, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id2, 43);
}

#[test]
fn ids_count_up_by_one() {
    let mut reqs = Requests::new();
    let (id1, _) = reqs.send(Request::Ping, 0).unwrap();
    let (id2, _) = reqs.send(Request::Ping, 1).unwrap();
    let (id3, _) = reqs.send(Request::Ping, 2).unwrap();
    assert_eq!((id1, id2, id3), (1, 2, 3));
    assert_eq!(reqs.in_flight(), 3);
}

#[test]
fn wrap_from_max_to_one_never_zero() {
    let mut reqs = Requests::starting_at(u32::MAX);
    let (id1, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id1, u32::MAX);
    let (id2, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id2, 1);
    let (id3, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id3, 2);
}

#[test]
fn send_encodes_request_under_assigned_id() {
    let mut reqs = Requests::starting_at(7);
    let req = Request::Post { room: "general".into(), text: "hello world".into() };
    let (id, bytes) = reqs.send(req.clone(), 100).unwrap();
    assert_eq!(id, 7);
    let expected = encode_request(7, &req).unwrap();
    assert_eq!(bytes, expected);
}

#[test]
fn send_encoding_failure_uses_no_id_and_remembers_nothing() {
    let mut reqs = Requests::new();
    // room is 0 bytes but min is 1 → FieldLength
    let bad = Request::Post { room: String::new(), text: "hello".into() };
    assert_eq!(reqs.send(bad, 0), Err(CodecError::FieldLength));
    assert_eq!(reqs.in_flight(), 0);
    // The id was not used up, so the next send still gets id 1
    let (id, _) = reqs.send(Request::Ping, 0).unwrap();
    assert_eq!(id, 1);
}

#[test]
fn on_reply_done_forgets_the_request() {
    let mut reqs = Requests::new();
    let req = Request::Sync { room: "a".into(), cursor: 5 };
    let (id, _) = reqs.send(req.clone(), 0).unwrap();
    assert_eq!(reqs.in_flight(), 1);

    let response = Response::Ok { cursor: 42 };
    let bytes = encode_response(id, &response).unwrap();
    let reply = reqs.on_reply(&bytes);
    assert_eq!(reply, Reply::Done { id, request: req, response });
    assert_eq!(reqs.in_flight(), 0);
}

#[test]
fn on_reply_unknown_when_id_not_in_flight() {
    let mut reqs = Requests::new();
    reqs.send(Request::Ping, 0).unwrap(); // id 1 is in flight

    let bytes = encode_response(99, &Response::Ok { cursor: 0 }).unwrap();
    let reply = reqs.on_reply(&bytes);
    assert_eq!(reply, Reply::Unknown { id: 99 });
    // Nothing changed: id 1 is still in flight
    assert_eq!(reqs.in_flight(), 1);
}

#[test]
fn on_reply_second_reply_same_id_is_unknown() {
    let mut reqs = Requests::new();
    let (id, _) = reqs.send(Request::Ping, 0).unwrap();

    let bytes = encode_response(id, &Response::Ok { cursor: 0 }).unwrap();
    let first = reqs.on_reply(&bytes);
    assert_eq!(first, Reply::Done { id, request: Request::Ping, response: Response::Ok { cursor: 0 } });

    // Second reply with the same id → Unknown, nothing changes
    let second = reqs.on_reply(&bytes);
    assert_eq!(second, Reply::Unknown { id });
    assert_eq!(reqs.in_flight(), 0);
}

#[test]
fn on_reply_malformed_returns_error_and_changes_nothing() {
    let mut reqs = Requests::new();
    reqs.send(Request::Ping, 0).unwrap();

    // Empty slice → Truncated
    let reply = reqs.on_reply(&[]);
    assert_eq!(reply, Reply::Malformed(CodecError::Truncated));
    assert_eq!(reqs.in_flight(), 1);

    // Tag 0 is not a response tag → BadKind(0)
    let reply = reqs.on_reply(&[0, 0, 0, 0, 1]);
    assert_eq!(reply, Reply::Malformed(CodecError::BadKind(0)));
    assert_eq!(reqs.in_flight(), 1);

    // Truncated id (only 3 bytes after tag)
    let reply = reqs.on_reply(&[128, 0, 0, 0]);
    assert_eq!(reply, Reply::Malformed(CodecError::Truncated));
    assert_eq!(reqs.in_flight(), 1);
}

#[test]
fn expire_returns_expired_oldest_first() {
    let mut reqs = Requests::new();
    let r1 = Request::Ping;
    let r2 = Request::Sync { room: "a".into(), cursor: 0 };
    let r3 = Request::MarkRead { room: "b".into(), cursor: 0 };
    reqs.send(r1.clone(), 0).unwrap(); // id 1
    reqs.send(r2.clone(), 1_000).unwrap(); // id 2
    reqs.send(r3.clone(), 2_000).unwrap(); // id 3

    // At 17_000: r1 (17000>=15000), r2 (16000>=15000), r3 (15000>=15000) all expire
    let expired = reqs.expire(17_000);
    assert_eq!(expired, vec![(1, r1), (2, r2), (3, r3)]);
    assert_eq!(reqs.in_flight(), 0);
}

#[test]
fn expire_boundary_at_exactly_timeout_ms() {
    let mut reqs = Requests::new();
    let req = Request::Ping;
    reqs.send(req.clone(), 10_000).unwrap();

    // 14_999 < 15_000 → not expired
    assert_eq!(reqs.expire(10_000 + TIMEOUT_MS - 1), Vec::<(u32, Request)>::new());
    assert_eq!(reqs.in_flight(), 1);

    // 15_000 >= 15_000 → expired
    let expired = reqs.expire(10_000 + TIMEOUT_MS);
    assert_eq!(expired, vec![(1, req)]);
    assert_eq!(reqs.in_flight(), 0);
}

#[test]
fn expire_earlier_than_send_time_expires_nothing() {
    let mut reqs = Requests::new();
    let req = Request::Ping;
    reqs.send(req.clone(), 5_000).unwrap();

    let expired = reqs.expire(4_000);
    assert!(expired.is_empty());
    assert_eq!(reqs.in_flight(), 1);
}

#[test]
fn expire_same_send_time_ordered_by_id() {
    let mut reqs = Requests::new();
    let r1 = Request::Ping;
    let r2 = Request::Sync { room: "a".into(), cursor: 0 };
    let r3 = Request::MarkRead { room: "b".into(), cursor: 0 };
    reqs.send(r1.clone(), 0).unwrap(); // id 1
    reqs.send(r2.clone(), 0).unwrap(); // id 2
    reqs.send(r3.clone(), 0).unwrap(); // id 3

    let expired = reqs.expire(TIMEOUT_MS);
    assert_eq!(expired, vec![(1, r1), (2, r2), (3, r3)]);
}

#[test]
fn in_flight_tracks_replies_and_expirations() {
    let mut reqs = Requests::new();
    assert_eq!(reqs.in_flight(), 0);

    reqs.send(Request::Ping, 0).unwrap(); // id 1
    assert_eq!(reqs.in_flight(), 1);

    reqs.send(Request::Ping, 0).unwrap(); // id 2
    assert_eq!(reqs.in_flight(), 2);

    // Reply to id 1
    let bytes = encode_response(1, &Response::Ok { cursor: 0 }).unwrap();
    reqs.on_reply(&bytes);
    assert_eq!(reqs.in_flight(), 1);

    // Expire id 2
    reqs.expire(TIMEOUT_MS);
    assert_eq!(reqs.in_flight(), 0);
}
