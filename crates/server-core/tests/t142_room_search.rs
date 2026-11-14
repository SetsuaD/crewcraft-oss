#![allow(clippy::unwrap_used)]

use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_search::{Hit, RoomSearch};
use crewcraft_server_core::room_service::{Event, EventKind};
use crewcraft_server_core::server::Server;

#[test]
fn new_search_returns_empty() {
    let search = RoomSearch::new();
    let server = Server::new();
    let hits = search.search(&server, "alice", "hello", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

#[test]
fn default_matches_new() {
    let a = RoomSearch::default();
    let b = RoomSearch::new();
    let server = Server::new();
    assert_eq!(a.search(&server, "alice", "test", 5), b.search(&server, "alice", "test", 5));
}

#[test]
fn posted_event_is_searchable_by_member_but_not_non_member() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();

    let mut search = RoomSearch::new();
    let event = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "hello world".to_string(), mentions: Vec::new() };
    search.index(&slug, 1, &event);

    // alice is the owner (a member)
    let hits = search.search(&server, "alice", "hello", 10);
    assert_eq!(hits, vec![Hit { slug: slug.clone(), cursor: 1 }]);

    // bob is not a member
    let hits = search.search(&server, "bob", "hello", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

#[test]
fn edited_event_replaces_text_at_target_cursor() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();

    let mut search = RoomSearch::new();

    // Post at cursor 1
    let posted = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "old text here".to_string(), mentions: Vec::new() };
    search.index(&slug, 1, &posted);

    // Edit at cursor 2, targeting cursor 1
    let edited = Event {
        cursor: 2,
        actor: "alice".to_string(),
        kind: EventKind::Edited { target: 1 },
        html: "new text now".to_string(),
        mentions: Vec::new(),
    };
    search.index(&slug, 2, &edited);

    // Old text is gone
    let hits = search.search(&server, "alice", "old", 10);
    assert_eq!(hits, Vec::<Hit>::new());

    // New text is present, under the original cursor (target = 1)
    let hits = search.search(&server, "alice", "new", 10);
    assert_eq!(hits, vec![Hit { slug: slug.clone(), cursor: 1 }]);
}

#[test]
fn deleted_event_removes_target_from_index() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();

    let mut search = RoomSearch::new();

    let posted = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "secret message".to_string(), mentions: Vec::new() };
    search.index(&slug, 1, &posted);

    let deleted = Event { cursor: 2, actor: "alice".to_string(), kind: EventKind::Deleted { target: 1 }, html: String::new(), mentions: Vec::new() };
    search.index(&slug, 2, &deleted);

    let hits = search.search(&server, "alice", "secret", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

#[test]
fn membership_events_index_nothing() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();

    let mut search = RoomSearch::new();

    let joined = Event {
        cursor: 1,
        actor: "alice".to_string(),
        kind: EventKind::Joined { user: "bob".to_string(), role: Role::Member },
        html: String::new(),
        mentions: Vec::new(),
    };
    search.index(&slug, 1, &joined);

    let left =
        Event { cursor: 2, actor: "alice".to_string(), kind: EventKind::Left { user: "bob".to_string() }, html: String::new(), mentions: Vec::new() };
    search.index(&slug, 2, &left);

    let hits = search.search(&server, "alice", "anything", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

#[test]
fn search_visits_only_rooms_user_is_member_of() {
    let mut server = Server::new();
    let slug_a = server.create_room("alice", "alpha").unwrap();
    let slug_b = server.create_room("bob", "beta").unwrap();

    // Alice is not a member of beta; bob is not a member of alpha.
    let mut search = RoomSearch::new();

    let event_a =
        Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "shared word here".to_string(), mentions: Vec::new() };
    search.index(&slug_a, 1, &event_a);

    let event_b = Event { cursor: 1, actor: "bob".to_string(), kind: EventKind::Posted, html: "shared word here".to_string(), mentions: Vec::new() };
    search.index(&slug_b, 1, &event_b);

    // alice sees only alpha
    let hits = search.search(&server, "alice", "shared", 10);
    assert_eq!(hits, vec![Hit { slug: slug_a.clone(), cursor: 1 }]);

    // bob sees only beta
    let hits = search.search(&server, "bob", "shared", 10);
    assert_eq!(hits, vec![Hit { slug: slug_b.clone(), cursor: 1 }]);

    // carol is in neither
    let hits = search.search(&server, "carol", "shared", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

#[test]
fn search_orders_newest_cursor_first_across_rooms() {
    let mut server = Server::new();
    let slug_a = server.create_room("alice", "alpha").unwrap();
    let slug_b = server.create_room("alice", "beta").unwrap();

    let mut search = RoomSearch::new();

    // alpha: cursors 1 and 3
    let e1 = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "common word".to_string(), mentions: Vec::new() };
    search.index(&slug_a, 1, &e1);

    let e3 = Event { cursor: 3, actor: "alice".to_string(), kind: EventKind::Posted, html: "common word".to_string(), mentions: Vec::new() };
    search.index(&slug_a, 3, &e3);

    // beta: cursor 2
    let e2 = Event { cursor: 2, actor: "alice".to_string(), kind: EventKind::Posted, html: "common word".to_string(), mentions: Vec::new() };
    search.index(&slug_b, 2, &e2);

    // Expected order: cursor 3 (alpha), cursor 2 (beta), cursor 1 (alpha)
    let hits = search.search(&server, "alice", "common", 10);
    assert_eq!(
        hits,
        vec![Hit { slug: slug_a.clone(), cursor: 3 }, Hit { slug: slug_b.clone(), cursor: 2 }, Hit { slug: slug_a.clone(), cursor: 1 },]
    );
}

#[test]
fn search_orders_equal_cursors_by_slug() {
    let mut server = Server::new();
    let slug_a = server.create_room("alice", "alpha").unwrap();
    let slug_b = server.create_room("alice", "beta").unwrap();

    let mut search = RoomSearch::new();

    let event = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "tied term".to_string(), mentions: Vec::new() };
    search.index(&slug_a, 1, &event);
    search.index(&slug_b, 1, &event);

    // Same cursor 1 in both rooms; "alpha" < "beta" so alpha first
    let hits = search.search(&server, "alice", "tied", 10);
    assert_eq!(hits, vec![Hit { slug: slug_a.clone(), cursor: 1 }, Hit { slug: slug_b.clone(), cursor: 1 },]);
}

#[test]
fn search_respects_global_limit() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();

    let mut search = RoomSearch::new();

    for cursor in 1..=4u64 {
        let event = Event { cursor, actor: "alice".to_string(), kind: EventKind::Posted, html: "capped word".to_string(), mentions: Vec::new() };
        search.index(&slug, cursor, &event);
    }

    // Limit 2: only the two newest (cursors 4 and 3)
    let hits = search.search(&server, "alice", "capped", 2);
    assert_eq!(hits, vec![Hit { slug: slug.clone(), cursor: 4 }, Hit { slug: slug.clone(), cursor: 3 },]);
}

#[test]
fn search_skips_room_not_on_server() {
    let server = Server::new();

    let mut search = RoomSearch::new();
    let event = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "phantom room text".to_string(), mentions: Vec::new() };
    search.index("phantom", 1, &event);

    // "phantom" was never created on the server → skipped silently
    let hits = search.search(&server, "alice", "phantom", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

#[test]
fn search_with_query_having_no_valid_terms_returns_empty() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();

    let mut search = RoomSearch::new();
    let event = Event { cursor: 1, actor: "alice".to_string(), kind: EventKind::Posted, html: "hello world".to_string(), mentions: Vec::new() };
    search.index(&slug, 1, &event);

    // "a" is a single alphanumeric char → term length 1 < 2 → dropped → no terms
    let hits = search.search(&server, "alice", "a", 10);
    assert_eq!(hits, Vec::<Hit>::new());

    // Empty string → no terms at all
    let hits = search.search(&server, "alice", "", 10);
    assert_eq!(hits, Vec::<Hit>::new());
}

/// Added in review: the index holds the text of the rendered html (not its tags or escapes), and membership is checked
/// when searching, so a member who leaves stops seeing the room.
#[test]
fn search_reads_html_text_and_current_membership() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "general").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();

    let mut search = RoomSearch::new();
    let event = Event {
        cursor: 2,
        actor: "alice".to_string(),
        kind: EventKind::Posted,
        html: "<strong>urgent</strong> &amp; more".to_string(),
        mentions: Vec::new(),
    };
    search.index(&slug, 2, &event);

    assert_eq!(search.search(&server, "bob", "urgent", 10), vec![Hit { slug: slug.clone(), cursor: 2 }]);
    assert_eq!(search.search(&server, "bob", "strong", 10), Vec::<Hit>::new());
    assert_eq!(search.search(&server, "bob", "amp", 10), Vec::<Hit>::new());

    server.remove_member(&slug, "bob", "bob").unwrap();
    assert_eq!(search.search(&server, "bob", "urgent", 10), Vec::<Hit>::new());
}
