use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_ui_model::FeedRow;
use crewcraft_ui_model::feed::feed_rows;

fn line(cursor: u64, author: &str, html: &str, edited: bool) -> Shown {
    Shown::Line(Line { cursor, author: author.to_string(), html: html.to_string(), edited })
}

fn message(cursor: u64, author: &str, html: &str, edited: bool, first_of_group: bool) -> FeedRow {
    FeedRow::Message { cursor, author: author.to_string(), html: html.to_string(), edited, first_of_group }
}

#[test]
fn empty_room_has_no_rows() {
    assert!(feed_rows(&[]).is_empty());
}

#[test]
fn groups_consecutive_messages_by_the_same_author() {
    let shown = [
        line(1, "ana", "<p>hi</p>", false),
        line(2, "ana", "<p>there</p>", true),
        line(4, "ben", "<p>hello</p>", false),
        line(5, "ana", "<p>back</p>", false),
        line(6, "Ana", "<p>not the same author</p>", false),
    ];
    assert_eq!(
        feed_rows(&shown),
        vec![
            message(1, "ana", "<p>hi</p>", false, true),
            message(2, "ana", "<p>there</p>", true, false),
            message(4, "ben", "<p>hello</p>", false, true),
            message(5, "ana", "<p>back</p>", false, true),
            message(6, "Ana", "<p>not the same author</p>", false, true),
        ]
    );
}

#[test]
fn pending_rows_keep_their_place_and_break_groups() {
    let shown = [
        line(7, "ana", "<p>one</p>", false),
        Shown::Pending { id: 1, body: "mine".to_string(), failed: false },
        Shown::Pending { id: 2, body: "lost".to_string(), failed: true },
        line(8, "ana", "<p>two</p>", false),
    ];
    assert_eq!(
        feed_rows(&shown),
        vec![
            message(7, "ana", "<p>one</p>", false, true),
            FeedRow::Pending { id: 1, body: "mine".to_string(), failed: false },
            FeedRow::Pending { id: 2, body: "lost".to_string(), failed: true },
            message(8, "ana", "<p>two</p>", false, true),
        ]
    );
}
