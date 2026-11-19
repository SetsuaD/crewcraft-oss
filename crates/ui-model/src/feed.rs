//! The rows of a conversation feed, built from a room view's `shown()` list. Task T302.

use crewcraft_client_core::room_view::Shown;

use crate::FeedRow;

/// One `FeedRow` per entry of `shown`, in the same order. `Shown::Line` becomes `FeedRow::Message` (cursor, author,
/// html and edited copied over) and `Shown::Pending` becomes `FeedRow::Pending` (id, body and failed copied over).
/// `first_of_group` is true unless the row directly above is a `Message` by the same author (exact comparison); the
/// first row is always true, and a `Pending` row above breaks a group.
pub fn feed_rows(shown: &[Shown]) -> Vec<FeedRow> {
    let mut rows = Vec::with_capacity(shown.len());
    let mut previous_author: Option<&str> = None;
    for entry in shown {
        match entry {
            Shown::Line(line) => {
                rows.push(FeedRow::Message {
                    cursor: line.cursor,
                    author: line.author.clone(),
                    html: line.html.clone(),
                    edited: line.edited,
                    first_of_group: previous_author != Some(line.author.as_str()),
                });
                previous_author = Some(line.author.as_str());
            }
            Shown::Pending { id, body, failed } => {
                rows.push(FeedRow::Pending { id: *id, body: body.clone(), failed: *failed });
                previous_author = None;
            }
        }
    }
    rows
}
