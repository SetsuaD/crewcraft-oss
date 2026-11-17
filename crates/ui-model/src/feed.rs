//! The rows of a conversation feed, built from a room view's `shown()` list. Task T302.

use crewcraft_client_core::room_view::Shown;

use crate::FeedRow;

/// One `FeedRow` per entry of `shown`, in the same order. `Shown::Line` becomes `FeedRow::Message` (cursor, author,
/// html and edited copied over) and `Shown::Pending` becomes `FeedRow::Pending` (id, body and failed copied over).
/// `first_of_group` is true unless the row directly above is a `Message` by the same author (exact comparison); the
/// first row is always true, and a `Pending` row above breaks a group.
#[allow(clippy::todo, reason = "stub until task T302 lands; remove this allow with it")]
pub fn feed_rows(shown: &[Shown]) -> Vec<FeedRow> {
    let _ = shown;
    todo!("T302: feed_rows")
}
