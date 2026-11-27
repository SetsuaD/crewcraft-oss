# Personal activity

Activity shows mentions, replies in threads, reactions from someone else and missed calls. Every item belongs to one person across all of their devices. The feed and badge use the signed-in account and current room membership. Archived rooms contribute no items. Leaving a room retires its items for that person, so rejoining starts a new membership.

The server derives references from accepted journal operations. A reply that also mentions the recipient creates one row with both reasons. Editing text leaves existing activity in place and can add a newly introduced mention. An edit never creates another reply alert. A mention resolves to an exact current member handle or a unique current account with that email local part. An ambiguous local part has no recipient. Structured quote replies need a stored message reference before they can contribute to Activity. The current client can create thread replies.

Activity references the message instead of copying it into the journal. The list reads the current plain-text preview and current bookmark state. Deleted messages and withdrawn reactions drop out of the feed. A missed call is dated when it ended. Its recipient had to belong to the room before the call started and must have missed the whole call. The server uses the membership's recorded join cursor, which survives room event retention gaps and restarts.

The server retains up to 256 recent references for each person and returns up to 64 matching rows with an indication when the view has more. The Unread filter selects rows beyond the person's seen position. Mentions also includes replies with a mention. Saved selects rows whose associated message is bookmarked by that person. The badge counts unseen eligible rows in the retained window across filters.

Mark seen acknowledges the head of the displayed snapshot. A newer item that arrives after the snapshot stays unread. A second device retrieves the same position on its next refresh. Marking an earlier position is harmless. Opening the feed or changing its filter leaves the seen position unchanged. Room read positions are separate.

## Wire and storage

Feature bit 32768 announces Activity. A client sends requests 48 and 49 only when the server negotiates the feature. ListActivity (48) takes a filter byte and returns `Ok` with the person's head, followed by one snapshot frame (144) with the same request ID. A counter-only filter returns the same head, seen position and badge with no rows. The client uses that filter while the pane is closed. The open pane refreshes its selected filter using the existing poll loop. See `crates/proto/src/activity.rs` for the row format and length limits.

MarkActivitySeen (49) takes the displayed `through` position and returns `Ok` with the current seen position. A position beyond the person's head is refused with error 17. Only an advance writes journal operation 41 with the authenticated person's key and position. Replay reconstructs the same per-person item IDs from existing operations before applying the seen records. No new journal entry is needed to record each item. Push type 86 remains reserved.

The rules that issue an item ID are part of journal replay compatibility. A future change to those rules must preserve the IDs produced by old records or migrate the stored seen positions with them. Display filters can change independently.
