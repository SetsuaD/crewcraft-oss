# Recovery after an event-history gap

T345 design, written before implementation on 2026-11-26. The pull request carries implementation and validation
status. This is a bounded current-state recovery path, not a reconstruction of unavailable historical events.

## Compatibility and scope

Normal incremental Sync stays unchanged. `FEATURE_GAP_REPLAY = 2048` negotiates request `Current` (30), push `Gap`
(81) and follow frame `CurrentPage` (139). A client without the feature receives none of these new shapes and keeps
its existing explicit `HistoryGap` behavior. The durable server can recover original messages from its current
projection; a memory-only server must refuse recovery it cannot supply.

The working app path includes the protocol and server/client libraries, the signed-in session and worker bridge,
and a persistent room-specific banner in the existing desktop and phone feed. No separate client is introduced.

## One consistent, bounded capture

For a negotiated Sync whose cursor precedes the retained event tail, the server sends
`Gap { room, cursor: head, after: requested_cursor, oldest: oldest_retained_cursor }` after the other Sync metadata.
The missing event interval is `after + 1 .. oldest - 1`. The client consumes the complete response, including any
negotiated pin and read snapshots, before requesting recovery.

`Current { room }` is one authenticated request. While holding the existing room-state mutex, the server selects
the newest **50 live current messages**, filtering deletions before applying the limit. It captures their current
bodies and associated metadata at one room head. It builds the complete bounded reply before returning success and
releases the mutex before network writes. It keeps no snapshot cache, generation counter or new journal record.

The acknowledgement is `Ok { cursor: captured_head }`, followed by one or more CurrentPage frames with the same
request ID, room, head, archive flag and `older` flag. `older` means live current messages exist outside this
window; it does not mean those messages were deleted or irretrievably lost. Page indexes start at zero and advance
consecutively. `last` explicitly terminates the stream. An empty room still sends one empty final page. Other
nonterminal empty pages are invalid.

Each page holds at most **16 records**. The sum of framed CurrentPage bytes, including their four-byte length
prefixes but excluding the fixed acknowledgement, is at most **8 MiB**, and the stream contains at most **32,768
records**. Each individual frame also respects the existing 1 MiB frame limit. Budget checks happen before
unbounded cloning or allocation. In particular, replay iterates borrowed reaction sets rather than cloning an
entire set before checking its limit. If capture or encoding exceeds a bound, the server returns an existing
refusal with no partial acknowledgement or pages. Response details remain empty.

This single-request capture avoids a full-room startup walk and repeated pagination restarts in an active room.
Every request checks current membership. The pages of this one response share that authorization point; they are
not separate requests. The following Sync checks membership again.

## Current records

Records are ordered strictly by `(message_cursor, kind, index_or_code, actor)`, where kind is Message, File, then
Reaction. Messages are unique, have cursors in `1 ..= captured_head`, and precede their own metadata records.

- A **Message** has its cursor, original author, complete current sanitized HTML, edited flag, optional true thread
  parent ID and optional imported timestamp. Parents may be outside the window or deleted; no old cached parent
  body is borrowed as current content.
- A **File** has its message cursor, contiguous file index and the existing bounded AttachedFile fields. Only
  current attachments are included.
- A **Reaction** has its message cursor, supported reaction code and actor. Individual sorted edges avoid an
  unbounded nested reactor vector.

The codec validates all string, boolean, kind, index, reaction, ordering and trailing-byte limits. Metadata without
its message in the captured window is invalid. The archive flag and imported times are current state. Earlier
call-history events are not reconstructed from message bodies; current open-call state is restored by Sync.

## Staged client installation

The client uses one original operation deadline and at most one recovery attempt. It stages the entire reply
outside the visible RoomView. It independently checks request ID, room, head, flags, consecutive page indexes,
record ordering, message uniqueness, terminal shape and all byte/count limits. The captured head must be at least
the current timeline cursor and the Gap push's head. Interrupted, mismatched, repeated, stale or oversized pages
leave the previous view and pending sends intact and retain an explicit gap. They never report successful Sync.

The page-reading phase decodes only CurrentPage frames. After its terminal page, the existing Ping exchange seals
the response boundary before installation: normal receive paths reject unexpected CurrentPage frames, so an extra
or repeated page before the matched Ping acknowledgement invalidates the transfer while the old view is still
intact. The Ping stays within the original deadline and introduces no protocol number.

After a complete valid stream, installation replaces the timeline at the captured **event head**, rather than the
last message cursor. It replaces files, thread parents, reactions, archive times and archive status, clears old
call history/open-call/key/seal caches, and preserves outbox and acknowledgement safety. Snapshot rows do not enter
the normal incoming-message notification path. Pin/read revision guards remain in force; fresh state is required
before Sync reports success.

The client then performs a normal Sync from the captured head. That applies later events and consumes fresh pin,
read and current-call metadata. If this second Sync encounters another gap or fails, recovery reports that failure
without recursively starting another Current walk. A completely installed captured window remains explicitly
marked as recovered state; partial records are never exposed as a complete replacement.

Without either pin or read snapshots, a Sync acknowledgement and last Posted event do not delimit trailing file,
thread, imported-time or call metadata. Recovery then uses the existing Ping exchange as a final drain barrier,
within the same deadline. Receiving its matched reply proves that the preceding Sync sidebands were consumed.
This barrier follows the fresh Sync; it serves a different purpose from the pre-installation page boundary.
Ordinary incremental Sync and the protocol numbers stay unchanged.

The worker forces all replacement metadata updates, including empty file/thread/reaction/time/call lists, even if
message text is unchanged. It refreshes the personal Saved view when requested. Pins and saved references outside
the 50-message window continue to resolve through the existing full current-state APIs.

Recovered live messages remain actionable. Durable reaction and reply validation uses the full current-message
projection rather than requiring the original post to remain in the event tail. Existing membership, posting,
read-only, reaction-code, rate-limit and top-level-parent checks retain their ordering and behavior. Journal replay
uses the same live-target validation, so actions on recovered posts survive a subsequent reopen. Deleted or
inaccessible targets remain refused.

## Honest visible history

A room-specific gap notice survives a successful follow-up Sync. It states that earlier event history could not be
replayed and that the displayed messages are recovered current state. A separate `older` indication says earlier
current messages are not loaded in this window. It must not label unloaded current messages as lost history. This
change does not add older-window paging controls or pretend the unavailable event chronology was reconstructed.

Existing feeds hide replies under their parent. A reply whose parent is absent must instead remain visible with
explicit unavailable-parent context and its real parent ID. The existing View thread action opens the available
children with an unavailable-parent notice. Both desktop and phone layouts follow this rule, including when all
50 recovered messages are replies. No fabricated parent or silently flattened relationship is introduced.

The banner and reply context use existing text/theme controls, remain available to accessibility tools, and do not
take keyboard focus away. Navigation uses existing real buttons. Native assistive-technology acceptance is separate
from automated interface checks.

## Required verification

- A real enrolled session offline past the retained tail recovers current edited/deleted message state and a
  persistent gap notice, then continues with ordinary incremental messages at the correct event cursor.
- A window larger than 50 live messages is bounded, marks unloaded older state accurately, and keeps pin/read/saved
  state correct even when their target is outside the recovered window.
- Already-populated message and metadata caches are replaced atomically; interrupted or hostile streams preserve
  the old view and pending sends. Empty recovery clears stale state too.
- Replies to missing parents stay visible and usable on desktop and phone. Snapshot records do not create fresh
  message notifications.
- In-tail and unnegotiated legacy Sync stay unchanged. Membership refusals disclose no replay body. A subsequent
  operation checks membership again, and a repeated gap stays bounded and explicit.

Exact-commit portable validation and both required pull-request statuses are the source acceptance gate. Physical
device and release acceptance remain separate claims.
