# Meetings and the calendar (design, task T370)

REQUIREMENTS.md section 2.5 says what meetings must do ("Guest meetings", "Staff-only meetings", "Calendar"), section
2.1 that a meeting edit is a system line, section 2.11 that creating, cancelling and editing a meeting is audited, and
section 3 what a meeting record holds. docs/CALLS.md built the calls a meeting runs on. This is the plan for meetings;
each slice lands as its own test-defined task.

## What a meeting is

A meeting is a **scheduled call in one room**. Staff meetings join or start the room's open staff call as
`CallStart` does (T360a1). The meeting adds a schedule, an audience, an edit version and a link to the calls it ran
on. T370c adds an exclusive call binding for guest meetings.

The record, kept by the chat server and rebuilt from its journal:

| Field | Meaning |
|---|---|
| `id` | A number the server gives, unique on the server. It is not a secret: it only works for members of the room. |
| `room` | The room the meeting belongs to. A meeting never moves to another room. |
| `owner` | Who scheduled it. |
| `audience` | `staff` or `guests`, fixed when the meeting is made. T370a creates staff meetings. T370c adds explicit guest creation. |
| `title` | 1 to 200 characters after trimming, no control characters. |
| `start_ms`, `duration` | The start in UTC milliseconds and a length of 1 to 1,440 minutes. |
| `agenda` | Plain text, 0 to 4,000 characters (a message's length). |
| `version` | 1 when made; every saved change (edit or cancel) adds one. |
| `cancelled` | Set by cancelling; a cancelled meeting never changes again. |
| `calls` | The calls joined through the meeting, open or ended. |

Times are UTC on the server. The server has no time zone database (chrono, default features off): a client turns its
own local work week into a UTC window and shows times in its own zone.

## Rules

- **Who.** Only members of the room see, schedule, edit, cancel or join its meetings. Scheduling, editing and
  cancelling need a member who may start a call (not a Guest-role member, not an archive room); editing and
  cancelling also need the meeting's owner or a room admin or owner. Joining needs any member, as joining a call does.
  Anything about a meeting in a room I am not in answers exactly like a meeting that does not exist.
- **Staff audience is the default and is permanent.** A meeting made without saying otherwise is `staff`: only room
  members join and it has no guest link. No request changes a meeting's audience, so a staff meeting never gains guest
  access, whatever settings change later. Guest meetings have their own creation request.
- **Version checks.** An edit or a cancel carries the version the client last saw. A stale version is a conflict
  (409 in REQUIREMENTS section 4's terms): nothing changes, and the client keeps its unsaved edits and asks the person
  to reload explicitly; it never resends on its own.
- **No change, no history.** An edit whose fields equal the saved ones (after trimming) succeeds at the same version
  and records nothing: no journal record, no system line, no audit entry. The version is checked first, so a stale
  no-change edit is still a conflict.
- **Started means frozen.** A meeting that has any call, open or ended, can no longer be edited, rescheduled or
  cancelled (422, not allowed). A meeting whose start time passed with nobody joining is still editable: rescheduling a
  meeting that did not happen is the common case.
- **Cancelling** sets `cancelled` and adds one to the version. A cancelled meeting cannot be joined, edited or
  cancelled again. It stays on record, and the calendar shows it marked cancelled.
- **Joining by id.** `MeetingJoin { meeting }` is enough: the server finds the room. A member joins the room's open
  call, or starts one if there is none (a video call; a Guest-role member can join an open call but not start one, as
  with `CallStart`), and that call is added to the meeting's `calls`. A meeting can be joined at any time before it is
  cancelled. Overlapping staff meetings can share the room's open staff call. A guest meeting follows the binding
  rules below.
- **Started on the spot** is scheduling a meeting that starts now, then joining it: two requests, no special case.
- **System lines**, built by the server from the record, never from client text, as `EventKind::MeetingLine`
  events: "scheduled a meeting: <title>, <start in UTC>, <duration>"; "edited the meeting: <title>, <start in UTC>,
  <duration>" (the 2.1 "meeting edited" line, also used for a reschedule); "cancelled the meeting: <title>". Like call
  lines they never count as unread. The call's own lines ("started a call", "call ended ...") are unchanged.
- **Audit.** Each schedule, saved edit and cancel is a journal record naming who, when and the meeting; that is the
  record 2.11 asks for. Copying those entries into the server's `audit.log` (T611l) is a later slice.
- **Concurrency.** Meeting changes run under the same server lock as every room change, so the version check, the
  started check and the change are one step; a join that links a call and an edit cannot both win.

## Calendar queries

`MeetingList { from_ms, to_ms }` answers every meeting in my rooms that overlaps the window (cancelled ones included,
marked), ordered by start then id. The window is at most 8 days, enough for a work week in any time zone, and at most
200 meetings come back, with a `more` flag when there are more (the client then narrows the window). The client makes
the window from its local Monday 00:00 to Saturday 00:00 with chrono; client-core has the helper.

## Wire (FEATURE_MEETINGS)

Behind the handshake feature bit `FEATURE_MEETINGS` (16384); a client that did not agree to it is never sent the new
frames and gets `Other` for a meeting line. Strings as elsewhere in `request` (`u16` length).

- Request 44 `MeetingSave`: `str room | u64 meeting (0 makes a new one) | u64 version (0 for new) | u64 start_ms | u16
  duration minutes | str title | str agenda`. Answered `Ok { cursor }` with the meeting's id, then one meetings frame
  holding the saved meeting.
- Request 45 `MeetingCancel`: `str room | u64 meeting | u64 version`. Answered `Ok { cursor }` with the new version.
- Request 46 `MeetingList`: `u64 from_ms | u64 to_ms`. Answered `Ok { cursor: n }`, then one meetings frame.
- Request 47 `MeetingJoin`: `u64 meeting`. Answered as `CallStart` is: `Ok { cursor }` with the call's id and, with
  `FEATURE_MEDIA`, the media frame.
- Follow frame 143, meetings: `u8 tag | u32 id | u8 more | u16 n | n × (u64 meeting | str room | u64 version | str
  owner | u8 audience (0 staff, 1 guests) | u64 start_ms | u16 duration | str title | str agenda | u8 state)`, state 0 scheduled,
  1 in progress (its call is open), 2 held (it had calls, none open), 3 cancelled.
- Push 85 `MeetingLine`: `u64 meeting | u8 change (1 scheduled, 2 edited, 3 cancelled) | u64 version | str author | str
  text`, an event that advances the cursor, like `CallLine`. A client refreshes its agenda when it sees one.
- Errors: unknown meeting or not in its room, `E_NO_SUCH_MEETING` (14); stale version, `E_CONFLICT` (13); started or
  cancelled, or not allowed to change it, `E_NOT_ALLOWED` (3); a bad title, agenda, length or window, `E_BAD_TEXT` (4).
- Journal: one record tag, 40, with a kind byte inside (scheduled, edited, cancelled, call linked), so meetings take one
  tag of the server's journal format.

## Staff-call media

A staff meeting uses the existing media credentials, `DropPerson` and `EndCall` events. The media server receives
no titles, agendas or schedules.

## Guest meetings and the lobby (T370c)

A staff member explicitly creates a `guests` meeting in a room where they can start a call. The server chooses a
link code from 15 random bytes (120 bits), encodes it as 24 unpadded Base32 characters, and returns it to the
creator once. It stores only a domain-separated digest. Creation also records the first name the creator
chooses to show guests. The name uses the same normalization and limits as a guest name. The creator chooses
an expiry 3 hours to 30 days after creation. The link is closed at that instant. The lobby defaults on.
The meeting owner or a room
admin or owner can change the lobby setting or close the link. Turning the lobby off requires confirmation of the
warning that new guests will enter directly. Existing waiting guests still need a decision.

- **Entrance.** A server-side trait takes typed lookup, knock, status and media requests. T370c calls it in
  process. A future transport supplies the verified peer address, while the server supplies the time and
  generates secrets. Lookup reveals only the meeting title and the first name chosen for guests. Knock
  normalizes the name, removes control and bidirectional-override characters, and accepts 1–60 characters after trimming. The
  server allocates an opaque guest ID and returns a fresh 32-byte bearer once. Status and media require the
  matching meeting and bearer. The guest can read their own state. Guests have no room membership, staff session
  or access to the room API.
- **State.** Each guest record contains its meeting, ID, display name, bearer digest with a separate domain from
  link codes, state and revision. A knock starts in `waiting`, or in `admitted` when the lobby is off. Staff
  with current call-start permission can admit or decline a waiting guest, or remove an admitted guest.
  Declined and removed are terminal. Bound waiting guests to 25 by default and retained guests to 64 per
  meeting. Lookup, knock and status have per-address limits and bounded limiter storage. Only an abuse
  investigation needs source addresses. Secrets stay out of journal data, audit entries and debug output.
- **Call binding.** A staff member explicitly joins the guest meeting by ID to start or join its open call.
  That call belongs to this guest meeting alone, within the existing one-open-call room limit. An ordinary
  call or a different meeting cannot reuse it. A join fails while an incompatible call is open. Guests never
  start calls. The binding survives replay and excludes the call from both missed-call projections.
- **Media.** A waiting guest may be admitted before a call opens. A media request succeeds only for a currently
  admitted guest, a live link and the open call bound to the same meeting. The trusted entrance gets a
  short-lived, single-use credential for that room, call and media server, with an opaque `guest:<id>`
  identity and a separate display label ending in `(guest)`. Its validity ends before the link expires. The
  credential stays in the trusted relay. A future live adapter must check authority at relay time and prevent
  a queued offer from succeeding after removal, expiry or cancellation. It must also enforce expiry on
  connected guests and reconcile drops after a restart or control-link outage before accepting offers.
- **Decisions and closure.** The journal records the actor, time and decision. A server-built, non-unread
  system line shows admission, decline, removal, automatic admission or link closure in the staff room. A
  closed link declines all waiting guests and removes all admitted guests in one operation. Closing the
  link works after a call starts and leaves the staff call running. Cancelling an unstarted guest meeting
  closes its schedule and link in the same journal operation. The expiry sweep uses the same closure
  transition, while entry refuses an expired link immediately. After the durable write, removal and closure
  enqueue the existing `DropPerson` for each affected guest on the bound open call. Replay uses the recorded
  decisions and times.

The staff API negotiates feature 65536 alongside `FEATURE_MEETINGS`. Clients without the guest feature see
only staff entries in their calendar and cannot join guest meetings. Request 50 creates a guest meeting or
updates its lobby setting. Request 51 closes a link, 52 lists the lobby, and 53 applies a decision. Updates
carry the last observed revision. Follow 145 gives the correlated result or bounded lobby snapshot. Only a
successful creation returns the code. Push 87 gives staff the current room waiting count and lobby revision
on Sync, including unchanged room cursors and zero waiting. The room history records committed decisions
separately from that count. Guests use typed in-process messages. Errors 18 and 19 cover unknown guest
records and unavailable links. Journal family 42 records guest operations and replays the same transitions
and call binding. Staff operations keep journal family 40 and the existing wire contract.

## Slices

1. **T370a, server-side staff meetings (this design's first slice).** The wire above in `crates/proto`, journal-backed
   records and the rules in `crates/server-core`, the network server's wiring, and the `crates/client-core` API
   (requests, the meetings frame, `MeetingLine`, the work-week window helper). No desktop UI.
   **Built (T370a).** `crewcraft_proto::meeting` (the record, the meetings frame, the limits), the four requests and
   `MeetingLine`; `crewcraft_server_core::meetings` (records under journal tag 40, the rules above, replay);
   `connection` answers the requests behind `FEATURE_MEETINGS`, which the network server announces;
   `crewcraft_client_core::calendar::work_week` and the `Meetings` and `MeetingLine` client events. Audit entries in
   `audit.log` and the app are not part of it.
2. **T370b, the calendar in the app.** The work-week agenda, the schedule and edit form (unsaved edits kept on a failed
   save, the conflict notice with an explicit reload), join buttons, start now.
<<<<<<< HEAD
3. **T370c, guest meetings and the lobby.** Staff requests, lobby counts, journal replay, in-process guest
   entrance and staff client-core API. Test expiry, waiting and direct admission, decline, media isolation and
   removal, link closure, staff-only privacy and restart. Browser ingress, live guest media transport, desktop
   lobby controls and ringing, and export to `audit.log` are later slices.
=======
   **Built (T370b).** The app bar's Calendar (and a Calendar button on the phone) shows a work week's meetings in my
   rooms, from `calendar::work_week_at` with the app's clock, with Previous week, This week and Next week
   (`crates/desktop-ui/src/calendar.rs`; the worker in `apps/crewcraft/src/worker.rs`). Cancelled meetings are marked
   "(cancelled)" and offer nothing; Edit and Cancel are offered only before a meeting's first call, and Cancel asks
   first. The form takes the start as `YYYY-MM-DD HH:MM` in UTC and checks every field before sending. A refused save
   keeps what was typed; a conflict disables Save until Reload, which shows the meeting as it is now. Start now
   schedules a meeting that starts now and joins it. Not yet: the app reads no time zone, so the week and every time
   are UTC (the area says so); since T370b2 the open calendar reads its week again when a meeting line arrives in a room
   the app follows, and meeting lines show in the room between messages, like call lines.
3. **T370c, guest meetings and the lobby**, with the guest entrance; then audit entries in `audit.log`.
>>>>>>> c8439a4 (T370b: the calendar in the app)

## Open questions for the owner

1. Who may edit or cancel: this design says the owner, room admins and room owners. Should any member who may post?
2. A meeting can be joined any time before it is cancelled, days early or long after its end. Should joining open only
   near the start (for example 15 minutes before) and close some time after the end?
3. System lines show times in UTC, because the server has no time zone database. Is that acceptable until lines carry
   the time as data for each client to show in its own zone?
