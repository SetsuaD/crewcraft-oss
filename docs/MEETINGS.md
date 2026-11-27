# Meetings and the calendar (design, task T370)

REQUIREMENTS.md section 2.5 says what meetings must do ("Guest meetings", "Staff-only meetings", "Calendar"), section
2.1 that a meeting edit is a system line, section 2.11 that creating, cancelling and editing a meeting is audited, and
section 3 what a meeting record holds. docs/CALLS.md built the calls a meeting runs on. This is the plan for meetings;
each slice lands as its own test-defined task.

## What a meeting is

A meeting is a **scheduled call in one room**. It never has a call of its own kind: joining a meeting joins (or starts)
that room's one open call, exactly as `CallStart` does (T360a1), so ringing, liveness, history lines, missed calls,
media credentials, removal and end-to-end keys all stay where CALLS.md put them. The meeting only adds a schedule, an
audience, an edit version and a link to the calls it ran on.

The record, kept by the chat server and rebuilt from its journal:

| Field | Meaning |
|---|---|
| `id` | A number the server gives, unique on the server. It is not a secret: it only works for members of the room. |
| `room` | The room the meeting belongs to. A meeting never moves to another room. |
| `owner` | Who scheduled it. |
| `audience` | `staff` or `guests`, fixed when the meeting is made. This slice makes only `staff`. |
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
  access, whatever settings change later. A guest meeting is a different meeting, made as one (later slice).
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
  cancelled; two meetings of one room that overlap share the room's one open call.
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
  owner | u8 audience (0 staff) | u64 start_ms | u16 duration | str title | str agenda | u8 state)`, state 0 scheduled,
  1 in progress (its call is open), 2 held (it had calls, none open), 3 cancelled.
- Push 85 `MeetingLine`: `u64 meeting | u8 change (1 scheduled, 2 edited, 3 cancelled) | u64 version | str author | str
  text`, an event that advances the cursor, like `CallLine`. A client refreshes its agenda when it sees one.
- Errors: unknown meeting or not in its room, `E_NO_SUCH_MEETING` (14); stale version, `E_CONFLICT` (13); started or
  cancelled, or not allowed to change it, `E_NOT_ALLOWED` (3); a bad title, agenda, length or window, `E_BAD_TEXT` (4).
- Journal: one record tag, 40, with a kind byte inside (scheduled, edited, cancelled, call linked), so meetings take one
  tag of the server's journal format.

## What the media server sees

Nothing new. A meeting's call is an ordinary call: the media server gets the same credentials, `DropPerson` and
`EndCall` events. It never learns titles, agendas or schedules.

## Guest meetings and the lobby (later)

A guest meeting is made with audience `guests` and gets what a staff meeting never has: an unguessable code of about
119 bits instead of the staff meeting's number, an expiry (a few hours to 30 days), lobby on or off, and guest records
(REQUIREMENTS sections 3 and 4). Its call has the guest entrance; admitted guests get a media credential scoped to that
meeting with a guest prefix; lobby decisions are system lines; cancelling turns away everyone waiting and drops
admitted guests through `DropPerson`. All of it attaches to the same record by audience, so nothing in this slice
changes when it lands, and because audience never changes a staff meeting stays out of all of it.

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
3. **T370c, guest meetings and the lobby**, with the guest entrance; then audit entries in `audit.log`.

## Open questions for the owner

1. Who may edit or cancel: this design says the owner, room admins and room owners. Should any member who may post?
2. A meeting can be joined any time before it is cancelled, days early or long after its end. Should joining open only
   near the start (for example 15 minutes before) and close some time after the end?
3. System lines show times in UTC, because the server has no time zone database. Is that acceptable until lines carry
   the time as data for each client to show in its own zone?
