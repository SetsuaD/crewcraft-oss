# CrewCraft requirements

This document lists the behaviours CrewCraft must have, in plain terms, so that they can be built and tested one at a
time. [SPEC.md](SPEC.md) says what CrewCraft is and records the decisions that shape it; where the two differ, SPEC.md
wins. [SECURITY-DESIGN.md](SECURITY-DESIGN.md) explains how access works.

Numbers called "default" are starting values; each should be a setting an administrator can change.

---

## 1. Overview

CrewCraft is a team-communication server, plus its clients, that an organization runs on hardware it controls. Staff
use it for direct messages, group rooms, team channels with threaded posts, files, presence, scheduling, and audio and
video calls with screen sharing. Its layout and workflow follow the familiar shape of mainstream team-chat tools (2.20), so people do
not need retraining, while its appearance comes from themes (2.19). It can also reach people outside the organization: guests
join video meetings from an ordinary browser through a lobby, without an account. It keeps everything that was said
(edits keep their history, deletion is redaction), can hold history imported from another system, and lets an
organization plug in its own identity provider and authorization service instead of the built-in ones.

---

## 2. Features

### 2.1 Messaging

- **Sending.** Every message belongs to exactly one room. The client sends an idempotency key with each message: the
  same key with the same content returns the message already stored; the same key with different content is a
  conflict. A body is limited in length (default 4,000 characters) and may be empty only when files are attached.
- **Direct messages.** A direct message is a two-member room identified by a canonical, sorted key of its two
  participants, so two people who start a conversation with each other at the same moment end up in one room. Starting
  a conversation with yourself opens your private notes room.
- **Formatting without HTML.** The server stores bodies as plain text. Clients render a small markdown subset (bold,
  italic, strikethrough, inline code, code blocks, quotes, bulleted and numbered lists, links) into safe elements; HTML
  is never stored and never rendered. *(Implementation status, early development: `server-core` currently renders the
  markdown subset on the server with an escape-everything renderer and keeps that HTML in the room log; moving rendering
  to the clients is planned.)* Every short preview (room list, notifications, quote snippets, activity items) is
  produced by the same parser as the full message, so a preview and its message always agree on what is formatting.
- **Quote replies.** When someone replies with a quote, the server builds the quote from the stored message it points
  to, which must be in the same room and not redacted. If the quoted message is later deleted, the quote stops showing
  its text.
- **Threads.** In team channels a reply attaches to a top-level post in the same room; replies to replies are refused.
  The post's reply count goes up. Opening a reply opens its parent's thread.
- **Editing.** Only the author may edit, only in a room that accepts writes, and never a redacted message. The earlier
  body is saved as a revision in the same transaction and the message is marked as edited. Moderators can read
  revisions. An edit that collides with another edit or with a deletion is a conflict and the person is asked to retry.
- **Deletion is redaction.** The author or a moderator clears the body in place, and the message then reads "This
  message has been deleted." Nothing is physically removed. Deletion by a moderator is audited.
- **Reactions.** A fixed set of named reactions plus any single emoji (short, with no letters or digits). Reacting
  again removes the reaction. Reactions are refused in read-only rooms, and each message has a cap on distinct
  reactions.
- **Mentions.** Mentioned people are kept only if they are current members of the room; each one gets an activity item.
- **Pinning.** A room has one pinned message; pinning another replaces it. Unpinning clears the pin only if it still
  points at that message. Pinning stays correct when it races replies and deletions.
- **Saved messages.** Each person can bookmark messages; the saved list shows every message in its current state.
- **System lines.** The server posts plain-text system messages for room events: people added, a rename, a call
  started or ended (with its duration and who took part), a lobby admit or decline, a meeting edited. Their content is
  built by the server, never from lists a client supplies.
- **Also in scope:** several pinned messages per room with a bar that cycles through them; coloured text and tables in
  formatted text; forwarding a message; link previews fetched only for hosts on an administrator's allowlist.

### 2.2 Rooms, teams and channels

- **Group rooms.** Created with a name (required), an optional topic and initial members. Members can be added, the room
  renamed, left or hidden.
- **Teams and channels.** A team has members and owners and always has a "General" channel, which cannot be renamed. A
  channel is a group room that belongs to a team. Team membership is copied into every channel's membership, and the
  channel membership stays the one check that authorizes messages. People are added to the team, not to a single
  channel. Channel names are unique within a team, and a team has a cap on channels. Leaving a team leaves all its
  channels, correctly even when that races other changes. Channels show posts with threaded replies; chats show message
  bubbles.
- **Personal room settings.** Each person can pin a room to the top of their list, mute it, hide it or mark it unread.
  A hidden room is still a real membership: search still finds it, and a new message in it does not unhide it.
- **Mark as unread.** From a chosen message, the person's read position moves to just before that message. Without a
  chosen message, it moves to just before the newest message written by someone else; if nobody else has written,
  nothing changes. Only that person's position moves.
- **Read-only rooms.** Imported history rooms and archived rooms never accept writes again: no sending, reacting,
  editing, pinning or uploading, and they do not count towards unread totals. Copying and saving still work.
- **Personal default rooms.** The first time someone opens CrewCraft they get a pinned notes room with exactly one
  member: nobody can be added and moderators can neither list nor read it. An administrator may also configure a
  personal room template (for example, a log room the person owns and may share). Each personal room is created once;
  if the person unpins it or leaves it, that choice stands.
- **Linked rooms.** A room may carry an opaque reference to a record in another system. There is at most one room per
  referenced record. References are plain values, not foreign keys.
- **Also in scope:** custom sections and favourites in the room list, filter chips, one combined list of chats and
  channels, room tabs (shared files, links and media, shared notes, pinned files with an in-place viewer, a whiteboard,
  a recap), a participant-count button, search within one conversation, and a shortcut to jump to a conversation.

### 2.3 Presence and status

- **Presence.** Automatic, Available, Busy, Do not disturb, Be right back, Appear away and Appear offline, plus an
  automatic "In a call". Automatic means online while a client has been in touch recently (default 90 seconds), away
  after a period with no input (default 5 minutes), and busy while the person's call heartbeat is fresh.
- **Status message.** Free text, optionally with an expiry time.
- **Typing.** A typist's client reports typing at most once every few seconds (default 3 seconds); someone counts as
  typing while their latest report is recent (about 6 seconds); sending clears it.
- **Read receipts.** Shown only in direct messages and in groups of 20 people or fewer, and only when both the reader
  and the viewer have receipts turned on. One privacy switch turns off both sending and seeing them; it is on by
  default. A read position only moves forward and only for messages the client actually displayed.
- **Two profiles.** An internal profile for colleagues (picture, job title, pronouns, about, status) and an external
  profile for guests and customer-facing rooms (picture, display name, title, status). The external profile never
  falls back to internal content.
- **Presence is not availability.** Presence never counts as being available to answer outside contacts (see 2.8).

### 2.4 Files

- **Upload.** The client sends the raw bytes as a streamed body (not multipart) with a declared length, up to a size
  limit (default 100 MB). Files are addressed by their SHA-256 hash, and image dimensions are read from the file
  header. Every refusal (wrong entrance, not signed in, missing capability, cross-origin request, storage not
  configured, not a member, read-only room, missing length, too large) happens before any byte of the body is read.
  When the upload finishes, membership and room state are checked again; if the person left or the room became
  read-only in the meantime, the temporary file is removed and no file record is created.
- **Attaching.** A message can carry up to 10 of the sender's uploads in that room that are not yet attached to
  anything. An upload already attached to another message is a conflict.
- **Download and preview.** Membership is checked on every request. Common raster images and PDF may display inline;
  everything else downloads as an attachment. Responses are sandboxed, forbid content sniffing and are marked private
  and not cacheable. A file on a redacted message, or one the person can no longer reach, is not found.
- **File browser.** Per room and across all of a person's rooms: substring search over file name, room name and
  uploader, a type filter (all, images, documents), and cursor paging in which each cursor is tied to the same person,
  room and query and access is re-checked on every page. Counts show rows loaded so far, never an implied total.
- **Shared bytes.** Identical content is stored once. If a database write fails after the bytes were moved into
  place, the bytes are deleted only when no file anywhere, attached or not, refers to that hash; when in doubt, the
  bytes are kept.
- **Imported media.** Imported history can refer to media that was or was not captured; a missing original shows its
  name and "not archived".
- **Also in scope:** dropping a file onto a room in the room list, pasting an image on a phone, a direct link to each
  file, and showing storage use against a quota.

### 2.5 Calls, voice, video and meetings

- **Calls in any room.** Audio or video calls start from the room header. Other members' clients ring (a toast, a
  tone, a desktop notification) and show a "call in progress, join" banner. Calls offer screen sharing, device
  choice, in-call chat, and grid and focus layouts. A room has at most one open staff call at a time; after a call
  ends, the next one is a new call record.
- **End-to-end encryption by default.** Audio, video and in-call chat are encrypted with a per-call key that only
  admitted participants receive; the media server forwards only ciphertext.
- **Call history and missed calls.** The room records "started a call" and "call ended", with the duration and the
  participants. A missed call is a call in one of my rooms that someone else started, that has ended, that I never
  joined, and that started after I joined the room; it is dated by when it ended. A guest meeting's call is never a
  missed call.
- **Call liveness.** While in a call, a client sends a heartbeat (default every 20 seconds after the previous attempt
  settles, giving up on an attempt after 10 seconds). A call with no heartbeat for a set period (default 75 seconds) is
  closed at its last heartbeat, and the history line is posted. When a heartbeat is refused because the person is no
  longer a member, the room is unavailable, the meeting is closed or the call has ended, the client leaves the call
  and says why; a network error keeps the media running and the client retries.
- **Guest meetings.** A staff member creates a meeting link that is valid for a chosen time, from a few hours up to 30
  days. A guest opens it in any browser, checks their camera and microphone, enters a name, asks to join and waits in
  a lobby. Staff in the room see how many are waiting, get a ring and a notification, and admit, decline or remove
  guests from a lobby panel. The lobby can be turned off for a meeting, with a warning. Cancelling a link turns away
  everyone waiting and has the media server disconnect guests who were admitted.
- **Staff-only meetings.** Scheduled meetings default to a staff audience: only room members can join and there is no
  guest link. A staff meeting never gains guest access, even if settings change later.
- **Calendar.** A work-week agenda of meetings in my rooms. Meetings can be scheduled (title, start, duration,
  agenda), started on the spot, edited or rescheduled with version checks (a stale version is a conflict; a meeting
  that has started or has any call history can no longer change), cancelled, and joined by meeting id. Saving an edit
  that changes nothing records no extra history. Unsaved edits survive a failed save, and a conflict requires an
  explicit reload.
- **Restricted networks.** For networks that allow only TCP port 443, media can go through a TLS-wrapped relay that
  answers only to its own server name.
- **Also in scope:** background blur processed without any outside service; recording and transcription, which ask
  for consent first and, for encrypted calls, need an explicit, visible opt-in for that call; picture-in-picture; a
  call-quality indicator; recurring meetings; calendar file import and export; a month view; a device-check page for
  guests; screen sharing by guests; raising a hand.
- **Out of scope:** telephone dial-in.

### 2.6 Search and history

- **Paging the feed.** A room opens at its newest page (default 50 messages), and earlier pages load on request.
  Opening a room around a given message returns about 25 messages on each side, including that message; a message
  that is not in the room is treated as if none was given. A channel's post list pages through top-level posts only,
  and a reply id anchors on its post. A thread view returns the post and its replies oldest first, up to a cap.
- **Search.** Covers every room I belong to, active and archived together. Opening a result opens the room around it.
- **Imported history.** Conversations imported from another system appear as read-only rooms in an Archive section.
  An import can be run again safely: rooms and messages carry stable external keys, so a second run adds nothing. A
  later run adds only what is new and updates rows the source now knows more about (newly captured media, an edit, a
  deletion), but never drops media an earlier run captured. People who have never signed in are reported and skipped,
  then added to their rooms and linked to the messages they wrote on a later run.
- **Continuing a conversation.** An archived one-to-one conversation between two people who now have accounts can be
  continued as their active direct message. Anything else continues as a new group room with the same people and a
  system line that links back to the archive.
- **Retention.** Indefinite by default; an administrator may configure a retention period that removes old messages.
  Rooms are archived, never deleted. People who leave stay readable: identity records are
  never deleted, and each message keeps a copy of its author's name and email.

### 2.7 Notifications and attention

- **While a client is open.** In the foreground or in a background tab, the client shows a system notification for a
  new message in a room that is not on screen, and rings for calls and lobby knocks. Clicking a notification asks the
  client that is already open to switch room without reloading, so drafts survive; a new window opens only if no
  client is open. A notification never grants access to a room.
- **Activity feed.** Mentions of me, replies to my messages (quotes or thread replies), other people's reactions to my
  messages, and missed calls, only from rooms I currently belong to and never from archived rooms. A reply that also
  mentions me is a single item. Filters: unread, mentions, saved. "Mark seen" clears the badge until something newer
  arrives.
- **Attention in the browser.** A generated chime (no audio file), enabled by a user gesture and offered with a "play
  test sound" button; the unread count in the window title; an app badge for installed web apps; and coordination
  between open tabs so that several tabs produce one chime and one notification.
- **Push while closed.** Standard web push with encrypted payloads and server keys that the server generates itself,
  so no vendor account is needed. Each subscription belongs to a sign-in session, so signing that device out silences
  it. Pushes go only to members who do not currently have the room open. A payload carries ids and a short title and
  body, never text from muted rooms or archived rooms. An endpoint that keeps failing is disabled, not deleted. A "send
  test alert" button proves the path to the current device.
- **Also in scope:** ringing through the phone's own call screen, and native push on phones.

### 2.8 Website and external chat (optional module)

- **Visitor queue.** A durable queue for anonymous website visitors. Duty pools name a primary and a backup responder.
  Admitting a visitor is one atomic step that reserves primary and backup capacity together with the visitor's first
  message, a stable assignment and an alert to send; if that cannot be done, the visitor is offered a way to leave a
  message instead. Acceptance records a fixed time T0, and the database enforces a deadline of T0 plus 30 seconds.
- **Staff visitor page.** A separate staff page shows the queue, a bounded transcript, and claim, reply and close
  actions. Every read and write resolves the person's authority fresh, with no grace period. A reply needs an active
  claim and the current assignment version.
- **Deadline worker.** A background job, run one at a time, records deadline breaches and raises alerts. It never
  reports itself as ready to serve visitors.
- **Enabling the public widget.** The public widget, alert delivery, an administrator's disable-and-drain control and
  rehearsals with real staff come with this module. The widget can be turned on only after every admitted rehearsal
  had a human reply within the deadline.
- **Device conversations (plug-in API).** A third-party agent running on a device can open a support conversation
  through a trusted relay that asserts the device's identity. There is one room per device and operating-system user.
  The OS user name is an unverified label, always shown as "user on host", and never linked automatically to a known
  contact. Staff see an inbox of these conversations and joining one is audited. "Delivered" is shown only once the
  device's read position has passed the message. Updates should arrive within a few seconds while the conversation
  window is open and within about a minute while it is closed.

### 2.9 Mobile

- **Phone layout.** A bottom tab bar, larger touch targets, a composer that stays visible above the keyboard, and no
  horizontal scrolling at narrow widths.
- **Installable web app.** A manifest and service worker so phone and desktop browsers offer to install the web
  client. The service worker never caches conversation pages, messages or files. If a navigation fails and the
  browser reports that it is offline, a generic recovery page with no private content is shown; other network or
  certificate failures show the browser's own error, so an access problem is never mislabelled as being offline.
- **Reconnecting.** Every live request has a deadline (default 20 seconds) that also covers a response body that
  stalls; live updates resume after reconnecting. Web clients have no offline send queue: after a failed send, the
  person reviews the conversation before trying again. *(Implementation status: the shared client core has an outbox
  that retries with backoff; whether native clients keep it, and an idempotency key so a retry cannot post twice, are
  open design points.)*
- **Mobile guidance.** Settings explain, per platform, how to install, grant permissions, update, repair and remove the
  app. Removing the app neither deletes data on the server nor revokes the device's credential.
- **Native app.** A device-held key, camera and microphone permissions limited to the CrewCraft server, a foreground
  service during calls, file picking and downloads, native push, and updates through the platform's app store.

### 2.10 Desktop

- **Desktop client.** Starts with the operating system and lives in the tray. The tray shows live status (connected,
  offline, connecting) and the unread count, and offers open, reload, mute sounds, start with the OS, and quit. When
  the unread count grows while another app has focus, the taskbar entry flashes (or the dock icon bounces) until the
  client is focused. It shows native notifications, presents the device certificate automatically, offers a picker for
  screen sharing, opens a room from a custom-scheme link, and identifies its platform and version to the server.
- **Boundaries.** The client displays only the CrewCraft server and, when one is configured, the identity provider's
  sign-in page; every other link opens in the default browser. Camera, microphone and screen capture are granted to
  the CrewCraft server only. Plain HTTP is refused.
- **Self-update.** Updates come from the client's own server (2.21), behind the same certificate-gated entrance as everything else. The feed
  is a manifest giving each installer's hash, size and whether it needs elevation. Published installers never change;
  the manifest is replaced atomically. The updater refuses downgrades, changed bytes, and installers not signed by the
  expected publisher.
- **Install lifecycle.** Install, in-place upgrade that keeps each user's settings, repair by running the installer
  again, uninstall, and registration in the operating system's list of installed apps.

### 2.11 Administration

- **Capability-gated entry.** Being signed in is not enough: using CrewCraft needs the "use" capability, and
  moderation needs a separate "moderate" capability.
- **Signed-in devices.** Every sign-in is a session with a platform label. Settings lists them and can sign out the
  current device or all others; moderators can revoke sessions.
- **Audited administrator reading.** Administrators can read any room through a separate, clearly named path that
  writes an audit event. Users are told this capability exists; individual reads are not announced.
- **Audit log.** Append-only events for moderator deletions, administrator reads, joins of device conversations,
  meetings created, cancelled or edited, imports, and loading of test data.
- **People before first sign-in.** An administrator can create a person before they first sign in, so others can
  message them straight away; their first real sign-in takes over that record.
- **Health check.** An endpoint that reports a real database round trip, whether an external authorizer (when one is
  configured) can be reached, the access mode, the call entrances, whether guest meetings are on, the encryption mode
  and whether push is configured.
- **Service integrations.** Signed service-to-service routes, used by service accounts and bots, can: make sure a room
  exists for a record in another system, post a notice into a person's own room, and read a room that a person has
  shared with a service.
- **Export.** People and administrators can export conversation data.

### 2.12 User management

- **People.** Administrators create and invite people (SPEC.md section 2), edit their profile fields (name, email, job
  title, department, manager, phone, location, picture), deactivate them and reactivate them. Deactivation signs the
  person out everywhere and revokes their devices at once, and keeps everything they wrote. People are never deleted;
  on a legal request an administrator can erase a deactivated person's profile data, and their messages then show a
  neutral placeholder name.
- **Groups.** Named groups of people, either listed by hand or defined by a rule over profile fields (for example a
  department). Groups can be added to teams, rooms and meetings, mentioned, and targeted by policies.
- **Roles and capabilities.** Built-in roles (owner, administrator, moderator, member, guest) and custom roles made from
  the published capability list, granted for the whole organization, a team or a room. Every change is audited and read
  back before it reports success (principle 4).
- **Policies.** Settings applied to groups or people: messaging (editing and deleting own messages, priority messages),
  meetings (who may create guest links, recording, length), files (quota, sharing outside the organization), guests
  (allowed or not), and retention. The most specific policy wins, and a "why does this person get this" view explains
  the effective value and where it came from.
- **Bulk changes.** People, groups and memberships import from and export to CSV, with a dry-run preview and a result for
  every row. An export imports back unchanged.
- **Security actions.** Reset a password (built-in password source), reset TOTP, revoke a device or a session, issue a
  new enrollment code, and sign a person out everywhere. TOTP reset needs a second administrator's approval. All of these
  are audited.
- **Delegated administration.** Team owners manage their own team's members and guests without organization-wide rights.
- **Provisioning.** An optional SCIM 2.0 endpoint lets an external directory create, update and deactivate people and
  groups. Fields owned by a configured identity provider or authorizer are shown read-only (SPEC.md section 3).
- **Admin console.** Search and filters over people, saved views, and a page per person showing devices, sessions,
  groups, roles, effective policies and their audit trail.

### 2.13 Guest access and invite links

- **Two kinds of guest.** Meeting guests join a meeting from a browser through the lobby without an account (2.5). Chat
  guests hold a guest account and take part in the teams, channels and chats they were invited to.
- **Invite links.** When policy allows, an owner of a team, channel or chat creates an invite link with a scope, an expiry
  (default 7 days, at most 30), a maximum number of uses (default 1), and whether each request needs approval (always for
  a link with more than one use). Links are listed with their use counts, can be revoked at once, and are audited.
- **Joining from a link.** A link opens a page on the public guest entrance, never the staff entrance. The guest gives a
  name and an email address; after approval, if required, the server emails a single-use enrollment code. The guest then
  enrolls a device exactly as staff do, with a guest-scoped certificate and mandatory TOTP. The link itself grants nothing.
- **Guest limits.** Guests see only the rooms they belong to and the people in them. They cannot browse the directory,
  create teams, rooms or invite links, or see anyone else's presence. They show only an external profile, are labelled
  "Guest" wherever their name appears, and a room shows that it contains guests.
- **Guest lifecycle.** Guest accounts end after a period without activity (default 90 days) or when their last room
  removes them; owners and administrators can remove a guest at any time, which revokes the guest's devices at once.

### 2.14 Team files and sharing

- **Libraries.** Every team channel and every chat has a Files tab backed by a shared library, and every person has a
  private library. Libraries hold folders; files can be uploaded (streamed as in 2.4), moved, renamed, copied and deleted
  to a recycle bin (default kept 30 days) from which they can be restored.
- **Versions.** Saving a file creates a version. People can list versions, download one and restore it; how many versions
  are kept is a policy.
- **Permissions.** A channel or chat library is readable by its members. A person's own files stay private until shared.
  Sharing goes to a person, group, room or team with view or edit rights, and never grants more than the sharer has.
- **Share links.** Internal links work for members only. Where policy allows, a link for guests carries an expiry and is
  view-only unless the sharer allows editing or downloading. Links are revocable and audited. A file request link lets a
  guest upload into one folder without seeing it.
- **Preview.** Images, PDF, text and code, audio, video and CrewCraft documents (2.15) open inside the client; everything
  else downloads.
- **Other tools.** Libraries are reachable over WebDAV through the certificate-gated entrance, so the operating system's
  file manager on an enrolled device can open them. A desktop sync folder is also in scope.
- **Storage.** Quotas per person and per team with storage use shown; content-addressed storage as in 2.4; a plug-in
  point for malware scanning that needs no outside service.
- **Search** covers file names and, for formats that carry text, their content.

### 2.15 Collaborative documents

- **Editing together.** Documents are created and edited inside every client (desktop, web, phone). Several people edit
  the same document at once and see each other's cursors and selections.
- **Kinds.** Rich-text documents first (headings, lists, tables, images, links, code, checklists, mentions); then a
  whiteboard; then spreadsheets (cells, formulas, sorting and filtering); then live cards, small shared pieces such as a
  list or a table that stay in sync wherever they are posted in a chat.
- **Offline.** Editing works offline. When the device reconnects its changes merge without conflicts, using conflict-free
  replicated data types; the merge is deterministic and covered by tests.
- **History and comments.** Automatic and named versions, who changed what, and restoring a version. Comment threads are
  anchored to the text, can mention people and can be resolved. A suggestions mode (tracked changes) is also in scope.
- **Access.** Documents are files in a library (2.14), so their permissions, versions, quotas and search follow the
  library. When someone loses access their further changes are refused at once.
- **Import and export.** Markdown, HTML, PDF and plain text first; OpenDocument and Office Open XML formats are also in
  scope.

### 2.16 Calendar

Extends the meeting calendar in 2.5.

- **Calendars.** A personal calendar and a calendar per team or channel, with day, work-week, week, month and agenda
  views, a time zone per event and per person, and working hours.
- **Events.** Online meetings (2.5) with a join button, and plain events; recurring series with exceptions; reminders;
  attachments; categories.
- **Invitations.** Invite people, groups, rooms or outside email addresses. Outside invitees receive a standard
  iCalendar invitation whose join link leads to the guest entrance. Invitees accept, decline, answer tentatively or
  propose a new time, and the organizer sees every answer.
- **Scheduling assistant.** Free and busy times of the invitees, without event details unless shared, and suggested times.
- **Other apps.** A CalDAV server through the certificate-gated entrance for the calendar apps on enrolled devices;
  iCalendar import and export; read-only subscriptions to outside calendar feeds.
- **Presence and absence.** "In a meeting" presence comes from the calendar; out-of-office shows on the person's card and
  answers new chats with the person's message.
- **Bookable rooms and equipment** are also in scope.

### 2.17 Contacts and directory

- **Directory.** Built from the people records (2.12): search by name, title, department and location. A profile card
  shows presence, local time and actions: chat, call, video call, email and schedule a meeting.
- **Org chart** from the manager field.
- **Personal contacts.** People outside the organization (name, email, phone, company, notes), contact lists and
  favourites. From a contact a person can email, schedule, or invite them as a guest (2.13).
- **Team contacts.** A shared address book per team.
- **Other apps.** CardDAV through the certificate-gated entrance; vCard and CSV import and export.
- **Privacy.** Guests see only the people they share rooms with. Each person decides which optional fields, such as a
  phone number, others can see.

### 2.18 Plugins and integrations

- **What plugins add.** Bots, slash commands, message actions, compose actions, tabs in channels and chats, activity
  feed items, incoming webhooks (post into a room) and outgoing webhooks (notify an address), meeting extensions and
  admin-console pages.
- **Sandboxed WebAssembly.** Plugins are WebAssembly modules written in Rust against `crewcraft-plugin-sdk`. The server
  runs them in a sandbox with no ambient access: a plugin declares the capabilities it needs (read messages where it is
  installed, post as its bot, reach a listed outside address, keep its own data) and gets nothing else, with limits on
  CPU, memory and time per call.
- **Declarative client UI.** A plugin describes its UI as data (cards, forms, lists) that each client draws itself, so
  no plugin code runs inside a client.
- **Lifecycle.** Administrators approve plugins for the organization; team owners install approved plugins into their
  teams; the approval screen lists every capability. An update that asks for more capabilities needs approval again.
  Disabling or removing a plugin ends its access at once, and its data can be exported.
- **Trust.** Plugin packages are signed and the server checks the signature and hash. Administrators add catalogs (a
  folder or an address); there is no built-in outside catalog.
- **Bots** are service accounts (section 7): labelled as bots and audited.
- **Stable API.** The plugin API is versioned with compatibility tests; a plugin built for an unsupported version is
  refused, never half-loaded.

### 2.19 Themes and appearance

- **Themes are data.** A theme is a TOML file of design tokens: colours (backgrounds, surfaces, text, strokes, the accent
  and its states, status and presence colours), font family and sizes, density, corner radii and icon set. A theme holds
  no code.
- **Built in:** CrewCraft Light, CrewCraft Dark, High contrast, and following the operating system.
- **Choices.** Each person picks a theme and a density; an administrator sets the organization's default theme, an
  accent colour, and the logo and name in the title bar.
- **Theme addons.** An organization can add its own themes without changing CrewCraft. A theme addon is one theme file
  (crate `crewcraft-theme`): its name, version and author, a light palette, an optional dark palette, type and shape.
  An administrator installs it on the server, from the admin console or by placing the file in the server's themes
  folder, chooses who may use it (everyone or listed groups) and may make it the organization's default. The server
  hands the file to clients over the certificate-gated entrance together with its SHA-256, and a client applies only
  a file whose hash matches. An addon never leaves the server it was installed on, so a theme an organization keeps
  private stays private. Removing an addon moves its users back to the default theme. Previews work before use.
- **Strict format.** Unknown sections or keys, duplicate keys, missing required colours and files over 64 KiB are
  refused with the line number, so a typo is never silently ignored.
- **Accessible by rule.** Every theme passes WCAG 2.2 AA contrast for text (4.5:1) and controls (3:1); the theme
  validator refuses one that does not, and tests draw the main screens in every built-in theme. Presence and status are
  shown by icon shape as well as colour, so a theme's presence colours are not contrast-checked.
- **Appearance only.** Themes never change layout or workflow (2.20), so help and training apply to every theme.

### 2.20 Layout

- **One layout everywhere.** Desktop and web share the layout people know from mainstream team-chat suites; phones adapt
  it.
- **Title bar:** back and forward, a central search box (Ctrl+E), the person's picture with presence and the status menu,
  and settings.
- **App bar** down the left side: Activity, Chat, Teams, Calendar, Calls, Files and Apps, with unread badges. Plugins can
  pin their own entries.
- **List pane** for Activity, Chat and Teams: the room list with filters, sections, pinned rooms and favourites. Calendar,
  Calls and Files use the whole main area instead.
- **Main pane:** a conversation header (name, pictures, tabs such as Chat, Files, Documents and plugin tabs, and the
  audio and video call buttons), the feed (bubbles in chats, posts with threaded replies in channels), and the composer
  with formatting, emoji, attachments and plugin actions.
- **Side pane** for thread replies, details and in-call chat.
- **Calls** fill the main area with a call stage that can pop out into its own window, with grid and focus layouts and a
  control bar.
- **Phones** replace the app bar with a bottom tab bar (2.9) and show one pane at a time with back navigation.
- **Keyboard and accessibility.** Every main action has a keyboard shortcut, listed in a shortcuts dialog, and every
  screen works with a keyboard and a screen reader.

### 2.21 Updates

Updates flow in one direction: the server updates itself from a signed release, and the clients then update from the
server they belong to. Nothing on an end user's device reaches out to the internet for updates.

- **Releases.** A release is a manifest (product, version, channel, release date, the oldest client version the server
  still accepts, and every artifact with its platform, size and SHA-256) signed with the project's release key. The
  server trusts only the public keys in its configuration, refuses an unsigned or wrongly signed manifest, refuses a
  version older than or equal to the one running (no downgrades through the update path), and refuses an artifact
  whose size or hash differs.
- **Server self-update.** The server checks its configured release source on a schedule (default daily) on the chosen
  channel (stable or beta). Depending on the administrator's choice it installs automatically inside a maintenance
  window, waits for an administrator to approve, or stays pinned to a version. It downloads and verifies the release,
  keeps the running version, swaps in the new one, restarts through the operating system's service manager and runs
  its health check. If the health check fails within a set time (default 5 minutes) it switches back to the previous
  version and reports why. Database changes follow principle 15: migrations only add, so the previous version still
  runs after a rollback.
- **The server carries the clients.** Each server release includes the matching desktop installers and the Android
  package. The web client is served by the server, so it is always current: an open page is told a new version is
  ready and reloads when the person agrees, or at once if its version is no longer accepted.
- **Clients update from their server.** A client reports its version and platform when it connects. When the server
  holds a newer client for that platform, the client downloads it through the certificate-gated entrance, checks the
  release signature and the hash, installs it in place keeping the device's identity, settings and credential, and
  restarts. Desktop clients install without asking unless the person is in a call; the Android app installs its update
  with the system's confirmation; store installs (Play, App Store) update through their store, and the server still
  tells them a newer version exists.
- **Required updates.** A client older than the server's oldest accepted version may sign in only to update. It shows
  why and offers the update; nothing else works until it is current.
- **Rollout.** An administrator can release a new client to a pilot group first, then to a percentage of devices, then
  to everyone, can pause a rollout, and can hold back a version that misbehaves. Which devices fall into a percentage
  is decided by a stable hash of the release and the device, so a device does not flip in and out.
- **Visibility.** The admin console shows the server's version, the release it is waiting on and why, the update and
  rollback history, and how many devices run each client version. Every update, approval, pause and rollback is audited.

---

## 3. Domain model

- **Person.** A local record of who someone is, written only by sign-in and enrollment: a stable identity, email,
  display name, an active flag, and when they were last seen. People are never deleted, so former colleagues stay
  readable. A person created before first sign-in holds a placeholder identity until that sign-in claims it. Guests
  are not people in this sense.
- **Person state.** Kept apart from the person record: chosen presence, status message and its expiry, last contact,
  last input, last call heartbeat, when activity was last marked seen, the read-receipt setting, and theme.
- **Profile.** Optional internal and external profiles (see 2.3). Pictures are stored as content-addressed files, not
  inside the database.
- **Room.** A kind (direct, group, linked to an external record, archive, device conversation), an optional name and
  topic, a canonical participant key for rooms that must be found or created without races (direct messages,
  personal rooms, device conversations), an external key for imported rooms, optional external references, an
  optional team, one pinned-message pointer, when and by whom it was archived, and the time and preview of its newest
  message, written in the same transaction as each message so the room list needs one query.
- **Membership.** Links a participant to a room. A participant is a person, an external contact or a device (a device
  reference plus an OS user). A membership has a role (owner or member), muted, hidden and pinned flags, a typing
  time, a read position (time and message id), and joined and left times. Leaving sets a time; the row is not deleted,
  and every membership check ignores memberships that have been left. Membership is what authorizes reading and
  writing messages.
- **Message.** Belongs to a room and has a unique client idempotency key, a kind (message or system), a plain-text
  body, structured details (such as a server-built quote or a call summary), an author kind and author with a copy of
  the author's name and email, a sent time, an optional thread parent with a reply count, edited and redacted markers
  with who did it, and a changed-at time that drives live updates for edits, reactions, pins and redactions.
- **Revision.** An earlier body of an edited message.
- **Reaction, mention, saved item.** Per-person records attached to a message.
- **File.** Uploaded bytes identified by SHA-256, with a name, type, size, optional image dimensions, uploader, room
  and optional message. A file exists without a message between upload and send.
- **Team and team member.** A team owns channels (group rooms); its membership is copied into each channel.
- **Call.** One call in one room or meeting, with its entrance (staff or guest), start and end, last heartbeat, and a
  participant list recorded by the server (person ids for staff, names for guests).
- **Meeting.** Belongs to a room and has an audience (staff or guests), an unguessable code (guest meetings) or a
  reserved code that is never public (staff meetings), an expiry, lobby on or off, an owner, schedule fields, an
  agenda and an edit version.
- **Meeting guest.** Someone who asked to join: display name, state (waiting, admitted, declined, removed), a hash of
  their bearer secret, and network details kept only for investigating abuse.
- **Authorization state.** Per identity: the capabilities last resolved, when, when the last good answer came, a
  revision number and any definitive denial. It lives in the server database, not only in a client token.
- **Session.** One sign-in on one device or browser: platform label, created, last seen, and revoked (with how: by the
  person, everywhere at once, or by a moderator). Revoked sessions stay on record for the audit trail. *(Implementation
  status: the early `accounts` session store deletes revoked rows, and its idle and absolute limits are the web
  session's; the device re-ask period in SPEC section 2 is separate.)*
- **Push subscription.** A push endpoint and keys belonging to a person and a session, with the last success, a failure
  count and a disabled marker.
- **Audit event.** Who, what, a summary, the target's type and id, and when.
- **Visitor objects (optional module).** Duty pool; duty assignment (primary and backup, heartbeats, evidence of
  readiness); visitor conversation (state, T0, deadline, assignment version, hashed visitor credential); visitor
  message; outbox event (stable id, lease, fencing token); record of idempotent operations.
- **How they fit together.** People join rooms through memberships; rooms hold messages, files, calls and meetings;
  messages hold revisions, reactions, mentions, saves and files; teams group channel rooms; meetings admit guests into
  calls; sessions own push subscriptions; authorization state is keyed by identity.

---

## 4. Security and access

**Identity and authorization are separate.** Identity answers "who is this?": CrewCraft's own accounts, or an external
OpenID Connect provider. Authorization answers "what may this person do here?": CrewCraft's built-in roles, or an
external authorizer. When an external authorizer is configured, CrewCraft does not manage roles itself.

**Capabilities.** "Use" (needed for every staff page and API), "moderate" (delete other people's messages and read
revisions, audited), and for the visitor module "respond" and "dispatch". An unknown role gives no capabilities. Having
an identity never grants entry by itself.

**Re-checking an external authorizer.** After a good answer, check again after 10 minutes; after a failed check, retry
after 60 seconds; while the authorizer is unreachable, keep the last good grant for at most 24 hours from when it was
last confirmed. A fresh sign-in needs a fresh positive answer and never uses grace. A definitive denial is stored on the
server, survives restarts and outages, and cannot be undone by presenting an older token. If an authorization decision
cannot be committed durably and read back independently, access is refused. The visitor module allows no grace at all.

**Sign-out is real.** Signing out revokes the session on the server, so a copied cookie or token is refused on its next
use.

**Membership is the only authorization for content.** Every query for messages, files, threads, search results and
activity is limited to the person's current memberships. The only exception is the audited administrator path.

**What an unauthorized caller sees.**
- At the network entrance: staff surfaces require a valid client certificate, and a client without one has its
  connection closed with zero bytes, with no banner, login page or error page.
- In the application: not signed in is 401; signed in but without the capability, not a member, not the author, or a
  cross-origin upload is 403.
- Anything in a room you are not in is 404, never 403, so its existence is not revealed.
- Guests: an unknown guest, the wrong meeting and the wrong secret all give the same 404. On the public guest entrance
  every staff page, staff API, service route, sign-in route and health route is 404; that allowlist is enforced in two
  independent places, and both fail closed when proxy or forwarded-host headers are present.
- Device conversations: a device may read and write only the room that matches both its device and its OS user. If
  the agent cannot work out which OS session is calling, it refuses rather than assume the console user.

**Status codes clients rely on.** 400 malformed; 401 sign in again; 403 not allowed; 404 not there, or not yours; 409
conflict (reload and retry, never resend blindly); 410 gone (call ended, link cancelled); 411 and 413 upload length
missing or too large; 422 well formed, but this room or message does not allow it (retrying will not help); 503 feature
not configured.

**Guest meetings.** A meeting code carries at least about 119 bits of randomness and admits only to the lobby. Each
guest receives a 32-byte bearer secret once, and only a domain-separated hash of it is stored. Only an admitted guest of
an open meeting receives a media credential, scoped to that one meeting, with a guest prefix on their identity and
"(guest)" after their name. A guest learns only the meeting title, the host's first name and their own lobby state.
Names are normalized, stripped of control and bidirectional-override characters so they cannot impersonate anyone, and
must be 1 to 60 characters. Knocking, polling and lookups are rate-limited per IP address, and a meeting has a cap on
waiting guests (default 25). Every lobby decision becomes a system line in the room, and creating or cancelling a
meeting is audited.

**Concurrency.** Changes to room access, joins, heartbeats, grants, guest admission, content writes, uploads and meeting
edits all serialize on a per-room lock taken in one global order: team, then rooms sorted by id, then meeting, then
rows. A leave that commits first wins over a later join or heartbeat; a join that commits first may issue its grant
before a later leave. A late admit cannot bring back a removed guest. No network call is made while these locks are
held.

**Media.** Every call is end-to-end encrypted by default. Call signalling passes the same certificate check as the rest
of the application. Media ports cannot carry a client certificate (browsers do not support it), so media access depends
on credentials issued over the authenticated signalling session, and the media port answers nothing it was not told to
expect. Removing a participant ends their media access at a server-side enforcement point: their media credentials stop
working at removal, and this does not depend on the removed client cooperating.

**Device identity.** Devices are enrolled with a single-use, short-lived code that a person approves; the code itself
is never stored (only a key derived from it, see SECURITY-DESIGN.md) and it carries a check symbol so typing mistakes are caught on the device. It is redeemed for a
certificate on a key generated on the device that cannot be exported. The issuer sets the certificate subject from the
approval record, never from the request. There are no portable certificate files. A device record has one active
certificate at a time, and a renewal gets a new serial number.

**Content safety.** No HTML from users is ever stored or rendered (see the implementation-status note in 2.1). Downloads are sandboxed. Message bodies, file names and visitor
text are untrusted input everywhere they are used.

**Service routes.** Service-to-service calls are POST only and signed with HMAC over the raw body, with a timestamp and
a replay window, compared in constant time. They are never reachable through the public guest entrance, and a route
whose secret is not set answers "not configured". A valid signature never permits reading another person's or device's
room: every call re-checks the room's references.

---

## 5. Clients and protocols

- **One client logic.** Features are written once in shared client logic, and every platform gets them at the same
  time. Each platform adds only what it alone can do: tray, ringing while closed, presenting the device certificate,
  taskbar flashing, a screen-share picker, native push.
- **JSON over HTTPS** for rooms, the feed, sending, message actions, typing, read positions, presence, people,
  activity, teams, calls, meetings, files, search, sessions, push subscriptions and profiles. Request bodies are small
  (default cap 16 KB), except uploads.
- **Live updates on a cursor log.** Every change has a cursor position. A client asks for everything after its last
  cursor and is always brought fully up to date, however long it was disconnected. A live update for an open room
  carries new messages, messages changed since the client's last update (edits, reactions, pins, redactions), who is
  typing, who has read what, and the pinned message; the room list is kept current the same way. Live updates should
  use a held connection, with the cursor log as the source of truth so a dropped connection can always catch up.
- **Calls.** Signalling goes through the same certificate-gated entrance as the application (staff) or through the
  public guest entrance (guests). Media travels over UDP to the media server, with an optional TLS relay on port 443
  for restrictive networks.
- **Push.** Standard web push with encrypted payloads and server-generated keys; native push on phones.
- **Desktop updates.** A static manifest behind the certificate gate, plus installers that never change once published.
- **Device conversations.** A third-party agent reaches CrewCraft through a trusted relay that authenticates the device
  and calls a signed service route.
- **Health.** A JSON endpoint that exercises the dependencies it reports on.

---

## 6. Design principles

1. **Real devices are the final proof.** Passing tests, a passing isolated run and a running server are separate steps,
   and none of them is the last one. A feature that involves people and devices is done when two people on two real
   devices have used it: a real call, a locked phone that rings. Simulations, headless browsers and emulated screen
   sizes help along the way but never stand in for that.
2. **Hold connections; recover from the cursor log.** Live features (typing, read receipts, edits, presence, ringing)
   travel over a held connection. The cursor log is how any client recovers after a gap, so no live feature depends on
   a connection never dropping.
3. **Authorization state lives on the server.** Capabilities, their last confirmation and any denial are stored durably
   on the server and changed under a lock. Sessions are server records, so signing out and revocation take effect
   everywhere. A client token alone is never the source of truth.
4. **Confirm security-relevant writes by reading them back.** A write that grants or removes access, or must happen
   exactly once, is reported as successful only after an independent read shows the committed result. A success code
   from the storage layer is not enough.
5. **Membership boundaries need one lock order.** Leave against join, leave against a finishing upload, cancel against
   admit, edit against delete, pin against reply: these follow one documented lock order, and tests prove the ordering
   by observing a caller actually waiting on the lock, not by sleeping.
6. **Removed means removed in calls.** Media credentials are short-lived, and a server-side enforcement point ends a
   removed participant's access at once, so a credential they kept cannot be reused.
7. **Uploads stream.** An upload is written to disk while it is hashed, nothing holds the whole body in memory, and
   every refusal happens before the body is read. *(Implementation status: the early `server-core` chunk assembler
   keeps chunks in memory and caps the chunk count; streaming to disk arrives before uploads are reachable over the
   network.)*
8. **Plan for known people who have never signed in.** Imported history and invitations refer to people before their
   first sign-in. Adding them to rooms and linking them to what they wrote is repeatable and idempotent, and a person
   can exist before they first sign in.
9. **Device trust must be simple to use on every platform.** Phones and desktops get a supported path: a key that
   cannot leave the device, a person-approved one-time code, clear permission prompts, and updates that keep the
   device's identity. Work on device trust for phones starts early rather than being left until the end.
10. **Kinds are extensible.** Room kinds, guest states and similar values can grow without a disruptive database
    change; the server validates them.
11. **Builds are reproducible.** A build works offline from the repository and its locked dependencies. Generated code,
    if any, is reproducible and checked, never a hidden step that can drift.
12. **The public guest entrance has two gates.** The network entrance and the application each enforce the guest
    allowlist on their own, and both fail closed on forwarded-host headers.
13. **Never overstate.** "Delivered" only once the recipient's read position has passed the message; file counts are
    "rows loaded"; missing archived files say "not archived" rather than looking broken; "no match" never means "does
    not exist".
14. **A promise of a human reply is kept by people, not software.** The visitor module admits a visitor only when
    staffed capacity has been confirmed, fixes the deadline at acceptance, never lets typing indicators, claims, canned
    messages or automated replies count as a reply, and stops admitting visitors when a deadline is missed. This is a
    product principle, not a setting.
15. **Version changes never weaken security.** Database migrations only add. The server refuses to run against a schema
    newer than it understands or older than it requires.
16. **One current state.** Documentation keeps one clear pointer to what is current; history moves out of the way
    rather than piling up at the top of files.

---

## 7. Integration points

CrewCraft runs on its own with no outside services. Each of these lets an organization connect what it already has.

| Integration point | What it is |
|---|---|
| Identity provider | A standard OpenID Connect relying party: issuer discovery, authorization code with PKCE, state and nonce, ID-token signature checks, configurable claim mapping. Built-in accounts are the default. |
| Authorizer | An interface that takes an identity and returns capabilities, a revision and caching hints. A built-in authorizer (administrator, moderator and member roles) and an HTTP authorizer for an external service. The contract: [AUTHORIZER.md](AUTHORIZER.md). |
| Device trust | Client-certificate checks at the server, and a device-enrollment provider that turns a one-time code into a certificate on a device-held key. |
| Importer | An interface that reads an export from another chat system and produces rooms, messages and media with stable external keys, repeatable top-ups, deferred author linking and remapping of email domains. |
| External records | Opaque references on rooms, plus a signed API to make sure a room exists for a record and to post a notice into it. |
| Service accounts and bots | Signed service routes with service authors, for reading a room a person has shared and posting into it. |
| Device conversations | An API for third-party agents: device identity asserted by a trusted relay, one room per device and OS user, a staff inbox. |
| Personal room templates | Per-person default rooms defined by configuration. |
| Push | Standard web push with no vendor account, and optional relays for native phone apps. |
| Appearance | Themes as token files with light, dark, high-contrast and system variants, plus installable theme packages (2.19). |
| Plugins | Sandboxed WebAssembly plugins written in Rust against `crewcraft-plugin-sdk` (2.18). |
| Open standards | WebDAV (files), CalDAV and iCalendar (calendars), CardDAV and vCard (contacts), SCIM 2.0 (provisioning), all behind the certificate-gated entrance. |
| Media store | A pluggable, content-addressed store for files (local filesystem or object storage). |
