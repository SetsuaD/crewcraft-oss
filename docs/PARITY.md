# Feature parity with Microsoft Teams

CrewCraft aims to do what people use Microsoft Teams for, so that a team can move over without relearning its daily
work. Parity means the same jobs done the same way: the same layout and workflow (REQUIREMENTS 2.20), not the same name,
icons or colours, and nothing copied. Microsoft and Microsoft Teams are trademarks of Microsoft Corporation, named here
only to describe the comparison.

`Status`: `done` (behaviour proven by tests and, where people and devices are involved, on real devices), `partial`
(some behaviour exists in the server core), `planned`, or `non-goal` (with the reason). A row is only `done` when its
REQUIREMENTS section is fully met.

| Area | What people do | CrewCraft | Milestone | Status |
|---|---|---|---|---|
| Chat | One-to-one and group chats, formatting, emoji, reactions, replies, edit and delete, pin | 2.1, 2.2 | M1, M3 | partial |
| Chat | Mentions of people, teams, channels and groups | 2.1, 2.12 | M1, M4 | partial |
| Chat | Priority and urgent messages, scheduled send, read receipts | 2.1, 2.3 | M3 | partial |
| Chat | Forward, share to another chat, save for later | 2.1 | M3 | planned |
| Teams | Teams with owners and members, standard and private channels, General channel | 2.2 | M1, M3 | partial |
| Teams | Posts with threaded replies, announcements, channel moderation | 2.2, 2.11 | M3 | partial |
| Teams | Team templates, archive and restore a team | 2.2 | M4 | planned |
| Teams | Channel and chat tabs (files, documents, plugins) | 2.20, 2.18 | M3, M11 | planned |
| Teams | Shared channels with another organization | n/a | later | planned (federation, after 1.0) |
| Activity | Activity feed with mentions, replies, reactions, missed calls | 2.7 | M3 | partial |
| Search | Messages, people, files; filters; jump to message | 2.6 | M1, M3 | partial |
| Presence | Automatic and chosen presence, status message, out of office | 2.3, 2.16 | M1, M9 | partial |
| Calls | Audio and video calls in any chat, screen sharing, device choice | 2.5 | M7 | planned |
| Calls | Call history, missed calls, call from the directory | 2.5, 2.17 | M7, M9 | partial |
| Meetings | Scheduled and instant meetings with chat, lobby, raise hand, reactions | 2.5 | M7 | planned |
| Meetings | Grid and focus layouts, pop-out windows, background blur | 2.5, 2.20 | M7 | planned |
| Meetings | Recording and transcription with consent, live captions | 2.5 | M12 | planned (local processing only) |
| Meetings | Breakout rooms, polls, meeting notes | 2.5, 2.15 | M12 | planned |
| Meetings | Webinars and town halls (large audiences, presenters, Q and A) | 2.5 | M12 | planned |
| Meetings | Guests join from a browser without an account | 2.5, 2.13 | M7 | planned |
| Guests | Guests added to teams and chats by invitation, clearly labelled, limited | 2.13 | M7 | planned |
| Files | Channel and chat files, personal files, folders, versions, recycle bin | 2.4, 2.14 | M8 | partial |
| Files | Share links with permissions and expiry, file requests | 2.14 | M8 | planned |
| Files | Open files from the OS file manager, sync folder | 2.14 | M8 | planned |
| Documents | Edit documents together in the app, comments, history | 2.15 | M10 | planned |
| Documents | Whiteboard | 2.15 | M12 | planned |
| Documents | Spreadsheets | 2.15 | M12 | planned |
| Documents | Live cards that stay in sync inside chat messages | 2.15 | M12 | planned |
| Documents | Office file formats (.docx, .xlsx) | 2.15 | M12 | planned (import and export) |
| Calendar | Personal and team calendars, day, week and month views, time zones | 2.16 | M9 | partial (work-week agenda in 2.5) |
| Calendar | Invitations with RSVP, recurring meetings, scheduling assistant, room booking | 2.16 | M9 | planned |
| Calendar | Calendar apps on the device (CalDAV), .ics import, export and subscriptions | 2.16 | M9 | planned |
| Contacts | Organization directory, profile cards, org chart | 2.17 | M9 | planned |
| Contacts | Personal and team contacts, CardDAV, vCard and CSV | 2.17 | M9 | planned |
| Admin | Users, groups, roles, bulk import and export, deactivation | 2.12 | M4 | partial |
| Admin | Policies for messaging, meetings, files, guests and retention | 2.12 | M4 | planned |
| Admin | Audit log, retention, export, signed-in devices | 2.11 | M1, M4 | partial |
| Admin | Directory provisioning (SCIM), single sign-on (OpenID Connect) | 2.12, 7 | M4 | planned |
| Apps | Bots, slash commands, message actions, tabs, webhooks | 2.18 | M11 | planned |
| Apps | Approve, install and manage apps per organization and team | 2.18 | M11 | planned |
| Look | Themes (light, dark, high contrast), density, organization accent and logo | 2.19 | M3, M11 | planned |
| Clients | Desktop (Windows, macOS, Linux), web, Android, iOS with notifications | 2.9, 2.10 | M3 to M6 | planned |
| Phone system | Calling ordinary phone numbers, dial-in | n/a | n/a | non-goal (needs a telephone carrier) |
| AI assistant | Built-in AI summaries and drafting | 2.18 | n/a | non-goal in the core; a plugin may add one |
| Workforce apps | Shifts, walkie-talkie, approvals, tasks boards | 2.18 | n/a | non-goal in the core; plugins |
| Office suite | Deep integration with one vendor's office cloud | n/a | n/a | non-goal; open standards (WebDAV, CalDAV, CardDAV, iCalendar, vCard) instead |
