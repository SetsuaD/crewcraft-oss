# Importing history (design, task T350)

REQUIREMENTS.md says what an import must do (section 2.1 "Imported history" and "Read-only rooms", 2.4 "Imported
media", the Importer integration point, and lesson 8, people who have never signed in). This is the plan for building
it on what exists: the room journal, the content-addressed file store (FILES.md) and the administrator's command line.
Each part below lands as its own test-defined task.

The design splits an import in two. A **reader** turns one system's export into a neutral **bundle**; the server
**imports a bundle**. Only readers know any other system's format, so a new source needs a new reader and nothing
else, and the server's rules (keys, re-runs, read-only rooms) are written and tested once.

## The bundle (T350b)

A bundle is a directory:

- `bundle.json`: one JSON object, read with unknown fields refused (strict, like every CrewCraft file):
  - `format`: `"crewcraft-import/1"`.
  - `source`: a short name for the system it came from (`"teams"`, `"test"`), 1 to 32 lowercase letters, digits or
    hyphens. Every external key below is scoped by it, so two sources never collide.
  - `rooms`: a list of `{ key, kind, name, members }`. `key` is the source's stable id for the conversation (1 to 200
    bytes). `kind` is `"direct"`, `"group"` or `"channel"`. `name` may be empty for a direct conversation. `members`
    is a list of email addresses.
  - `messages`: a list of `{ room, key, author, sent_ms, text, reply_to, edited_ms, deleted, files }`. `room` is a
    room's `key`; `key` is the message's stable id; `author` an email address; `sent_ms` the original time (Unix
    milliseconds); `text` plain text up to the usual 4,000 characters (a reader turns rich text into plain text);
    `reply_to` an optional message `key` in the same room; `edited_ms` optional; `deleted` true for a message the
    source deleted (it is kept as redacted, with no text); `files` a list of `{ name, size, sha256, path }`, where
    `path` is optional: a file the export captured lives at `files/<path>` inside the bundle, and one it did not
    capture has no path.
- `files/`: the captured media, if any.

The bundle is the contract between a reader and the server. It is plain, inspectable and editable by hand (workspace
rule 22: a person can check or fix an import without a model), and a test fixture is just a small directory.

## Importing a bundle (engine T350a, command T350b, media T350e)

The engine (T350a) lives in `server-core` and works on the bundle as typed values; the command (T350b) reads
`bundle.json`, runs the engine and writes the report. Files are T350e: until then a bundle's files are counted in
the report and not imported.

`crewcraft-server import --data <dir> --bundle <dir> [--map-domain old.example=new.example]... [--dry-run]` runs on
the server host as the administrator, with the server stopped or through the same journal lock it uses (one writer).

- Each bundle room becomes (or, on a re-run, is found as) an **archive room**: kind archive, the bundle's name (a
  direct conversation is named after its two people), and an external key `source:key`. Archive rooms are read-only
  from the moment they exist: posting, editing, deleting, reacting, replying and uploading are all refused
  (`E_NOT_ALLOWED`). Search covers them; unread counts do not.
- Each message becomes a message in its room with its original author, time and text, and an external key
  `source:room:key`. The author need not have an account: the message keeps the author's email address, and the
  app shows the address until that person has signed in.
- Members who already have accounts are added to the room. Members who do not are **reported and skipped**; a later
  run adds them once they have accounts (lesson 8).
- `reply_to` makes the message a reply in its parent's thread (T340), when the parent is a top-level message of the
  same room; otherwise the message is imported as top-level, and the report says so.
- Files: a captured file is stored in the file store exactly as an upload is (hashed and checked against `sha256`
  and `size`; identical bytes stored once) and attached to its message. A file the export did not capture is recorded
  by name and size only, and the app shows its name and "not archived".
- `--map-domain` rewrites the domain of every email address (members and authors) before anything else, for an
  organisation that moved domains.

**Re-runs are safe.** Rooms and messages are found by their external keys, so a second run of the same bundle adds
nothing. A later, larger export adds what is new and updates what the source now knows more about: an edit (the
text changes, the message is marked edited), a deletion (the message is redacted), and newly captured media (a file
that was "not archived" gets its bytes). A run never drops media an earlier run captured, and never un-deletes.

All of it is written to the journal as import records (`Op::ImportRoom`, `Op::ImportMessage`, `Op::ImportFile`), each
carrying its external key, so a restart replays an import exactly as any other change, and the import's own
bookkeeping (key to room, key to cursor) is rebuilt from them.

**The report.** Every run, dry or not, prints and writes `import-report.json` next to the bundle: rooms created and
found, messages added, updated and unchanged, files stored and not archived, people skipped (by room), replies made
top-level, and every refusal with its bundle position. It exits non-zero when anything was refused (workspace rule
29(ii)), and a dry run changes nothing.

## Reading a Teams export (T350c)

A reader, `crewcraft-server import-teams --export <dir> --out <new-bundle-dir>` (`import_teams.rs`), built only from
Microsoft's public Graph API documentation of `chatMessage`, `chat`, `channel`, `conversationMember` and `user`. Its
input is what the documented Graph calls return, saved as JSON:

- `users.json`: `GET /users` pages, mapping each user `id` to its `mail` (or `userPrincipalName`). A message names its
  sender by id and display name, not by email.
- `conversations/*.json`, one file per conversation: `{"chat": chat}` or `{"team": team, "channel": channel}`, with
  `"members"` (conversationMember list) and `"pages"` (the conversation's `{"value": [chatMessage, ...]}` pages; a
  channel message's expanded `replies` are read too).
- `files/<message id>/<attachment name>`: an attachment's bytes, when the export captured them.

It maps:

- `id` to the message key, `replyToId` to `reply_to`, `createdDateTime` to `sent_ms`, `lastModifiedDateTime` to
  `edited_ms` when it differs, `deletedDateTime` to `deleted`;
- `from.user.id` through `users.json` to `author`; senders it cannot map are reported, their messages left out, and the
  command exits non-zero after writing the bundle;
- `body` to `text`, turning HTML into plain text (paragraphs, line breaks and list items kept; everything else
  dropped);
- `attachments` to `files`, marked captured only when the export folder holds the bytes;
- system and event messages (`messageType` other than `message`) are left out and counted in the report.

The reader never talks to Microsoft. The export it reads can be saved by any tool that calls the documented Graph
API, or by CrewCraft's own exporter below.

## Exporting from Teams (T351)

`crewcraft-server export-teams` (`export_teams.rs`) lets a person export **their own** Teams history through
Microsoft Graph v1.0 into exactly the layout above, so `import-teams` and then `import` take it as it is. It is built
only from Microsoft's public documentation: the OAuth 2.0 device authorization grant (RFC 8628) on the Microsoft
identity platform, and the Graph `chat`, `team`, `channel`, `conversationMember`, `user`, `chatMessage`,
`chatMessageHostedContent`, `shares` and `driveItem` resources. It runs on any computer with a browser nearby; it does
not need the CrewCraft server.

**Before you start: an app registration.** In your organization's Microsoft Entra admin center, register an
application (or ask an administrator to): a public client with "Allow public client flows" turned on, and these
**delegated, read-only** Microsoft Graph permissions:

| Permission | Why |
|---|---|
| `offline_access` | Renew the sign-in during a long export without asking again. |
| `User.ReadBasic.All` | People's addresses (`GET /users`), so a message's sender becomes an email address. |
| `Chat.Read` | Your chats, their members and messages, and images pasted into them. |
| `Files.Read.All` | Files shared in chats and channels (they live in OneDrive and SharePoint). |
| `Team.ReadBasic.All` | The teams you are in. |
| `Channel.ReadBasic.All` | Their channels. |
| `ChannelMember.Read.All` | A channel's members. |
| `ChannelMessage.Read.All` | A channel's messages and replies. |

The last two usually need an administrator's consent. Without it, `--chats-only` exports chats alone and asks for
only the first four. Nothing here can change anything in Teams: there is no write permission in the list.

**Running it.**

```text
crewcraft-server export-teams --tenant <tenant id or domain> --client-id <application id> --out <export directory>
    [--chats-only] [--max-file-mb <n>] [--login-url <url>] [--graph-url <url>] [--ca-file <pem>]
```

It prints an address and a code: open the address in any browser, enter the code and sign in as yourself. The token
stays in the exporter's memory, is never written or printed, and is sent only to the Graph address; it is cleared
when the export ends. Then the exporter:

- lists your chats (`/me/chats`) and, unless `--chats-only`, the channels of every team you are in
  (`/me/joinedTeams`, `/teams/{id}/channels`), and for each conversation its members and all its messages, following
  `@odata.nextLink` page by page (and a channel message's `replies` past their own next link). A next page that points
  anywhere but the Graph address is refused, so the token never leaves it;
- waits when Graph says to: a 429, 503 or 504 is tried again after its `Retry-After` (at most five minutes), or after
  1, 2, 4... seconds without one, at most six times before it stops with an error;
- downloads each named attachment to `files/<message id>/<name>`: a shared file through `/shares/{id}/driveItem` and
  the short-lived download address Graph gives for it (the token is not sent there), a file Graph hosts from Graph.
  A file over the cap (`--max-file-mb`, default 100), a name that is not a safe file name on every system (`:`, `?`,
  `*` and the like, device names such as `CON`), or something that is not a file is left out and listed; the import
  shows it as "not archived";
- writes each conversation's file only after its attachments, and every file through a temporary name, so whatever
  is in the directory is complete; and writes `users.json` from `GET /users` plus one page of conversation members that
  list does not name (guests from other organizations).

A conversation Graph refuses (403 or 404) and an attachment whose download fails are listed, the rest is exported, and
the command exits non-zero. **Running the same command again resumes**: conversations already written are not fetched
again and only missing attachments are downloaded, so an interrupted or partly refused export is finished by running
it again. To pick up messages sent since, export into a new directory and import that too: imports are safe to repeat
and add only what is new.

Then, as above: `crewcraft-server import-teams --export <export directory> --out <new bundle directory>`, and
`crewcraft-server import`. A sender `users.json` cannot name (an account deleted since) makes `import-teams` stop and
say so; add that id with its address to `users.json` by hand and run it again.

Not exported yet: images and files referenced only inside a message's text and not listed among its attachments,
reactions, and meeting recordings and transcripts.

**Help wanted: live verification.** The exporter is tested against a mock of the identity platform and Graph built
from the documentation (`tasks/T351-teams-export/test.rs`); it has not yet been run against a real tenant by the
project. If you run it on your own organization's Teams, please report (without ids, names or addresses) whether
sign-in, paging, channel replies, shared files and pasted images exported, what permissions your administrator had to
consent to, and any Graph error you saw. Open an issue named `T351 live verification`.

## The app (T350d)

An **Archive** section under the room list, for the archive rooms a person is in. An archive room shows its
messages with their original authors and times, reads "Archive: read only" where the composer would be, and offers
Save on captured files and "not archived" on the rest. Search results from archive rooms are marked.

## Continuing a conversation (T352)

An archive room offers **Continue this conversation** (REQUIREMENTS "Continuing a conversation"; `Request::Continue`,
announced by `FEATURE_CONTINUE`; `crates/server-core/src/continuation.rs`).

- Only someone who can read the archive (one of its members) may continue it. The archive's **linked people** are its
  members: an import adds only people who have accounts, and a later run adds the rest once they do, so an author
  without an account is never added anywhere.
- An archived one-to-one conversation (the import notes the bundle's `"direct"` kind in the journal) whose two people
  are both linked continues in **their direct message**: the one they already have while both are still in it, or a
  new one. There is never a second one, even when another archive between the same two people is continued too.
- Anything else continues in **one new group room** with exactly the linked people. Someone linked later (by a later,
  larger import) who continues it is added to that same room.
- The room gets one line, built by the server, that links back to each archive it continues; the app shows it between
  the messages with **Open the archive**. The archive itself stays read-only.
- Continuing again answers the same room and changes nothing. Each change is a journal record, so a restart rebuilds
  it.

## Later

- More readers (Slack, Mattermost, plain mailbox exports), each its own task, each only producing bundles.
