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

The reader never talks to Microsoft: fetching an export is the administrator's job, with their own tenant's tools.

## The app (T350d)

An **Archive** section under the room list, for the archive rooms a person is in. An archive room shows its
messages with their original authors and times, reads "Archive: read only" where the composer would be, and offers
Save on captured files and "not archived" on the rest. Search results from archive rooms are marked.

## Later

- Continuing a conversation (REQUIREMENTS 2.1): an archived one-to-one conversation between two people who now have
  accounts continues as their direct message; anything else as a new group room linking back to the archive.
- More readers (Slack, Mattermost, plain mailbox exports), each its own task, each only producing bundles.
