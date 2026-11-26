# Files and attachments (design, task T330)

REQUIREMENTS.md section 2.4 says what files must do. This is the plan for building it on what exists: the
mutual-TLS device connection (every byte of a file travels inside a signed-in session, so the device rule of
SECURITY-DESIGN.md applies unchanged), the room journal, and the chunk reassembly of `server-core::upload` (T107).
Each part below lands as its own test-defined task.

## Storage (T330a)

- Bytes live in the server's data directory under `files/`, named by the lowercase hex SHA-256 of their content
  (`files/ab/abcd...`, two-character fan-out). Identical content is stored once.
- An upload in progress is a file under `files/partial/`, named by a random id, owner-only like the rest of the data
  directory. It is never served.
- Finishing an upload: hash the partial file, check the hash the client declared, `fsync` it, then rename it to its
  content name (or delete it when that name already exists: same bytes). Only after the rename is the file record
  written to the journal. A crash before the record leaves bytes nothing refers to; they are removed at start-up,
  unless any record refers to their hash (when in doubt, the bytes are kept).
- A file record (`Op::FileStored`, in the room journal so membership and redaction rules apply to it in order):
  room, uploader, file id (a random 128-bit id, so two uploads of the same bytes are two files), content hash, size,
  name (1 to 255 bytes, no path separators or control characters), and the image's width and height when the bytes
  start with a PNG, JPEG, GIF or WebP header. No type is trusted from the client.
- Limits: one file up to 100 MB (configurable); at most 64 uploads in progress per server and 4 per person. A
  per-person quota comes with the administration work (REQUIREMENTS 2.11).

## Upload over the device connection (T330b)

New requests, behind a handshake feature bit (`FEATURE_FILES`), each answered like the others:

1. `UploadBegin { room, name, size, sha256 }`: refused before any byte is sent when the person is not a member, the
   room is read-only, `size` is 0 or over the limit, or the limits of uploads in progress are reached. `Ok` carries
   the upload id.
2. `UploadChunk { upload, offset, bytes }`: 1 byte to 256 KiB, in order or not, each chunk checked against the
   declared size (the T107 rules: a repeated chunk with other bytes is a conflict). Chunks are written to the partial
   file as they arrive, never held whole in memory.
3. `UploadFinish { upload }`: the hash and size are checked, membership and room state are checked **again**, and only
   then is the record written. `Ok` carries the file id.

An upload not finished within 10 minutes of its last chunk, or whose connection closes, is discarded.

## Attaching (T330c)

`Post` gains an optional list of up to 10 file ids. Each must be the poster's own upload in that room and not yet
attached to anything; otherwise the post is refused (`E_BAD_ATTACHMENT`) and nothing is posted. The message's event
carries the attachments (file id, name, size, image size), and so does its push, so clients draw them with the
message. A body may be empty only when files are attached. Redacting a message detaches its files: they are then not
found.

## Download (T330d)

`Download { file, offset, length }` (up to 256 KiB per request) answers with the bytes. Membership in the file's
room is checked on every request, and a file on a redacted message, or in a room the person has left, is not found.
The client writes what it downloads to a file the person chose, or, for an inline image preview, keeps it in memory
up to a size cap; nothing a server sends is ever opened or run by CrewCraft.

## The app (T330e)

An attach button and dropping a file onto the composer (desktop), the file chips on a message (name, size; an
image's preview), and Save. Uploads show progress and can be cancelled.

## Later

The file browser across rooms (REQUIREMENTS 2.4), quotas and storage use, team files (2.14), and imported media
("not archived" for missing originals) follow once the parts above are in.
