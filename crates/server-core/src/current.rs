//! Atomic bounded capture of the current room window after a missing event interval (T345, docs/GAP-REPLAY.md).
//! Called under the normal room-state lock. Encoded pages are returned only after the entire capture fits its
//! budgets, so a refusal cannot leave a partially acknowledged snapshot on the wire. No cache or journal change.

use crewcraft_proto::current::{
    CurrentPage, CurrentRecord, MAX_CURRENT_BYTES, MAX_CURRENT_MESSAGES, MAX_CURRENT_PAGE_RECORDS, MAX_CURRENT_RECORDS, encode_page,
};
use crewcraft_proto::frame::encode;
use crewcraft_proto::push::{MAX_ATTACHMENT_NAME, MAX_ATTACHMENTS, MAX_HTML};
use crewcraft_proto::request::MAX_AUTHOR;

use crate::durable::{DurableError, DurableServer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentError {
    /// Missing and inaccessible rooms are indistinguishable.
    NoSuchRoom,
    /// The server has no complete durable projection.
    Unavailable,
    /// A record or the complete encoded reply exceeds the recovery bounds.
    TooLarge,
    Storage(DurableError),
}

impl DurableServer {
    /// Capture up to fifty newest live messages. The bytes contain only framed follow pages, not the Ok reply.
    pub fn current(&self, slug: &str, user: &str, id: u32) -> Result<(u64, Vec<u8>), CurrentError> {
        self.check_alive().map_err(CurrentError::Storage)?;
        let room = self.server.room(slug).map_err(|_| CurrentError::NoSuchRoom)?;
        if room.role(user).is_none() {
            return Err(CurrentError::NoSuchRoom);
        }
        let messages = self.previews.get(slug);
        let older = messages.is_some_and(|messages| messages.len() > MAX_CURRENT_MESSAGES);
        let mut selected: Vec<_> = messages.into_iter().flat_map(|messages| messages.iter().rev()).take(MAX_CURRENT_MESSAGES).collect();
        selected.reverse();
        let mut capture = Capture::new(slug, room.head(), older, room.is_read_only(), id);
        for (&cursor, message) in selected {
            // Field bounds are checked before cloning a body or an actor from the persistent projection.
            capture.check_record()?;
            if message.author.is_empty() || message.author.len() > MAX_AUTHOR || message.html.len() > MAX_HTML {
                return Err(CurrentError::TooLarge);
            }
            capture.push(CurrentRecord::Message {
                cursor,
                author: message.author.clone(),
                html: message.html.clone(),
                edited: message.edited,
                parent: self.parent_of(slug, cursor),
                sent_ms: self.imported_sent_ms(slug, cursor),
            })?;
            // Normal stored filenames are validated at acceptance. Imported names are checked before the bounded
            // existing attachment accessor clones them, including entries whose bytes were not archived.
            if self
                .imported_files(slug, cursor)
                .is_some_and(|files| files.iter().take(MAX_ATTACHMENTS).any(|file| file.name.is_empty() || file.name.len() > MAX_ATTACHMENT_NAME))
            {
                return Err(CurrentError::TooLarge);
            }
            for (index, file) in self.attachments(slug, cursor).into_iter().enumerate() {
                capture.check_record()?;
                capture.push(CurrentRecord::File { cursor, index: u8::try_from(index).map_err(|_| CurrentError::TooLarge)?, file })?;
            }
            for (reaction, author) in room.reaction_edges(cursor) {
                capture.check_record()?;
                if author.is_empty() || author.len() > MAX_AUTHOR {
                    return Err(CurrentError::TooLarge);
                }
                capture.push(CurrentRecord::Reaction { cursor, reaction, author: author.to_owned() })?;
            }
        }
        Ok((room.head(), capture.finish()?))
    }
}

struct Capture {
    page: CurrentPage,
    id: u32,
    count: usize,
    frames: Vec<u8>,
}

impl Capture {
    fn new(room: &str, head: u64, older: bool, archived: bool, id: u32) -> Self {
        Self {
            page: CurrentPage { room: room.to_owned(), head, index: 0, last: false, older, archived, records: Vec::new() },
            id,
            count: 0,
            frames: Vec::new(),
        }
    }

    fn check_record(&self) -> Result<(), CurrentError> {
        if self.count >= MAX_CURRENT_RECORDS { Err(CurrentError::TooLarge) } else { Ok(()) }
    }

    fn push(&mut self, record: CurrentRecord) -> Result<(), CurrentError> {
        self.check_record()?;
        if self.page.records.len() == MAX_CURRENT_PAGE_RECORDS {
            self.flush(false)?;
        }
        self.page.records.push(record);
        self.count += 1;
        Ok(())
    }

    fn flush(&mut self, last: bool) -> Result<(), CurrentError> {
        self.page.last = last;
        let bytes = encode_page(self.id, &self.page).map_err(|_| CurrentError::TooLarge)?;
        let framed = encode(&bytes).map_err(|_| CurrentError::TooLarge)?;
        if framed.len() > MAX_CURRENT_BYTES.saturating_sub(self.frames.len()) {
            return Err(CurrentError::TooLarge);
        }
        self.frames.extend_from_slice(&framed);
        self.page.records.clear();
        self.page.index = self.page.index.checked_add(1).ok_or(CurrentError::TooLarge)?;
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, CurrentError> {
        self.flush(true)?;
        Ok(self.frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Connection;
    use crate::durable::CurrentMessage;
    use crewcraft_proto::frame::Decoder;
    use crewcraft_proto::request::{FEATURE_GAP_REPLAY, Request, Response, decode_response, encode_request};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestJournal(std::path::PathBuf);

    impl TestJournal {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("t345-unit-{}-{}.journal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
        }
    }

    impl Drop for TestJournal {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn both_record_and_encoded_byte_budgets_stop_a_large_reactor_stream() -> Result<(), CurrentError> {
        for author_length in [16, MAX_AUTHOR] {
            let mut capture = Capture::new("room", 1, false, false, 1);
            capture.push(CurrentRecord::Message {
                cursor: 1,
                author: "writer".into(),
                html: String::new(),
                edited: false,
                parent: None,
                sent_ms: None,
            })?;
            let mut refused_at = None;
            for index in 0..=MAX_CURRENT_RECORDS {
                let author = format!("{index:05}{}", "x".repeat(author_length - 5));
                if capture.push(CurrentRecord::Reaction { cursor: 1, reaction: 1, author }) == Err(CurrentError::TooLarge) {
                    refused_at = Some(index);
                    break;
                }
            }
            assert!(capture.frames.len() <= MAX_CURRENT_BYTES);
            assert!(refused_at.is_some_and(|at| if author_length == MAX_AUTHOR {
                at < MAX_CURRENT_RECORDS - 1
            } else {
                at == MAX_CURRENT_RECORDS - 1
            }));
        }
        Ok(())
    }

    #[test]
    fn oversized_capture_refuses_before_acknowledgement_or_pages_and_hides_membership() -> Result<(), CurrentError> {
        let journal = TestJournal::new();
        let mut server = DurableServer::open(&journal.0).map_err(CurrentError::Storage)?;
        let room = server.create_room("owner", "Room").map_err(CurrentError::Storage)?;
        let message = server.post(&room, "owner", "body", 0).map_err(CurrentError::Storage)?;
        server.previews.insert(
            room.clone(),
            BTreeMap::from([(message, CurrentMessage { author: "owner".into(), html: "x".repeat(MAX_HTML + 1), edited: false })]),
        );
        assert_eq!(server.current(&room, "stranger", 1), Err(CurrentError::NoSuchRoom));
        assert_eq!(server.current("absent", "stranger", 1), Err(CurrentError::NoSuchRoom));
        let request = encode_request(5, &Request::Current { room }).map_err(|_| CurrentError::TooLarge)?;
        let bytes = encode(&request).map_err(|_| CurrentError::TooLarge)?;
        let output =
            Connection::with_features("owner", FEATURE_GAP_REPLAY).receive_durable(&mut server, &bytes, 0).map_err(|_| CurrentError::TooLarge)?;
        let mut decoder = Decoder::new();
        decoder.push(&output);
        let answer = decoder.next_frame().map_err(|_| CurrentError::TooLarge)?.ok_or(CurrentError::TooLarge)?;
        assert_eq!(decode_response(&answer), Ok((5, Response::Error { code: crate::dispatch::E_OTHER, detail: String::new() })));
        assert!(decoder.next_frame().map_err(|_| CurrentError::TooLarge)?.is_none());
        Ok(())
    }
}
