//! Message search across the rooms a user can see: one `search::Index` (T112) per room, kept up to date from that
//! room's events (`room_service::Event`, T120) and queried only for rooms the asking user is a member of. Composed from
//! `search`, `html_text` (T141) and `server` (T122). Task T142.

use std::collections::HashMap;

use crate::html_text::html_text;
use crate::room_service::{Event, EventKind};
use crate::search::Index;
use crate::server::Server;

/// One search result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub slug: String,
    pub cursor: u64,
}

pub struct RoomSearch {
    indices: HashMap<String, Index>,
}

impl Default for RoomSearch {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomSearch {
    /// No rooms indexed.
    pub fn new() -> Self {
        Self { indices: HashMap::new() }
    }

    /// Update the index of room `slug` with one of its events at `cursor`: a `Posted` event indexes `html_text` of its
    /// html under `cursor`; an `Edited { target }` event re-indexes `target` with the new text (`Index::insert` replaces);
    /// a `Deleted { target }` event removes `target`; membership events change nothing. A room's index is created on its
    /// first event.
    pub fn index(&mut self, slug: &str, cursor: u64, event: &Event) {
        let index = self.indices.entry(slug.to_string()).or_default();
        match &event.kind {
            EventKind::Posted => {
                index.insert(cursor, &html_text(&event.html));
            }
            EventKind::Edited { target } => {
                index.insert(*target, &html_text(&event.html));
            }
            EventKind::Deleted { target } => {
                index.remove(*target);
            }
            EventKind::Joined { .. } | EventKind::Left { .. } => {}
        }
    }

    /// Up to `limit` hits for `query` (as `Index::search`) across every indexed room whose current members include
    /// `user` (`server.room(slug)` and its `role`). Rooms the user is not in, or that the server no longer has, are
    /// skipped silently. Order: newest first by cursor across all rooms; equal cursors in different rooms by slug.
    pub fn search(&self, server: &Server, user: &str, query: &str, limit: usize) -> Vec<Hit> {
        let mut hits: Vec<Hit> = Vec::new();
        for (slug, index) in &self.indices {
            let service = match server.room(slug) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if service.role(user).is_none() {
                continue;
            }
            let cursors = index.search(query, limit);
            for cursor in cursors {
                hits.push(Hit { slug: slug.clone(), cursor });
            }
        }
        hits.sort_by(|a, b| b.cursor.cmp(&a.cursor).then_with(|| a.slug.cmp(&b.slug)));
        hits.truncate(limit);
        hits
    }
}
