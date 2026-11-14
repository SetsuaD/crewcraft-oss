//! The client's requests in flight: their ids, their timeouts, and matching each reply to its request. Over
//! `proto::request` (T124). Task T129.

use std::collections::HashMap;

use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::{Request, Response, decode_response, encode_request};

/// A request with no reply this long after it was sent has timed out.
pub const TIMEOUT_MS: u64 = 15_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The reply to a request in flight, which is now forgotten.
    Done { id: u32, request: Request, response: Response },
    /// A well-formed reply whose id is not in flight (it came after its timeout, or twice). Nothing changes.
    Unknown { id: u32 },
    /// The bytes do not decode (`decode_response`). Nothing changes.
    Malformed(CodecError),
}

#[derive(Debug, Default)]
pub struct Requests {
    next_id: u32,
    in_flight: HashMap<u32, (Request, u64)>,
}

impl Requests {
    /// Ids start at 1.
    pub fn new() -> Self {
        Self { next_id: 1, in_flight: HashMap::new() }
    }

    /// Ids start at `next_id` (0 is taken as 1). Lets a test reach the wrap-around.
    pub fn starting_at(next_id: u32) -> Self {
        let next_id = if next_id == 0 { 1 } else { next_id };
        Self { next_id, in_flight: HashMap::new() }
    }

    /// Encode `request` (`encode_request`) under the next id and remember it as sent at `now_ms`. Ids count up by one,
    /// wrap from `u32::MAX` to 1 (never 0), and skip any id still in flight. If encoding fails, the error is returned,
    /// nothing is remembered and the id is not used up.
    pub fn send(&mut self, request: Request, now_ms: u64) -> Result<(u32, Vec<u8>), CodecError> {
        let mut id = self.next_id;
        if id == 0 {
            id = 1;
        }
        while self.in_flight.contains_key(&id) {
            id = if id == u32::MAX { 1 } else { id + 1 };
        }

        let bytes = encode_request(id, &request)?;

        self.in_flight.insert(id, (request, now_ms));
        self.next_id = if id == u32::MAX { 1 } else { id + 1 };

        Ok((id, bytes))
    }

    /// A reply arrived (see `Reply`).
    pub fn on_reply(&mut self, bytes: &[u8]) -> Reply {
        let (id, response) = match decode_response(bytes) {
            Ok(v) => v,
            Err(e) => return Reply::Malformed(e),
        };

        match self.in_flight.remove(&id) {
            Some((request, _)) => Reply::Done { id, request, response },
            None => Reply::Unknown { id },
        }
    }

    /// Forget and return the requests whose time is up (`now_ms - sent >= TIMEOUT_MS`), oldest first: by send time,
    /// then by id. A `now_ms` earlier than a send time expires nothing.
    pub fn expire(&mut self, now_ms: u64) -> Vec<(u32, Request)> {
        let mut expired: Vec<(u32, Request, u64)> = self
            .in_flight
            .iter()
            .filter(|(_, (_, sent_at))| now_ms >= *sent_at && now_ms - *sent_at >= TIMEOUT_MS)
            .map(|(&id, (request, sent_at))| (id, request.clone(), *sent_at))
            .collect();

        let expired_ids: Vec<u32> = expired.iter().map(|(id, _, _)| *id).collect();
        for id in &expired_ids {
            self.in_flight.remove(id);
        }

        expired.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));

        expired.into_iter().map(|(id, req, _)| (id, req)).collect()
    }

    /// How many requests are in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }
}
