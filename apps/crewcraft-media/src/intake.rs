//! The signalling intake (task T363b): how requests reach the serving loop. A participant's offer and media
//! credential, and the chat server's word to drop a person or end a call, arrive as [`Request`]s from an [`Intake`].
//!
//! Owns: the request shape and an in-process intake ([`channel`]): a [`Handle`] any thread can call, and the
//! [`ChannelIntake`] the loop drains. Called by: [`crate::serve::run`].
//!
//! The chat server's control connection (mutual TLS, docs/CALLS.md "Admission", task T360b3) lives in the binary,
//! `apps/crewcraft-media-server`: it feeds a [`Handle`]. Joins have no network intake yet.

use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};

use crate::{JoinError, Joined};

/// How many requests may wait for the loop before a `Handle` call waits too.
const CAPACITY: usize = 256;

/// One request to the serving loop.
pub enum Request {
    /// Admit a participant to `call` (see [`crate::MediaServer::join`]); the answer goes to `reply`.
    Join { call: u64, credential: Vec<u8>, offer: String, reply: Sender<Result<Joined, JoinError>> },
    /// Drop every session of `person` in `call` (they left, were removed or lost permission).
    DropPerson { call: u64, person: String },
    /// Drop everyone in `call` (it ended).
    EndCall { call: u64 },
}

/// Where the serving loop takes its requests from. `take` must not block: the loop calls it between datagrams.
pub trait Intake {
    /// Move the requests that have arrived onto `into`.
    fn take(&mut self, into: &mut Vec<Request>);
}

/// An intake with no requests: a media server with no control connection configured.
pub struct NoIntake;

impl Intake for NoIntake {
    fn take(&mut self, _into: &mut Vec<Request>) {}
}

/// A cloneable way to send requests to a serving loop in the same process.
#[derive(Clone)]
pub struct Handle {
    requests: SyncSender<Request>,
}

/// The loop's end of [`channel`].
pub struct ChannelIntake {
    requests: Receiver<Request>,
}

/// An in-process intake and the handle that feeds it.
pub fn channel() -> (Handle, ChannelIntake) {
    let (requests, receiver) = mpsc::sync_channel(CAPACITY);
    (Handle { requests }, ChannelIntake { requests: receiver })
}

impl Handle {
    /// Ask the loop to admit a participant, and wait for its answer. `JoinError::Stopped` when the loop is gone.
    pub fn join(&self, call: u64, credential: &[u8], offer: &str) -> Result<Joined, JoinError> {
        let (reply, answer) = mpsc::channel();
        let request = Request::Join { call, credential: credential.to_vec(), offer: offer.to_owned(), reply };
        self.requests.send(request).map_err(|_| JoinError::Stopped)?;
        answer.recv().unwrap_or(Err(JoinError::Stopped))
    }

    /// Ask the loop to drop `person` from `call`. Returns false when the loop is gone.
    pub fn drop_person(&self, call: u64, person: &str) -> bool {
        self.requests.send(Request::DropPerson { call, person: person.to_owned() }).is_ok()
    }

    /// Ask the loop to end `call`. Returns false when the loop is gone.
    pub fn end_call(&self, call: u64) -> bool {
        self.requests.send(Request::EndCall { call }).is_ok()
    }
}

impl Intake for ChannelIntake {
    fn take(&mut self, into: &mut Vec<Request>) {
        // At most a queue's worth at a time, so a busy sender cannot hold the loop away from its socket.
        for _ in 0..CAPACITY {
            match self.requests.try_recv() {
                Ok(request) => into.push(request),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }
}
