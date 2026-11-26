//! The app's call keys (docs/CALLS.md end-to-end encryption, task T360d3): a state machine with no I/O, driven by
//! what the server last said about the call (its participants' call keys and the boxes sealed to this person), and
//! returning the requests to send.
//!
//! Owns: this device's call key pair for one call, its current sender key and key id, which participants it was
//! sealed to, and the keys others sealed to it. Rules: publish the call key whenever the server's list does not show
//! it; seal the current sender key to every other participant once; when anyone leaves, rotate (a new sender key
//! under the next key id, sealed again to everyone still there), so the person who left never gets it; open every box
//! sealed to this person once. Called by the worker (`worker.rs`); calls `crewcraft_sframe::seal`.

use std::collections::{BTreeMap, BTreeSet};

use crewcraft_sframe::Error;
use crewcraft_sframe::seal::{CallKeyPair, open, seal};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// What a step asks the worker to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Send {
    /// `CallKey`: this device's call public key.
    Publish([u8; 32]),
    /// `CallSeal`: the current sender key, sealed to `to`.
    Seal { to: String, kid: u64, sealed: Vec<u8> },
}

/// The context a sender key is sealed under: the call, who sends, and the key id, so a box opens nowhere else.
pub fn context(call: u64, from: &str, kid: u64) -> String {
    format!("crewcraft call {call} from {from} kid {kid}")
}

fn random_key() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut key[..]).map_err(|_| Error::BadKey)?;
    Ok(key)
}

/// One person's keys for one call.
pub struct CallCrypto {
    call: u64,
    me: String,
    pair: CallKeyPair,
    kid: u64,
    sender_key: Zeroizing<[u8; 32]>,
    sealed_to: BTreeSet<String>,
    others: BTreeSet<String>,
    received: BTreeMap<(String, u64), Zeroizing<Vec<u8>>>,
    /// Boxes that would not open (sealed to an old key, or changed): not tried again.
    refused: BTreeSet<(String, u64)>,
}

impl std::fmt::Debug for CallCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallCrypto").field("call", &self.call).field("kid", &self.kid).field("received", &self.received.len()).finish_non_exhaustive()
    }
}

impl CallCrypto {
    /// Fresh keys for `me` in `call`: a new call key pair and a first sender key (key id 1).
    pub fn new(call: u64, me: &str) -> Result<Self, Error> {
        Ok(Self {
            call,
            me: me.to_owned(),
            pair: CallKeyPair::generate()?,
            kid: 1,
            sender_key: random_key()?,
            sealed_to: BTreeSet::new(),
            others: BTreeSet::new(),
            received: BTreeMap::new(),
            refused: BTreeSet::new(),
        })
    }

    pub fn call(&self) -> u64 {
        self.call
    }

    /// One step from the server's view of the call: `keys`, every participant's call key; `boxes`, the sender keys
    /// sealed to me by (sender, kid). Returns what to send, in order.
    pub fn step(&mut self, keys: &BTreeMap<String, [u8; 32]>, boxes: &BTreeMap<(String, u64), Vec<u8>>) -> Result<Vec<Send>, Error> {
        let mut out = Vec::new();
        if keys.get(&self.me) != Some(&self.pair.public_key()) {
            out.push(Send::Publish(self.pair.public_key()));
        }
        let now: BTreeSet<String> = keys.keys().filter(|person| **person != self.me).cloned().collect();
        // Someone left: a new sender key they will never get.
        if self.others.iter().any(|person| !now.contains(person)) {
            self.kid += 1;
            self.sender_key = random_key()?;
            self.sealed_to.clear();
        }
        self.others = now;
        for person in &self.others {
            if self.sealed_to.contains(person) {
                continue;
            }
            let Some(public) = keys.get(person) else { continue };
            // A participant's key that cannot be sealed to (a low-order point) is skipped, not fatal.
            if let Ok(sealed) = seal(public, context(self.call, &self.me, self.kid).as_bytes(), &self.sender_key[..]) {
                out.push(Send::Seal { to: person.clone(), kid: self.kid, sealed });
                self.sealed_to.insert(person.clone());
            }
        }
        for ((from, kid), sealed) in boxes {
            let id = (from.clone(), *kid);
            if self.received.contains_key(&id) || self.refused.contains(&id) {
                continue;
            }
            match open(&self.pair, context(self.call, from, *kid).as_bytes(), sealed) {
                Ok(key) => {
                    self.received.insert(id, key);
                }
                Err(_) => {
                    self.refused.insert(id);
                }
            }
        }
        Ok(out)
    }

    /// The key id this person sends under now.
    pub fn sending_kid(&self) -> u64 {
        self.kid
    }

    /// This person's current sender key, for the media pipeline.
    pub fn sender_key(&self) -> &[u8] {
        &self.sender_key[..]
    }

    /// The sender key `from` sealed to me under `kid`, if it arrived.
    pub fn received_key(&self, from: &str, kid: u64) -> Option<&[u8]> {
        self.received.get(&(from.to_owned(), kid)).map(|key| &key[..])
    }

    /// The people whose sender key reached me (any key id), sorted.
    pub fn received_from(&self) -> Vec<String> {
        let people: BTreeSet<&String> = self.received.keys().map(|(from, _)| from).collect();
        people.into_iter().cloned().collect()
    }
}
