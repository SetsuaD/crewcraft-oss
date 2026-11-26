//! T360d3: the app's call keys (docs/CALLS.md): three people in a call publish their call keys and seal their sender
//! keys to each other through a stand-in for the server's relay; everyone opens everyone else's key and decrypts their
//! SFrame frames; when one leaves, the others rotate to a new key id the one who left never receives.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use crewcraft::call_crypto::{CallCrypto, Send};
use crewcraft_sframe::{CipherSuite, Key, decrypt};

const CALL: u64 = 7;

/// The server's relay for one call: published keys, and boxes by (recipient, sender, kid).
#[derive(Default)]
struct Relay {
    keys: BTreeMap<String, [u8; 32]>,
    boxes: BTreeMap<(String, String, u64), Vec<u8>>,
}

impl Relay {
    fn boxes_for(&self, me: &str) -> BTreeMap<(String, u64), Vec<u8>> {
        self.boxes.iter().filter(|((to, _, _), _)| to == me).map(|((_, from, kid), sealed)| ((from.clone(), *kid), sealed.clone())).collect()
    }

    fn take(&mut self, from: &str, sends: Vec<Send>) {
        for send in sends {
            match send {
                Send::Publish(key) => {
                    self.keys.insert(from.to_owned(), key);
                }
                Send::Seal { to, kid, sealed } => {
                    self.boxes.insert((to, from.to_owned(), kid), sealed);
                }
            }
        }
    }

    fn leave(&mut self, person: &str) {
        self.keys.remove(person);
        self.boxes.retain(|(to, from, _), _| to != person && from != person);
    }
}

/// Run steps until nobody has anything left to send.
fn settle(relay: &mut Relay, people: &mut [(&str, &mut CallCrypto)]) {
    for _ in 0..4 {
        for (name, crypto) in people.iter_mut() {
            let sends = crypto.step(&relay.keys, &relay.boxes_for(name)).unwrap();
            relay.take(name, sends);
        }
    }
}

fn can_read(reader: &CallCrypto, sender: &CallCrypto, from: &str) -> bool {
    let frame = Key::new(CipherSuite::Aes128GcmSha256, sender.sending_kid(), sender.sender_key()).unwrap().encrypt(0, b"", b"audio").unwrap();
    let Some(key) = reader.received_key(from, sender.sending_kid()) else { return false };
    let key = Key::new(CipherSuite::Aes128GcmSha256, sender.sending_kid(), key).unwrap();
    decrypt(|kid| (kid == sender.sending_kid()).then_some(&key), b"", &frame).is_ok()
}

#[test]
fn everyone_gets_everyone_elses_key_and_a_leaver_is_rotated_out() {
    let mut relay = Relay::default();
    let (mut ana, mut bo, mut cy) =
        (CallCrypto::new(CALL, "ana").unwrap(), CallCrypto::new(CALL, "bo").unwrap(), CallCrypto::new(CALL, "cy").unwrap());
    settle(&mut relay, &mut [("ana", &mut ana), ("bo", &mut bo), ("cy", &mut cy)]);
    assert_eq!(ana.received_from(), vec!["bo", "cy"]);
    assert_eq!(bo.received_from(), vec!["ana", "cy"]);
    assert!(can_read(&bo, &ana, "ana") && can_read(&cy, &ana, "ana") && can_read(&ana, &cy, "cy"));
    // Nothing more to send once settled: each key was published and sealed once.
    assert!(ana.step(&relay.keys, &relay.boxes_for("ana")).unwrap().is_empty());

    // Cy leaves: Ana and Bo rotate to key id 2, sealed only to each other.
    relay.leave("cy");
    settle(&mut relay, &mut [("ana", &mut ana), ("bo", &mut bo)]);
    assert_eq!((ana.sending_kid(), bo.sending_kid()), (2, 2));
    assert!(can_read(&bo, &ana, "ana") && can_read(&ana, &bo, "bo"));
    assert!(cy.received_key("ana", 2).is_none());
    assert!(!relay.boxes.keys().any(|(to, _, _)| to == "cy"), "nothing is sealed to Cy any more");
}

#[test]
fn the_key_is_published_again_when_the_server_forgot_it() {
    let mut relay = Relay::default();
    let mut ana = CallCrypto::new(CALL, "ana").unwrap();
    let first = ana.step(&relay.keys, &BTreeMap::new()).unwrap();
    assert!(matches!(first.as_slice(), [Send::Publish(_)]));
    relay.take("ana", first);
    assert!(ana.step(&relay.keys, &BTreeMap::new()).unwrap().is_empty());
    // A server restart forgets call keys: the next step publishes again.
    relay.keys.clear();
    assert!(matches!(ana.step(&relay.keys, &BTreeMap::new()).unwrap().as_slice(), [Send::Publish(_)]));
}
