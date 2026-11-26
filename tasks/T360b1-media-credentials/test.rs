//! T360b1: media credentials (docs/CALLS.md "Admission"): the chat server signs a credential for one device of one
//! person to join one call on one media server, good for 60 seconds; the media server accepts it once, and refuses
//! forged, changed, expired, copied and misdirected ones.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_media_auth::{Error, Issuer, LIFETIME_MS, Verifier};

const T0: u64 = 1_800_000_000_000;
const MEDIA: &str = "media.example.org";

fn issuer() -> Issuer {
    Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap()
}

#[test]
fn a_credential_admits_once() {
    let issuer = issuer();
    let mut media = Verifier::new(issuer.public_key(), MEDIA);
    let credential = issuer.issue(7, "general", "ana@example.org", 42, MEDIA, T0).unwrap();
    let grant = media.verify(&credential, T0 + 1_000).unwrap();
    assert_eq!((grant.call, grant.room.as_str(), grant.person.as_str(), grant.device), (7, "general", "ana@example.org", 42));
    assert_eq!(grant.not_after_ms, T0 + LIFETIME_MS);
    assert_eq!(media.verify(&credential, T0 + 2_000), Err(Error::Replayed), "a copy is refused");
    // Two credentials for the same person are two admissions.
    let again = issuer.issue(7, "general", "ana@example.org", 42, MEDIA, T0 + 3_000).unwrap();
    assert!(media.verify(&again, T0 + 3_000).is_ok());
}

#[test]
fn bad_credentials_are_refused() {
    let issuer = issuer();
    let mut media = Verifier::new(issuer.public_key(), MEDIA);
    let credential = issuer.issue(7, "general", "ana@example.org", 42, MEDIA, T0).unwrap();
    assert_eq!(media.verify(&credential, T0 + LIFETIME_MS + 1), Err(Error::Expired));

    let mut changed = credential.clone();
    changed[8] ^= 1; // the call id
    assert_eq!(media.verify(&changed, T0), Err(Error::BadSignature));
    let forged = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap().issue(7, "general", "ana@example.org", 42, MEDIA, T0).unwrap();
    assert_eq!(media.verify(&forged, T0), Err(Error::BadSignature), "another key");
    let elsewhere = issuer.issue(7, "general", "ana@example.org", 42, "other.example.org", T0).unwrap();
    assert_eq!(media.verify(&elsewhere, T0), Err(Error::WrongServer));
    for cut in [0, 1, 10, credential.len() - 1] {
        assert_eq!(media.verify(&credential[..cut], T0), Err(Error::Malformed), "cut at {cut}");
    }
    let mut longer = credential.clone();
    longer.push(0);
    assert_eq!(media.verify(&longer, T0), Err(Error::Malformed));
    assert_eq!(issuer.issue(7, "", "ana@example.org", 42, MEDIA, T0), Err(Error::Unusable), "an empty room name");
    // The good one still works: refusals use nothing up.
    assert!(media.verify(&credential, T0 + 1).is_ok());
}

#[test]
fn used_credentials_are_forgotten_once_expired() {
    let issuer = issuer();
    let mut media = Verifier::new(issuer.public_key(), MEDIA);
    for n in 0..5 {
        let credential = issuer.issue(n, "general", "ana@example.org", 1, MEDIA, T0).unwrap();
        media.verify(&credential, T0).unwrap();
    }
    assert_eq!(media.remembered(), 5);
    let later = issuer.issue(9, "general", "ana@example.org", 1, MEDIA, T0 + LIFETIME_MS + 10).unwrap();
    media.verify(&later, T0 + LIFETIME_MS + 10).unwrap();
    assert_eq!(media.remembered(), 1, "the memory of used credentials stays bounded");
}
