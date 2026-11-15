//! What the authority issues and refuses. Synthetic names only (example.org), no real keys.

// The helpers here are test code too, but clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies.
#![allow(clippy::unwrap_used)]

use crewcraft_pki::{Authority, Claims, DEVICE_LIFETIME_SECS, PkiError, Status, key_id_of_certificate, serial_of_certificate};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    PublicKeyData,
};
use x509_parser::parse_x509_certificate;

const NOW_MS: u64 = 1_800_000_000_000;
const ALICE: Claims<'static> = Claims { person: "alice@example.org", device_id: 7 };

fn authority() -> Authority {
    Authority::create_root("Test Root", NOW_MS).unwrap().create_issuing("Test Issuing", NOW_MS).unwrap()
}

/// A signing request for `key` that asks for everything it should not get.
fn greedy_csr(key: &KeyPair) -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["admin.example.org".to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, "root-admin");
    params.distinguished_name.push(DnType::OrganizationName, "Not The Server");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::Any];
    params.serialize_request(key).unwrap().der().to_vec()
}

fn plain_csr(key: &KeyPair) -> Vec<u8> {
    CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(key).unwrap().der().to_vec()
}

#[test]
fn the_server_ignores_everything_in_the_request_except_the_key() {
    let mut ca = authority();
    let key = KeyPair::generate().unwrap();
    let issued = ca.issue_device(&greedy_csr(&key), &ALICE, NOW_MS).unwrap();
    let (_, cert) = parse_x509_certificate(&issued.certificate).unwrap();

    // The subject is the server's: the person and the device, nothing the request asked for.
    let subject = cert.subject();
    assert_eq!(subject.iter_common_name().map(|a| a.as_str().unwrap()).collect::<Vec<_>>(), ["alice@example.org"]);
    assert_eq!(subject.iter_organizational_unit().map(|a| a.as_str().unwrap()).collect::<Vec<_>>(), ["device-7"]);
    assert_eq!(subject.iter_organization().count(), 0);
    assert!(cert.subject_alternative_name().unwrap().is_none(), "the requested alternative name was copied");
    // Not a CA, whatever the request said.
    assert!(cert.basic_constraints().unwrap().is_none_or(|b| !b.value.ca));
    // Client authentication and nothing else.
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth && !eku.any && !eku.code_signing && !eku.email_protection);
    assert!(eku.other.is_empty());
    let usage = cert.key_usage().unwrap().unwrap().value;
    assert!(usage.digital_signature() && !usage.key_cert_sign() && !usage.crl_sign());
    // The key is the one from the request.
    assert_eq!(cert.public_key().subject_public_key.data.as_ref(), key.der_bytes());
}

#[test]
fn a_device_certificate_lives_exactly_ninety_days() {
    let mut ca = authority();
    let issued = ca.issue_device(&plain_csr(&KeyPair::generate().unwrap()), &ALICE, NOW_MS).unwrap();
    let (_, cert) = parse_x509_certificate(&issued.certificate).unwrap();
    assert_eq!(cert.validity().not_before.timestamp(), 1_800_000_000);
    assert_eq!(cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp(), DEVICE_LIFETIME_SECS);
    assert_eq!(DEVICE_LIFETIME_SECS, 7_776_000);
    assert_eq!((issued.not_before, issued.not_after), (1_800_000_000, 1_800_000_000 + DEVICE_LIFETIME_SECS));
}

#[test]
fn a_request_without_proof_of_the_key_is_refused() {
    let mut ca = authority();
    let theirs = KeyPair::generate().unwrap();
    let victim = KeyPair::generate().unwrap();
    // Put the victim's public key into a request signed by someone else: the sender cannot prove they hold it.
    let mut csr = plain_csr(&theirs);
    let (mine, other) = (theirs.der_bytes(), victim.der_bytes());
    assert_eq!(mine.len(), other.len());
    let at = csr.windows(mine.len()).position(|w| w == mine).unwrap();
    csr[at..at + mine.len()].copy_from_slice(other);
    assert!(matches!(ca.issue_device(&csr, &ALICE, NOW_MS), Err(PkiError::Csr(_))));

    // A request whose signature bytes were damaged is refused too.
    let mut damaged = plain_csr(&theirs);
    let last = damaged.len() - 1;
    damaged[last] ^= 0xff;
    assert!(matches!(ca.issue_device(&damaged, &ALICE, NOW_MS), Err(PkiError::Csr(_))));
    // And garbage.
    assert!(matches!(ca.issue_device(b"not a request", &ALICE, NOW_MS), Err(PkiError::Csr(_))));
}

#[test]
fn only_p256_keys_are_accepted() {
    let mut ca = authority();
    for alg in [&PKCS_ED25519, &PKCS_ECDSA_P384_SHA384] {
        let key = KeyPair::generate_for(alg).unwrap();
        assert!(matches!(ca.issue_device(&plain_csr(&key), &ALICE, NOW_MS), Err(PkiError::NotP256)));
    }
}

#[test]
fn claims_must_be_sane() {
    let mut ca = authority();
    let csr = plain_csr(&KeyPair::generate().unwrap());
    for bad in [
        Claims { person: "", device_id: 1 },
        Claims { person: "alice@example.org", device_id: 0 },
        Claims { person: "alice\n@example.org", device_id: 1 },
        Claims { person: &"a".repeat(255), device_id: 1 },
    ] {
        assert!(matches!(ca.issue_device(&csr, &bad, NOW_MS), Err(PkiError::BadClaims)), "{bad:?}");
    }
}

#[test]
fn serials_are_random_and_distinct() {
    let mut ca = authority();
    let csr = plain_csr(&KeyPair::generate().unwrap());
    let serials: std::collections::HashSet<_> = (0..50).map(|_| ca.issue_device(&csr, &ALICE, NOW_MS).unwrap().serial).collect();
    assert_eq!(serials.len(), 50);
    assert!(serials.iter().all(|s| s.len() == 16 && s[0] & 0xc0 == 0x40));
}

#[test]
fn renewal_keeps_the_key_identity_and_changes_the_certificate() {
    let mut ca = authority();
    let key = KeyPair::generate().unwrap();
    let first = ca.issue_device(&plain_csr(&key), &ALICE, NOW_MS).unwrap();
    let later = NOW_MS + 60 * 86_400 * 1000;
    let second = ca.renew(&first.certificate, &plain_csr(&key), later).unwrap();
    assert_eq!(first.key_id, second.key_id);
    assert_eq!(key_id_of_certificate(&second.certificate).unwrap(), first.key_id);
    assert_ne!(first.serial, second.serial);
    assert_ne!(first.certificate, second.certificate);
    // The renewed certificate carries the identity recorded at issue, not anything the renewal request says.
    assert_eq!(
        ca.status(&second.certificate, later).unwrap(),
        Status::Good(crewcraft_pki::LeafInfo { person: "alice@example.org".into(), device_id: 7, key_id: first.key_id })
    );
    // The old certificate is still good until it expires.
    assert!(matches!(ca.status(&first.certificate, later).unwrap(), Status::Good(_)));
}

#[test]
fn renewal_with_another_key_or_another_certificate_is_refused() {
    let mut ca = authority();
    let key = KeyPair::generate().unwrap();
    let first = ca.issue_device(&plain_csr(&key), &ALICE, NOW_MS).unwrap();
    // A different key is a different device identity, not a renewal.
    let other = KeyPair::generate().unwrap();
    assert!(matches!(ca.renew(&first.certificate, &plain_csr(&other), NOW_MS), Err(PkiError::KeyMismatch)));
    // Nothing was recorded for the refused renewal.
    let before = ca.revoke_key(&first.key_id);
    assert_eq!(before, 1);

    // A certificate this authority never issued cannot be renewed.
    let mut elsewhere = authority();
    let foreign = elsewhere.issue_device(&plain_csr(&key), &ALICE, NOW_MS).unwrap();
    assert!(matches!(ca.renew(&foreign.certificate, &plain_csr(&key), NOW_MS), Err(PkiError::NotIssuedHere)));
}

#[test]
fn a_forged_certificate_with_a_known_serial_is_unknown() {
    let mut ca = authority();
    let key = KeyPair::generate().unwrap();
    let real = ca.issue_device(&plain_csr(&key), &ALICE, NOW_MS).unwrap();
    // Same serial, same key, different bytes (issued by another authority).
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&real.serial));
    let fake = params.self_signed(&key).unwrap();
    assert_eq!(serial_of_certificate(fake.der()).unwrap(), real.serial);
    assert_eq!(ca.status(fake.der(), NOW_MS).unwrap(), Status::Unknown);
    assert!(matches!(ca.renew(fake.der(), &plain_csr(&key), NOW_MS), Err(PkiError::NotIssuedHere)));
}

#[test]
fn revocation_is_per_certificate_and_per_key_and_is_rechecked() {
    let mut ca = authority();
    let key = KeyPair::generate().unwrap();
    let first = ca.issue_device(&plain_csr(&key), &ALICE, NOW_MS).unwrap();
    let second = ca.renew(&first.certificate, &plain_csr(&key), NOW_MS).unwrap();
    let bob = ca.issue_device(&plain_csr(&KeyPair::generate().unwrap()), &Claims { person: "bob@example.org", device_id: 8 }, NOW_MS).unwrap();

    // One certificate.
    assert!(ca.revoke(&first.serial));
    assert_eq!(ca.status(&first.certificate, NOW_MS).unwrap(), Status::Revoked);
    assert!(matches!(ca.status(&second.certificate, NOW_MS).unwrap(), Status::Good(_)));
    // A revoked certificate cannot be renewed.
    assert!(matches!(ca.renew(&first.certificate, &plain_csr(&key), NOW_MS), Err(PkiError::Revoked)));
    // The whole device key: every certificate it ever had, and no one else's.
    assert_eq!(ca.revoke_key(&second.key_id), 1);
    assert_eq!(ca.status(&second.certificate, NOW_MS).unwrap(), Status::Revoked);
    assert!(matches!(ca.status(&bob.certificate, NOW_MS).unwrap(), Status::Good(_)));
    // A serial we never issued.
    assert!(!ca.revoke(&[1, 2, 3]));
}

#[test]
fn an_expired_certificate_is_expired_and_cannot_renew() {
    let mut ca = authority();
    let key = KeyPair::generate().unwrap();
    let issued = ca.issue_device(&plain_csr(&key), &ALICE, NOW_MS).unwrap();
    let after = NOW_MS + (DEVICE_LIFETIME_SECS as u64) * 1000;
    assert!(matches!(ca.status(&issued.certificate, after - 1000).unwrap(), Status::Good(_)));
    assert_eq!(ca.status(&issued.certificate, after).unwrap(), Status::Expired);
    assert!(matches!(ca.renew(&issued.certificate, &plain_csr(&key), after), Err(PkiError::Expired)));
}

#[test]
fn the_server_certificate_names_the_host_and_nothing_else() {
    let ca = authority();
    let server = ca.server_certificate("chat.example.org", NOW_MS).unwrap();
    assert_eq!(server.chain.len(), 2);
    assert_eq!(server.chain[1], ca.certificate());
    let (_, cert) = parse_x509_certificate(&server.chain[0]).unwrap();
    assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "chat.example.org");
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && !eku.client_auth);
    // Nothing in the certificate says what product answers.
    assert!(!String::from_utf8_lossy(&server.chain[0]).to_lowercase().contains("crewcraft"));
    // The root signs only the issuing authority; the issuing authority is not a root.
    let (_, issuing) = parse_x509_certificate(ca.certificate()).unwrap();
    assert!(issuing.basic_constraints().unwrap().unwrap().value.ca);
    assert_eq!(issuing.basic_constraints().unwrap().unwrap().value.path_len_constraint, Some(0));
}
