#![allow(clippy::unwrap_used)]

use crewcraft_pki::{Authority, Claims, ISSUING_LIFETIME_SECS, IssuingLoadError};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
use x509_parser::parse_x509_certificate;

const NOW_MS: u64 = 1_800_000_000_000;

#[test]
fn restored_issuer_keeps_the_chain_for_device_and_server_certificates() {
    let root = Authority::create_root("Test Root", NOW_MS).unwrap();
    let mut original = root.create_issuing("Test Issuing", NOW_MS).unwrap();
    let root_der = root.certificate().to_vec();
    let issuing_der = original.certificate().to_vec();
    let key_der = original.with_issuing_key(<[u8]>::to_vec).unwrap();

    let device_key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&device_key).unwrap();
    let claims = Claims { person: "alice@example.org", device_id: 7 };
    let before = original.issue_device(csr.der().as_ref(), &claims, NOW_MS).unwrap();
    drop(original);
    drop(root);

    let mut restored = Authority::load_issuing(&root_der, &issuing_der, &key_der, NOW_MS + 1000).unwrap();
    assert_eq!(restored.certificate(), issuing_der.as_slice());
    let after = restored.issue_device(csr.der().as_ref(), &claims, NOW_MS + 1000).unwrap();
    let server = restored.server_certificate("server.example.org", NOW_MS + 1000).unwrap();
    let (_, parsed_root) = parse_x509_certificate(&root_der).unwrap();
    let (_, parsed_issuer) = parse_x509_certificate(&issuing_der).unwrap();
    parsed_issuer.verify_signature(Some(parsed_root.public_key())).unwrap();
    for chain in [&before.chain, &after.chain, &server.chain] {
        assert_eq!(chain[1], issuing_der);
        let (_, leaf) = parse_x509_certificate(&chain[0]).unwrap();
        assert_eq!(leaf.issuer().as_raw(), parsed_issuer.subject().as_raw());
        leaf.verify_signature(Some(parsed_issuer.public_key())).unwrap();
    }
    assert_ne!(before.serial, after.serial);
    assert_eq!(before.key_id, after.key_id);
}

#[test]
fn wrong_root_and_wrong_private_keys_are_refused() {
    let root = Authority::create_root("Test Root", NOW_MS).unwrap();
    let other_root = Authority::create_root("Test Root", NOW_MS).unwrap();
    let issuing = root.create_issuing("Test Issuing", NOW_MS).unwrap();
    let key = issuing.with_issuing_key(<[u8]>::to_vec).unwrap();
    let load = |root_der: &[u8], key_der: &[u8]| Authority::load_issuing(root_der, issuing.certificate(), key_der, NOW_MS);
    assert_eq!(load(other_root.certificate(), &key).unwrap_err(), IssuingLoadError::Chain);

    let wrong_key = KeyPair::generate().unwrap();
    assert_eq!(load(root.certificate(), wrong_key.serialized_der()).unwrap_err(), IssuingLoadError::KeyMismatch);
    let wrong_curve = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    assert_eq!(load(root.certificate(), wrong_curve.serialized_der()).unwrap_err(), IssuingLoadError::PrivateKey);
}

#[test]
fn rejects_malformed_expired_and_unconstrained_material() {
    let root = Authority::create_root("Test Root", NOW_MS).unwrap();
    let issuing = root.create_issuing("Test Issuing", NOW_MS).unwrap();
    assert_eq!(root.with_issuing_key(|_| ()).unwrap_err(), IssuingLoadError::Constraints);
    issuing
        .with_issuing_key(|key| {
            let load = |cert: &[u8], key: &[u8], now| Authority::load_issuing(root.certificate(), cert, key, now);
            let expired = NOW_MS + ISSUING_LIFETIME_SECS as u64 * 1000 + 1000;
            assert_eq!(load(issuing.certificate(), key, expired).unwrap_err(), IssuingLoadError::Time);
            assert_eq!(load(root.certificate(), key, NOW_MS).unwrap_err(), IssuingLoadError::Constraints);
            let leaf = issuing.server_certificate("server.example.org", NOW_MS).unwrap();
            assert_eq!(load(&leaf.chain[0], &leaf.key_pkcs8, NOW_MS).unwrap_err(), IssuingLoadError::Constraints);

            let mut malformed_cert = issuing.certificate().to_vec();
            malformed_cert.push(0);
            assert_eq!(load(&malformed_cert, key, NOW_MS).unwrap_err(), IssuingLoadError::Certificate);
            let mut malformed_key = key.to_vec();
            malformed_key.push(0);
            assert_eq!(load(issuing.certificate(), &malformed_key, NOW_MS).unwrap_err(), IssuingLoadError::PrivateKey);
        })
        .unwrap();
}
