//! T362a: CrewCraft's own str0m crypto provider. The SRTP ciphers and hashes give the published test vectors (RFC
//! 3711 B.2, FIPS-197 C.1 and C.3, the GCM paper's test cases 4 and 16, RFC 2202, FIPS 180), each also computed with
//! OpenSSL when the test was written; the certificate is a self-signed P-256 certificate whose key loads; and two DTLS
//! peers made by the provider complete a handshake, see each other's certificate and agree on SRTP keys.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::time::{Duration, Instant};

use crewcraft_media_crypto::provider;
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePrivateKey;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsInstance, DtlsOutput, SrtpProfile};
use str0m_proto::crypto::{CryptoProvider, DtlsVersion};
use x509_cert::der::{Decode, Encode};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn the() -> CryptoProvider {
    provider()
}

#[test]
fn aes_counter_mode_gives_the_rfc_3711_keystream() {
    let key: [u8; 16] = hex("2B7E151628AED2A6ABF7158809CF4F3C").try_into().unwrap();
    let iv: [u8; 16] = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000").try_into().unwrap();
    let mut cipher = the().srtp_provider.aes_128_cm_sha1_80().create_cipher(key, true);
    let mut out = [0u8; 48];
    cipher.encrypt(&iv, &[0u8; 48], &mut out).unwrap();
    assert_eq!(out.to_vec(), hex("E03EAD0935C95E80E166B16DD92B4EB4D23513162B02D0F72A43A2FE4A5F97AB41E95B3BB0A2E8DD477901E4FCA894C0"));
    // Decrypting is the same keystream.
    let mut back = [0u8; 48];
    the().srtp_provider.aes_128_cm_sha1_80().create_cipher(key, false).decrypt(&iv, &out, &mut back).unwrap();
    assert_eq!(back, [0u8; 48]);
    // An output too small is an error, not a panic.
    assert!(cipher.encrypt(&iv, &[0u8; 48], &mut [0u8; 47]).is_err());
}

#[test]
fn one_aes_block_gives_the_fips_197_answers() {
    let plain = hex("00112233445566778899aabbccddeeff");
    let mut out = [0xEEu8; 20];
    the().srtp_provider.srtp_aes_128_ecb_round(&hex("000102030405060708090a0b0c0d0e0f"), &plain, &mut out);
    assert_eq!(out[..16].to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    assert_eq!(out[16..], [0xEE; 4], "bytes past the input are left alone");
    let mut out = [0u8; 16];
    the().srtp_provider.srtp_aes_256_ecb_round(&hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), &plain, &mut out);
    assert_eq!(out.to_vec(), hex("8ea2b7ca516745bfeafc49904b496089"));
    // A key of the wrong length leaves zeros, never stale bytes.
    let mut out = [0xEEu8; 16];
    the().srtp_provider.srtp_aes_128_ecb_round(&[1; 15], &plain, &mut out);
    assert_eq!(out, [0; 16]);
}

const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_PLAIN: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

#[test]
fn aes_128_gcm_gives_test_case_4_and_refuses_a_changed_packet() {
    let key: [u8; 16] = hex("feffe9928665731c6d6a8f9467308308").try_into().unwrap();
    let iv: [u8; 12] = hex(GCM_IV).try_into().unwrap();
    let (plain, aad) = (hex(GCM_PLAIN), hex(GCM_AAD));
    let mut sealed = vec![0u8; plain.len() + 16];
    the().srtp_provider.aead_aes_128_gcm().create_cipher(key, true).encrypt(&iv, &aad, &plain, &mut sealed).unwrap();
    let want = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
                5bc94fbc3221a5db94fae95ae7121a47";
    assert_eq!(sealed, hex(want));
    let mut opener = the().srtp_provider.aead_aes_128_gcm().create_cipher(key, false);
    let mut out = vec![0u8; sealed.len()];
    // The associated data may come in pieces.
    let n = opener.decrypt(&iv, &[&aad[..12], &aad[12..]], &sealed, &mut out).unwrap();
    assert_eq!(out[..n], plain[..]);
    let mut changed = sealed.clone();
    changed[3] ^= 1;
    let mut out = vec![0xEEu8; sealed.len()];
    assert!(opener.decrypt(&iv, &[&aad], &changed, &mut out).is_err());
    assert!(out[..plain.len()].iter().all(|b| *b == 0), "a refused packet leaves no plaintext behind");
    assert!(opener.decrypt(&iv, &[&aad], &sealed[..15], &mut out).is_err(), "shorter than a tag");
}

#[test]
fn aes_256_gcm_gives_test_case_16() {
    let key: [u8; 32] = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").try_into().unwrap();
    let iv: [u8; 12] = hex(GCM_IV).try_into().unwrap();
    let (plain, aad) = (hex(GCM_PLAIN), hex(GCM_AAD));
    let mut sealed = vec![0u8; plain.len() + 16];
    the().srtp_provider.aead_aes_256_gcm().create_cipher(key, true).encrypt(&iv, &aad, &plain, &mut sealed).unwrap();
    let want = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
                76fc6ece0f4e1768cddf8853bb2d551b";
    assert_eq!(sealed, hex(want));
    let mut out = vec![0u8; sealed.len()];
    let n = the().srtp_provider.aead_aes_256_gcm().create_cipher(key, false).decrypt(&iv, &[&aad], &sealed, &mut out).unwrap();
    assert_eq!(out[..n], plain[..]);
}

#[test]
fn the_hashes_give_the_published_answers() {
    let mac = the().sha1_hmac_provider.sha1_hmac(b"Jefe", &[b"what do ya ", b"want for nothing?"]);
    assert_eq!(mac.to_vec(), hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
    assert_eq!(the().sha1_provider.sha1(b"abc").to_vec(), hex("a9993e364706816aba3e25717850c26c9cd0d89d"));
    assert_eq!(the().sha256_provider.sha256(b"abc").to_vec(), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

#[test]
fn the_certificate_is_a_fresh_self_signed_p256_certificate() {
    let made = the().dtls_provider.generate_certificate().unwrap();
    let cert = x509_cert::Certificate::from_der(&made.certificate).unwrap();
    let tbs = cert.tbs_certificate();
    assert_eq!(tbs.subject(), tbs.issuer());
    assert_eq!(tbs.subject().to_string(), "CN=CrewCraft");
    // ecdsa-with-SHA256, and the signature checks against the certificate's own key.
    assert_eq!(cert.signature_algorithm().oid.to_string(), "1.2.840.10045.4.3.2");
    let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(tbs.subject_public_key_info().subject_public_key.raw_bytes()).unwrap();
    let signature = p256::ecdsa::DerSignature::try_from(cert.signature().raw_bytes()).unwrap();
    public.verify(&tbs.to_der().unwrap(), &signature).unwrap();
    // The private key is PKCS#8 and belongs to the certificate.
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(&made.private_key).unwrap();
    assert_eq!(key.verifying_key(), &public);
    // Valid now, for a clock a little behind too.
    let now = std::time::SystemTime::now();
    let validity = tbs.validity();
    assert!(validity.not_before.to_system_time() + Duration::from_secs(3600) < now);
    assert!(validity.not_after.to_system_time() > now + Duration::from_secs(7 * 24 * 3600));
    // Each certificate is new.
    let other = the().dtls_provider.generate_certificate().unwrap();
    assert_ne!(other.certificate, made.certificate);
    assert_ne!(other.private_key, made.private_key);
}

/// One side of a DTLS connection in memory, and what it has seen.
struct Side {
    dtls: Box<dyn DtlsInstance>,
    cert: DtlsCert,
    connected: bool,
    peer_cert: Option<Vec<u8>>,
    keying: Option<(Vec<u8>, SrtpProfile)>,
    received: Vec<Vec<u8>>,
}

impl Side {
    fn new(version: DtlsVersion, active: bool, now: Instant) -> Self {
        let cert = the().dtls_provider.generate_certificate().unwrap();
        let mut dtls = the().dtls_provider.new_dtls(&cert, now, version, None).unwrap();
        dtls.set_active(active);
        Side { dtls, cert, connected: false, peer_cert: None, keying: None, received: Vec::new() }
    }

    /// Everything the side has to say, into `out`; when it next wants a timeout.
    fn drain(&mut self, out: &mut Vec<Vec<u8>>) -> Instant {
        let mut buf = vec![0u8; 2048];
        loop {
            let mut grow = None;
            match self.dtls.poll_output(&mut buf) {
                DtlsOutput::Packet(packet) => out.push(packet.to_vec()),
                DtlsOutput::Timeout(at) => return at,
                DtlsOutput::Connected => self.connected = true,
                DtlsOutput::PeerCert(der) => self.peer_cert = Some(der.to_vec()),
                DtlsOutput::KeyingMaterial(material, profile) => self.keying = Some((material.to_vec(), profile)),
                DtlsOutput::ApplicationData(data) => self.received.push(data.to_vec()),
                DtlsOutput::BufferTooSmall { needed } => grow = Some(needed),
                _ => {}
            }
            if let Some(needed) = grow {
                buf.resize(needed, 0);
            }
        }
    }
}

/// Run `a` and `b` against each other until both are quiet, moving the clock to the next timeout when no packets
/// are in flight.
fn run(a: &mut Side, b: &mut Side, now: &mut Instant) {
    for _ in 0..200 {
        let (mut to_b, mut to_a) = (Vec::new(), Vec::new());
        let next_a = a.drain(&mut to_b);
        let next_b = b.drain(&mut to_a);
        if to_a.is_empty() && to_b.is_empty() {
            if a.connected && b.connected {
                return;
            }
            *now = (*now).max(next_a.min(next_b));
            a.dtls.handle_timeout(*now).unwrap();
            b.dtls.handle_timeout(*now).unwrap();
            continue;
        }
        for packet in to_b {
            b.dtls.handle_packet(&packet).unwrap();
        }
        for packet in to_a {
            a.dtls.handle_packet(&packet).unwrap();
        }
    }
    panic!("the handshake did not finish: a connected {}, b connected {}", a.connected, b.connected);
}

fn handshake(client: DtlsVersion, server: DtlsVersion) {
    let mut now = Instant::now();
    let mut a = Side::new(client, true, now);
    let mut b = Side::new(server, false, now);
    a.dtls.handle_timeout(now).unwrap();
    b.dtls.handle_timeout(now).unwrap();
    run(&mut a, &mut b, &mut now);
    // Each sees the other's certificate, and both derive the same SRTP keys for the same profile.
    assert_eq!(a.peer_cert.as_deref(), Some(&b.cert.certificate[..]));
    assert_eq!(b.peer_cert.as_deref(), Some(&a.cert.certificate[..]));
    let (keys_a, profile_a) = a.keying.clone().unwrap();
    let (keys_b, profile_b) = b.keying.clone().unwrap();
    assert_eq!(profile_a, profile_b);
    assert_eq!(keys_a, keys_b);
    assert_eq!(keys_a.len(), profile_a.keying_material_len());
    assert_eq!(a.dtls.protocol_version(), b.dtls.protocol_version());
    // Data goes both ways over the connection.
    a.dtls.send_application_data(b"hello from a").unwrap();
    b.dtls.send_application_data(b"hello from b").unwrap();
    run(&mut a, &mut b, &mut now);
    assert_eq!(b.received, vec![b"hello from a".to_vec()]);
    assert_eq!(a.received, vec![b"hello from b".to_vec()]);
}

#[test]
fn two_dtls_1_2_peers_connect_and_agree_on_srtp_keys() {
    handshake(DtlsVersion::Dtls12, DtlsVersion::Dtls12);
}

#[test]
fn two_dtls_1_3_peers_connect_and_agree_on_srtp_keys() {
    handshake(DtlsVersion::Dtls13, DtlsVersion::Dtls13);
}

#[test]
fn a_peer_that_offers_either_version_connects_to_a_dtls_1_2_peer() {
    handshake(DtlsVersion::Auto, DtlsVersion::Dtls12);
}
