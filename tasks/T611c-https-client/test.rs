//! T611c: the server's HTTPS client against a real TLS server in the test (its own CA, server and client
//! certificates, made at run time): the request it sends, Content-Length and chunked answers, redirects refused, size
//! limits, an untrusted server refused, mutual TLS, and timeouts.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crewcraft_https::{Client, Error, Roots};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

struct Pki {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

fn pki(name: &str) -> Pki {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.self_signed(&key).unwrap();
    Pki { ca_pem: pem(cert.der()), ca_der: cert.der().clone(), issuer: Issuer::new(params, key) }
}

/// The PEM text of a DER certificate (rcgen's own PEM output is a feature this workspace leaves off).
fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

fn leaf(ca: &Pki, names: &[&str]) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (vec![cert.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
}

/// A one-connection TLS server. It sends `answer` (raw HTTP bytes) after reading the request, or nothing at all when
/// `answer` is `None`, and hands back the request it read.
fn serve(ca: &Pki, client_ca: Option<&Pki>, answer: Option<Vec<u8>>) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let provider = Arc::new(ring::default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider)).with_safe_default_protocol_versions().unwrap();
    let (chain, key) = leaf(ca, &["localhost", "127.0.0.1"]);
    let config = match client_ca {
        Some(client_ca) => {
            let mut roots = RootCertStore::empty();
            roots.add(client_ca.ca_der.clone()).unwrap();
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
            builder.with_client_cert_verifier(verifier).with_single_cert(chain, key).unwrap()
        }
        None => builder.with_no_client_auth().with_single_cert(chain, key).unwrap(),
    };
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((tcp, _)) = listener.accept() else { return };
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let Ok(n) = tls.read(&mut chunk) else { return };
            if n == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..n]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
                let length = head.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse::<usize>().unwrap());
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let _ = tx.send(request);
        match answer {
            Some(bytes) => {
                let _ = tls.write_all(&bytes);
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
            None => thread::sleep(Duration::from_secs(3)),
        }
    });
    (port, rx)
}

fn client(ca: &Pki) -> Client {
    Client::new(&Roots::Pem(ca.ca_pem.clone().into_bytes()), None).unwrap().with_limits(Duration::from_secs(2), 1024)
}

fn ok_json(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

#[test]
fn a_get_sends_a_plain_request_and_reads_the_body() {
    let ca = pki("test ca");
    let (port, seen) = serve(&ca, None, Some(ok_json(r#"{"issuer":"x"}"#)));
    let answer = client(&ca).get(&format!("https://localhost:{port}/.well-known/openid-configuration?x=1")).unwrap();
    assert_eq!((answer.status, answer.content_type.as_deref()), (200, Some("application/json")));
    assert_eq!(answer.clone().ok().unwrap(), br#"{"issuer":"x"}"#);
    let request = String::from_utf8(seen.recv().unwrap()).unwrap();
    assert!(request.starts_with("GET /.well-known/openid-configuration?x=1 HTTP/1.1\r\n"), "{request}");
    assert!(request.contains(&format!("\r\nHost: localhost:{port}\r\n")) && request.contains("\r\nConnection: close\r\n"), "{request}");
}

#[test]
fn a_post_carries_its_body_and_a_chunked_answer_is_joined() {
    let ca = pki("test ca");
    let chunked =
        b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"er\r\nB;ext=1\r\nror\":\"bad\"}\r\n0\r\nX-Trailer: 1\r\n\r\n"
            .to_vec();
    let (port, seen) = serve(&ca, None, Some(chunked));
    let answer = client(&ca)
        .post(&format!("https://localhost:{port}/token"), "application/x-www-form-urlencoded", b"grant_type=authorization_code&code=abc")
        .unwrap();
    assert_eq!(answer.status, 400);
    assert_eq!(answer.body, br#"{"error":"bad"}"#);
    assert_eq!(answer.ok(), Err(Error::Status(400)));
    let request = String::from_utf8(seen.recv().unwrap()).unwrap();
    assert!(request.starts_with("POST /token HTTP/1.1\r\n"));
    assert!(request.contains("\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 38\r\n"), "{request}");
    assert!(request.ends_with("\r\n\r\ngrant_type=authorization_code&code=abc"));
}

#[test]
fn redirects_and_oversized_or_malformed_answers_are_refused() {
    let ca = pki("test ca");
    let cases: Vec<(Vec<u8>, Error)> = vec![
        (b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.org/\r\nContent-Length: 0\r\n\r\n".to_vec(), Error::Redirect(302)),
        (ok_json(&"x".repeat(1025)), Error::TooLarge),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n".to_vec(), Error::TooLarge),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello".to_vec(), Error::Malformed("conflicting content-length")),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec(), Error::Malformed("transfer-encoding")),
        (b"SPDY/3 200 OK\r\n\r\n".to_vec(), Error::Malformed("status line")),
        (format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\n\r\n", "a".repeat(20_000)).into_bytes(), Error::Malformed("headers too long")),
    ];
    for (answer, want) in cases {
        let (port, _seen) = serve(&ca, None, Some(answer));
        assert_eq!(client(&ca).get(&format!("https://localhost:{port}/")), Err(want.clone()), "{want:?}");
    }
}

#[test]
fn only_trusted_servers_over_https() {
    let ca = pki("test ca");
    let other = pki("another ca");
    let (port, _seen) = serve(&ca, None, Some(ok_json("{}")));
    assert!(matches!(client(&other).get(&format!("https://localhost:{port}/")), Err(Error::Tls(_))));
    assert_eq!(client(&ca).get("http://localhost/"), Err(Error::NotHttps));
    assert!(matches!(client(&ca).get("https://user:pw@localhost/"), Err(Error::BadUrl(_))));
    assert!(matches!(Client::new(&Roots::Pem(b"not a certificate".to_vec()), None), Err(Error::Config(_))));
    assert!(Client::new(&Roots::Public, None).is_ok(), "the public roots load");
}

#[test]
fn mutual_tls_presents_the_client_certificate() {
    let ca = pki("test ca");
    let clients = pki("client ca");
    let (port, _seen) = serve(&ca, Some(&clients), Some(ok_json("{}")));
    assert!(client(&ca).get(&format!("https://localhost:{port}/")).is_err(), "no client certificate, no answer");

    let (port, seen) = serve(&ca, Some(&clients), Some(ok_json(r#"{"decision":"allow"}"#)));
    let identity = leaf(&clients, &["chat-server"]);
    let with_cert = Client::new(&Roots::Pem(ca.ca_pem.clone().into_bytes()), Some(identity)).unwrap();
    let answer = with_cert.post(&format!("https://localhost:{port}/v1/authorize"), "application/json", br#"{"api":1}"#).unwrap();
    assert_eq!(answer.ok().unwrap(), br#"{"decision":"allow"}"#);
    assert!(String::from_utf8(seen.recv().unwrap()).unwrap().starts_with("POST /v1/authorize HTTP/1.1\r\n"));
}

#[test]
fn a_silent_server_times_out() {
    let ca = pki("test ca");
    let (port, _seen) = serve(&ca, None, None);
    let started = Instant::now();
    let quick = Client::new(&Roots::Pem(ca.ca_pem.clone().into_bytes()), None).unwrap().with_limits(Duration::from_millis(500), 1024);
    assert_eq!(quick.get(&format!("https://localhost:{port}/")), Err(Error::Timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
}
