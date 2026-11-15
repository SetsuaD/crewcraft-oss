#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft::enroll_client::{CertificateProblem, EnrollmentError, EnrollmentRequest, ExchangeProblem, FirstTotpCode, enroll};
use crewcraft_pki::{Authority, Claims, Issued};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use x509_parser::prelude::{FromDer, X509Certificate};

const CODE: &str = "287082";
const PASSWORD: &str = "synthetic test password";

type Captured = Rc<RefCell<Vec<u8>>>;

struct Scripted {
    incoming: Cursor<Vec<u8>>,
    sent: Captured,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.incoming.read(buf)
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sent.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn script(responses: impl IntoIterator<Item = (u32, BootstrapResponse)>) -> (Scripted, Captured) {
    let mut incoming = Vec::new();
    for (id, response) in responses {
        let payload = bootstrap::encode_bootstrap_response(id, &response).unwrap();
        incoming.extend(frame::encode(&payload).unwrap());
    }
    let sent = Captured::default();
    (Scripted { incoming: Cursor::new(incoming), sent: sent.clone() }, sent)
}

fn requests(sent: &Captured) -> Vec<(u32, BootstrapRequest)> {
    let bytes = sent.borrow();
    let mut stream = Cursor::new(bytes.as_slice());
    let mut requests = Vec::new();
    while let Some(frame) = frame::read_frame(&mut stream, frame::MAX_FRAME).unwrap() {
        requests.push(bootstrap::decode_bootstrap_request(frame.payload()).unwrap());
    }
    requests
}

struct Fixture {
    root: Authority,
    issuer: Authority,
    issued: Issued,
    csr: Vec<u8>,
    expected_spki: Vec<u8>,
    now_ms: u64,
}

impl Fixture {
    fn new() -> Self {
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let root = Authority::create_root("Test Root", now_ms).unwrap();
        let mut issuer = root.create_issuing("Test Issuer", now_ms).unwrap();
        let device = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&device).unwrap();
        let issued = issuer.issue_device(csr.der(), &Claims { person: "reader@example.org", device_id: 1 }, now_ms).unwrap();
        Self { root, issuer, issued, csr: csr.der().to_vec(), expected_spki: device.subject_public_key_info(), now_ms }
    }

    fn request(&self) -> EnrollmentRequest<'_> {
        EnrollmentRequest { device_name: "Test Device", csr: &self.csr, password: PASSWORD, expected_spki: &self.expected_spki }
    }

    fn activation(&self) -> BootstrapResponse {
        BootstrapResponse::Activated { certificate: self.issued.certificate.clone(), issuer_certificate: self.issuer.certificate().to_vec() }
    }
}

fn test_uri() -> String {
    crewcraft_totp::Totp::with_defaults(vec![7; 20]).unwrap().otpauth_uri("CrewCraft Lab", "pilot@example.org")
}

fn setup() -> (u32, BootstrapResponse) {
    (1, BootstrapResponse::Setup { totp_uri: test_uri() })
}

fn code() -> Option<FirstTotpCode> {
    FirstTotpCode::parse(CODE.into())
}

#[test]
fn bootstrap_exchange_keeps_one_stream_and_returns_the_verified_w1_chain() {
    let fixture = Fixture::new();
    let (stream, sent) = script([setup(), (2, fixture.activation())]);
    let output = enroll(stream, fixture.request(), fixture.root.certificate(), |setup| {
        assert_eq!(setup.protected_uri(), test_uri());
        assert_eq!(format!("{setup:?}"), "TotpSetup(..)");
        assert_eq!(format!("{setup:#?}"), "TotpSetup(..)");
        let first_code = code().unwrap();
        assert_eq!(format!("{first_code:?}"), "FirstTotpCode(..)");
        assert_eq!(format!("{first_code:#?}"), "FirstTotpCode(..)");
        Some(first_code)
    })
    .unwrap();
    assert_eq!(output.leaf.as_ref(), fixture.issued.certificate);
    assert_eq!(output.issuer.as_ref(), fixture.issuer.certificate());
    assert_eq!(
        requests(&sent),
        [
            (1, BootstrapRequest::Redeem { device_name: "Test Device".into(), csr: fixture.csr.clone(), password: PASSWORD.into() }),
            (2, BootstrapRequest::ConfirmTotp { code: CODE.into() }),
        ]
    );
}

#[test]
fn refusal_cancel_and_bad_setup_do_not_send_confirmation() {
    let fixture = Fixture::new();
    let (stream, sent) = script([(1, BootstrapResponse::Error { code: 7 })]);
    let error = enroll(stream, fixture.request(), fixture.root.certificate(), |_| panic!("unexpected setup")).unwrap_err();
    assert_eq!(error, EnrollmentError::SetupRefused(7));
    assert_eq!(requests(&sent).len(), 1);

    let (stream, sent) = script([setup()]);
    let error = enroll(stream, fixture.request(), fixture.root.certificate(), |_| None).unwrap_err();
    assert_eq!(error, EnrollmentError::PromptCancelled);
    assert_eq!(requests(&sent).len(), 1);

    let (stream, sent) = script([(1, BootstrapResponse::Setup { totp_uri: "otpauth://totp/lab\u{1b}".into() })]);
    let error = enroll(stream, fixture.request(), fixture.root.certificate(), |_| panic!("unsafe setup was displayed")).unwrap_err();
    assert_eq!(error, EnrollmentError::Setup(ExchangeProblem::InvalidSetupUri));
    assert_eq!(requests(&sent).len(), 1);
    assert!(FirstTotpCode::parse("1234é".into()).is_none());
    assert!(FirstTotpCode::parse("12345".into()).is_none());
}

#[test]
fn lost_or_unrecognized_confirmation_never_retries_and_differs_from_a_refusal() {
    let fixture = Fixture::new();
    for (response, expected) in [
        (None, EnrollmentError::ConfirmationUnknown(ExchangeProblem::Io(io::ErrorKind::UnexpectedEof))),
        (Some((1, fixture.activation())), EnrollmentError::ConfirmationUnknown(ExchangeProblem::UnexpectedReply)),
        (Some((2, BootstrapResponse::Error { code: 11 })), EnrollmentError::ConfirmRefused(11)),
    ] {
        let (stream, sent) = script([setup()].into_iter().chain(response));
        let error = enroll(stream, fixture.request(), fixture.root.certificate(), |_| code()).unwrap_err();
        assert_eq!(error, expected);
        let requests = requests(&sent);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].0, 2);
        assert!(matches!(&requests[1].1, BootstrapRequest::ConfirmTotp { .. }));
    }
}

#[test]
fn rejects_leafs_with_other_keys_untrusted_issuer_and_trailing_der() {
    let fixture = Fixture::new();
    let wrong_spki = KeyPair::generate().unwrap().subject_public_key_info();
    let (stream, _) = script([setup(), (2, fixture.activation())]);
    let request = EnrollmentRequest { expected_spki: &wrong_spki, ..fixture.request() };
    let error = enroll(stream, request, fixture.root.certificate(), |_| code()).unwrap_err();
    assert_eq!(error, EnrollmentError::ActivatedCertificateRejected(CertificateProblem::WrongDeviceKey));

    let other_issuer = fixture.root.create_issuing("Test Issuer", fixture.now_ms).unwrap();
    let wrong_issuer =
        BootstrapResponse::Activated { certificate: fixture.issued.certificate.clone(), issuer_certificate: other_issuer.certificate().to_vec() };
    let (stream, _) = script([setup(), (2, wrong_issuer)]);
    let error = enroll(stream, fixture.request(), fixture.root.certificate(), |_| code()).unwrap_err();
    assert_eq!(error, EnrollmentError::ActivatedCertificateRejected(CertificateProblem::WrongIssuer));

    let wrong_root = Authority::create_root("Test Root", fixture.now_ms).unwrap();
    let (stream, _) = script([setup(), (2, fixture.activation())]);
    let error = enroll(stream, fixture.request(), wrong_root.certificate(), |_| code()).unwrap_err();
    assert_eq!(error, EnrollmentError::ActivatedCertificateRejected(CertificateProblem::WrongIssuer));

    let mut leaf_with_tail = fixture.issued.certificate.clone();
    leaf_with_tail.push(0);
    let malformed = BootstrapResponse::Activated { certificate: leaf_with_tail, issuer_certificate: fixture.issuer.certificate().to_vec() };
    let (stream, _) = script([setup(), (2, malformed)]);
    let error = enroll(stream, fixture.request(), fixture.root.certificate(), |_| code()).unwrap_err();
    assert_eq!(error, EnrollmentError::ActivatedCertificateRejected(CertificateProblem::Malformed));
}

#[test]
fn requires_client_auth_and_refuses_invalid_pin_before_writing() {
    let fixture = Fixture::new();
    let server = fixture.issuer.server_certificate("localhost", fixture.now_ms).unwrap();
    let (_, leaf) = X509Certificate::from_der(&server.chain[0]).unwrap();
    let request = EnrollmentRequest { expected_spki: leaf.public_key().raw, ..fixture.request() };
    let activation = BootstrapResponse::Activated { certificate: server.chain[0].clone(), issuer_certificate: server.chain[1].clone() };
    let (stream, _) = script([setup(), (2, activation)]);
    let error = enroll(stream, request, fixture.root.certificate(), |_| code()).unwrap_err();
    assert_eq!(error, EnrollmentError::ActivatedCertificateRejected(CertificateProblem::ClientAuthentication));

    let (stream, sent) = script([setup(), (2, fixture.activation())]);
    let mut malformed_root = fixture.root.certificate().to_vec();
    malformed_root.push(0);
    assert_eq!(enroll(stream, fixture.request(), &malformed_root, |_| code()).unwrap_err(), EnrollmentError::InvalidTrust);
    assert!(sent.borrow().is_empty());
}
