//! Driver for a loopback lab CLI with a caller-provided enrolled device signer. Task T217.

use std::fmt;
use std::io::{self, BufRead, Read};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::message::{MAX_BODY, MAX_NAME};
use crewcraft_proto::signin::{CODE_LEN, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, SignIn};
use crewcraft_tls::DeadlineSocket;
use rustls::client::{ResolvesClientCert, Resumption};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, SignatureScheme, StreamOwned};

use crate::chat_session::{ChatError, ChatSession};

const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);
const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ROOT_DER: usize = 64 * 1024;

type Transport = StreamOwned<ClientConnection, DeadlineSocket>;
type SetDeadline = fn(&mut Transport, Instant);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabError {
    Usage,
    Address,
    Trust,
    Device,
    Connect(io::ErrorKind),
    Handshake,
    Input,
    Chat(ChatError),
    MissingTimeline,
}

/// Parse only the public command tail of the CLI. All credential and message bytes come from protected input.
#[derive(Clone, Copy)]
pub enum LabCommand<'a> {
    SignIn,
    Post { room: &'a str },
    Sync { room: &'a str },
}

impl<'a> LabCommand<'a> {
    pub fn parse(words: &[&'a str]) -> Result<Self, LabError> {
        match words {
            ["sign-in"] => Ok(Self::SignIn),
            ["post", room] if valid_room(room) => Ok(Self::Post { room }),
            ["sync", room] if valid_room(room) => Ok(Self::Sync { room }),
            _ => Err(LabError::Usage),
        }
    }
}

fn valid_room(room: &str) -> bool {
    !room.is_empty() && room.len() <= MAX_NAME && room.chars().all(|ch| !ch.is_control() && !ch.is_whitespace())
}

/// Results stay in memory. The caller can render approved fields without logging credentials or raw transport errors.
pub enum LabOutcome {
    SignedIn,
    Posted { cursor: u64 },
    Synced { head: u64, lines: Vec<Shown> },
}

/// An authenticated connection. Dropping it ends the local session. Commands use the same connection
/// and the same room views until the connection closes.
pub struct LabSession {
    chat: ChatSession<Transport, SetDeadline>,
}

impl LabSession {
    /// `text` comes from the caller's protected input and is sent only on this connection.
    pub fn post(&mut self, room: &str, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.post(room, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn edit(&mut self, room: &str, target: u64, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.edit(room, target, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn delete(&mut self, room: &str, target: u64) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.delete(room, target, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn sync(&mut self, room: &str) -> Result<(u64, Vec<Shown>), LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        let head = self.chat.sync(room, false, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)?;
        let lines = self.chat.view(room).ok_or(LabError::MissingTimeline)?.shown();
        Ok((head, lines))
    }
}

pub struct LabEndpoint {
    address: SocketAddr,
    server_name: ServerName<'static>,
    roots: RootCertStore,
}

impl LabEndpoint {
    /// The expected name and fingerprint are supplied by a trusted operator or invitation.
    /// No DNS lookup, platform root store, or fallback trust is used.
    pub fn new(address: &str, expected_server_name: &str, expected_root: RootFingerprint, root_der: &[u8]) -> Result<Self, LabError> {
        let address: SocketAddr = address.parse().map_err(|_| LabError::Address)?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(LabError::Address);
        }
        let server_name = ServerName::try_from(expected_server_name.to_owned()).map_err(|_| LabError::Trust)?;
        if root_der.is_empty() || root_der.len() > MAX_ROOT_DER || !expected_root.matches(root_der) {
            return Err(LabError::Trust);
        }
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root_der.to_vec())).map_err(|_| LabError::Trust)?;
        Ok(Self { address, server_name, roots })
    }

    /// Sign in once over verified mutual TLS. Read an EOF-terminated record of three prepared,
    /// non-echoing lines for email, password and current TOTP. No credential or token is returned.
    pub fn open_authenticated(&self, device: Arc<dyn ResolvesClientCert>, protected_input: &mut impl BufRead) -> Result<LabSession, LabError> {
        let (session, _) = self.open(device, protected_input, false)?;
        Ok(session)
    }

    /// Run one operation. The caller provides the registered device's certificate resolver and prepared, non-echoing
    /// input. Supply LF or CRLF lines for email, password, and current TOTP, plus one message line for `post`.
    /// The input must end after the last line.
    /// The driver reads these only after verifying TLS and selecting a client certificate.
    pub fn run(
        &self,
        device: Arc<dyn ResolvesClientCert>,
        command: LabCommand<'_>,
        protected_input: &mut impl BufRead,
    ) -> Result<LabOutcome, LabError> {
        if let LabCommand::Post { room } | LabCommand::Sync { room } = command
            && !valid_room(room)
        {
            return Err(LabError::Usage);
        }
        let (mut session, message) = self.open(device, protected_input, matches!(command, LabCommand::Post { .. }))?;
        match command {
            LabCommand::SignIn => Ok(LabOutcome::SignedIn),
            LabCommand::Post { room } => {
                let cursor = session.post(room, &message.ok_or(LabError::Input)?)?;
                Ok(LabOutcome::Posted { cursor })
            }
            LabCommand::Sync { room } => {
                let (head, lines) = session.sync(room)?;
                Ok(LabOutcome::Synced { head, lines })
            }
        }
    }

    fn open(
        &self,
        device: Arc<dyn ResolvesClientCert>,
        protected_input: &mut impl BufRead,
        read_message: bool,
    ) -> Result<(LabSession, Option<String>), LabError> {
        let stream = self.connect(device)?;
        let email = read_line(protected_input, MAX_EMAIL_BYTES)?;
        let password = read_line(protected_input, MAX_PASSWORD_BYTES)?;
        let code = read_line(protected_input, CODE_LEN)?;
        if email.is_empty() || password.is_empty() || code.len() != CODE_LEN || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(LabError::Input);
        }
        let message = if read_message { Some(read_line(protected_input, MAX_BODY)?) } else { None };
        if !protected_input.fill_buf().map_err(|_| LabError::Input)?.is_empty() {
            return Err(LabError::Input);
        }
        let credentials = SignIn { email: &email, password: &password, code: &code };
        let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "crewcraft-lab".into() };
        let settings = Settings::new(&email);
        let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let chat = ChatSession::connect(stream, set_deadline, &credentials, hello, settings, FRAME_TIMEOUT, deadline).map_err(LabError::Chat)?;
        Ok((LabSession { chat }, message))
    }

    pub(crate) fn connect(&self, device: Arc<dyn ResolvesClientCert>) -> Result<Transport, LabError> {
        if !device.has_certs() || device.only_raw_public_keys() {
            return Err(LabError::Device);
        }
        let resolver = Arc::new(SelectedDevice { device, selected: AtomicBool::new(false) });
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| LabError::Trust)?
            .with_root_certificates(self.roots.clone())
            .with_client_cert_resolver(resolver.clone());
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        let mut connection = ClientConnection::new(Arc::new(config), self.server_name.clone()).map_err(|_| LabError::Trust)?;
        let tcp = TcpStream::connect_timeout(&self.address, TCP_TIMEOUT).map_err(|error| LabError::Connect(error.kind()))?;
        let mut socket = DeadlineSocket::new(tcp, Instant::now() + TLS_TIMEOUT);
        connection.complete_io(&mut socket).map_err(|_| LabError::Handshake)?;
        if connection.is_handshaking() || connection.wants_write() {
            return Err(LabError::Handshake);
        }
        if !resolver.selected.load(Ordering::Relaxed) {
            return Err(LabError::Device);
        }
        Ok(StreamOwned::new(connection, socket))
    }
}

struct SelectedDevice {
    device: Arc<dyn ResolvesClientCert>,
    selected: AtomicBool,
}

impl fmt::Debug for SelectedDevice {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("SelectedDevice { .. }")
    }
}

impl ResolvesClientCert for SelectedDevice {
    fn resolve(&self, root_hint_subjects: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let selected =
            self.device.resolve(root_hint_subjects, schemes).filter(|key| !key.cert.is_empty() && key.key.choose_scheme(schemes).is_some());
        self.selected.store(selected.is_some(), Ordering::Relaxed);
        selected
    }

    fn has_certs(&self) -> bool {
        self.device.has_certs()
    }
}

fn read_line(input: &mut impl BufRead, max: usize) -> Result<String, LabError> {
    // Two extra bytes allow for CRLF without allocating or reading past the field's bound.
    let mut bytes = Vec::new();
    Read::take(input, max as u64 + 2).read_until(b'\n', &mut bytes).map_err(|_| LabError::Input)?;
    if bytes.pop() != Some(b'\n') {
        return Err(LabError::Input);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.truncate(bytes.len() - 1);
    }
    if bytes.len() > max || bytes.iter().any(|&byte| matches!(byte, b'\r' | 0)) {
        return Err(LabError::Input);
    }
    String::from_utf8(bytes).map_err(|_| LabError::Input)
}
