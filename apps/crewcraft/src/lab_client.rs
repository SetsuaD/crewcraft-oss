//! Driver for a loopback lab CLI with a caller-provided enrolled device signer. Task T217.

use std::io::{self, BufRead, Read};
use std::net::SocketAddr;
use std::sync::Arc;

use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::message::MAX_BODY;
use crewcraft_proto::signin::{CODE_LEN, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, SignIn};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName};

use crate::chat_session::ChatError;
use crate::connect::{self, Transport};
use crate::signed_in::{SignedInSession, sign_in, valid_room};

const MAX_ROOT_DER: usize = 64 * 1024;

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

/// Results stay in memory. The caller can render approved fields without logging credentials or raw transport errors.
pub enum LabOutcome {
    SignedIn,
    Posted { cursor: u64 },
    Synced { head: u64, lines: Vec<Shown> },
}

/// An authenticated lab connection: the same session type a server endpoint opens.
pub type LabSession = SignedInSession;

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
        let session = sign_in(stream, &credentials, "crewcraft-lab")?;
        Ok((session, message))
    }

    pub(crate) fn connect(&self, device: Arc<dyn ResolvesClientCert>) -> Result<Transport, LabError> {
        Ok(connect::connect(&[self.address], &self.server_name, &self.roots, device)?.transport)
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
