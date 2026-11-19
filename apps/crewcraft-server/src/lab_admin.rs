//! Operator commands for a lab installation, as typed operations a command line can wire later: set up a NEW state
//! directory (`init`), open an existing one with its pinned root (`reopen`), and invite a person offline (`invite`).
//!
//! Owns: the order "persist, then show" for invitations (the one-time enrollment code is handed to a caller-provided
//! `ProtectedDisplay` only after the account store has durably recorded the invitation's public bootstrap key; a
//! refused write never shows a code, and a display that fails withdraws the invitation), the address
//! canonicalisation (`normalize_email`) and the bounded invitation lifetime.
//! Does not own: the installation files (`lab_installation`), the store (`crewcraft_server_core::account_store`), the
//! code format (`crewcraft_enroll`), normal online start, the listener.
//!
//! Secrets: the code exists only in memory between its creation and the display call. Nothing here prints, logs or
//! returns it; every type's `Debug` leaves it out. What `init` and `invite` return is public: the root certificate and
//! its SHA-256 pin, and the invitation's email, public bootstrap key and expiry.

use std::fmt;
use std::path::Path;

use crewcraft_accounts::identity::normalize_email;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_server_core::account_store::{AccountStore, AppendLog, StoreError};
use crewcraft_server_core::invites::Invite;
use rand_core::{OsRng, RngCore};

use crate::lab_installation::{InstallationError, LabInstallation};

/// How long an invitation stays usable when the operator does not say.
pub const DEFAULT_INVITE_TTL_MS: u64 = 72 * 60 * 60 * 1000;
/// The longest lifetime an operator may give an invitation.
pub const MAX_INVITE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug)]
pub enum AdminError {
    Installation(InstallationError),
    /// The address is not an email address `normalize_email` accepts.
    BadEmail,
    /// A lifetime of zero, or longer than `MAX_INVITE_TTL_MS`.
    BadTtl,
    /// The operating system's random source failed; no code was made.
    Random,
    /// The store refused to record the invitation; no code was shown.
    Store(StoreError),
    /// The code was recorded but could not be shown. `withdrawn` says whether the invitation was then removed again (if
    /// not, it expires on its own and an operator should revoke it).
    DisplayFailed {
        withdrawn: bool,
    },
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminError::Installation(e) => write!(f, "lab installation: {e:?}"),
            AdminError::BadEmail => f.write_str("not an email address"),
            AdminError::BadTtl => write!(f, "an invitation lasts between 1 ms and {MAX_INVITE_TTL_MS} ms"),
            AdminError::Random => f.write_str("the system random source failed"),
            AdminError::Store(e) => write!(f, "the account store refused the invitation: {e}"),
            AdminError::DisplayFailed { withdrawn: true } => f.write_str("the code could not be shown; the invitation was withdrawn"),
            AdminError::DisplayFailed { withdrawn: false } => f.write_str("the code could not be shown and the invitation could not be withdrawn"),
        }
    }
}

impl std::error::Error for AdminError {}

/// The installation's root certificate: what clients pin. Public.
#[derive(Clone, PartialEq, Eq)]
pub struct LabRoot {
    pub certificate_der: Vec<u8>,
    /// SHA-256 of `certificate_der`; `reopen` takes it.
    pub sha256: [u8; 32],
}

impl fmt::Debug for LabRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LabRoot {{ sha256: {}, der: {} bytes }}", hex(&self.sha256), self.certificate_der.len())
    }
}

/// Set up a NEW lab state in a directory that does not exist yet, and report its root. Never opens existing state.
pub fn init(path: &Path, now_ms: u64) -> Result<(LabInstallation, LabRoot), AdminError> {
    let installation = LabInstallation::initialize(path, now_ms).map_err(AdminError::Installation)?;
    let root = LabRoot { certificate_der: installation.issuer.root_certificate().to_vec(), sha256: installation.issuer.root_fingerprint() };
    Ok((installation, root))
}

/// Open existing lab state whose root must have this SHA-256 (from `init`). Never creates state.
pub fn reopen(path: &Path, root_sha256: [u8; 32], now_ms: u64) -> Result<LabInstallation, AdminError> {
    LabInstallation::open(path, root_sha256, now_ms).map_err(AdminError::Installation)
}

/// What a `ProtectedDisplay` is given: the person, the one-time code and when it stops working. `Debug` leaves the code
/// out.
pub struct IssuedCode<'a> {
    email: &'a str,
    code: &'a str,
    expires_ms: u64,
}

impl IssuedCode<'_> {
    pub fn email(&self) -> &str {
        self.email
    }
    /// The one-time enrollment code. Show it to the operator only; never log it.
    pub fn code(&self) -> &str {
        self.code
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

impl fmt::Debug for IssuedCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuedCode {{ email: {:?}, expires_ms: {}, code: .. }}", self.email, self.expires_ms)
    }
}

/// The display could not show the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayFailed;

/// Where an invitation's one-time code is shown: a channel only the operator can read (their own terminal, or a file
/// created for them alone). There is deliberately no default implementation that writes to standard output or a log.
pub trait ProtectedDisplay {
    fn show(&mut self, issued: &IssuedCode<'_>) -> Result<(), DisplayFailed>;
}

/// What `invite` returns. Public values only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteReceipt {
    /// The canonical address the invitation was recorded for.
    pub email: String,
    /// The public key the code derives; the store keeps only this.
    pub bootstrap_pub: [u8; 32],
    pub expires_ms: u64,
}

/// Invite `email` offline: make a fresh code, record ONLY its public bootstrap key durably, then show the code through
/// `display`. A new invitation for an address that already has one replaces it (the old code stops working).
/// `ttl_ms` defaults to `DEFAULT_INVITE_TTL_MS` and may not exceed `MAX_INVITE_TTL_MS`.
pub fn invite<L: AppendLog>(
    accounts: &mut AccountStore<L>,
    email: &str,
    ttl_ms: Option<u64>,
    now_ms: u64,
    display: &mut dyn ProtectedDisplay,
) -> Result<InviteReceipt, AdminError> {
    let email = normalize_email(email).map_err(|_| AdminError::BadEmail)?;
    let ttl = ttl_ms.unwrap_or(DEFAULT_INVITE_TTL_MS);
    if ttl == 0 || ttl > MAX_INVITE_TTL_MS {
        return Err(AdminError::BadTtl);
    }
    let expires_ms = now_ms.checked_add(ttl).ok_or(AdminError::BadTtl)?;

    let mut secret = [0u8; 20];
    OsRng.try_fill_bytes(&mut secret).map_err(|_| AdminError::Random)?;
    let code = EnrollmentCode::from_bytes(secret);
    let bootstrap_pub = code.bootstrap_public_key();

    // Persist first. If the store refuses, the code is dropped here and never shown.
    accounts.issue_invite(Invite { email: email.clone(), bootstrap_pub, expires_ms }, now_ms).map_err(AdminError::Store)?;

    let text = code.to_display();
    let shown = display.show(&IssuedCode { email: &email, code: &text, expires_ms });
    drop(text);
    if shown.is_err() {
        // Nobody saw the code: take the invitation back so no usable, unseen code is left behind.
        let withdrawn = matches!(accounts.revoke_invite(&bootstrap_pub), Ok(true));
        return Err(AdminError::DisplayFailed { withdrawn });
    }
    Ok(InviteReceipt { email, bootstrap_pub, expires_ms })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
