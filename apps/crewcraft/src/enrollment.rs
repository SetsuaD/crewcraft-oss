//! Enrollment off the window's thread: generate the device key, redeem the invitation, show the authenticator setup,
//! wait for the first code and hand back the record to save. Task T304.
//!
//! Owns: the enrollment thread and its two-step conversation with the window. Called by the window. Calls
//! `device::NewDevice::enroll`.
//!
//! `start_external` enrolls through the server's identity provider instead (task T611i): the provider's page opens in
//! the system browser (`EnrollmentEvent::WaitingForBrowser`), and `cancel` or dropping the handle ends the wait.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crewcraft_enroll::EnrollmentCode;
use zeroize::Zeroizing;

use crate::bootstrap_transport::{EXTERNAL_BROWSER_TIMEOUT, MAX_CONFIRMATION_WINDOW, MAX_EXTERNAL_CONFIRMATION_WINDOW};
use crate::device::{DeviceError, NewDevice, StoredDevice};
use crate::enroll_client::{FirstTotpCode, browser_problem};
use crate::external_flow::browse;
use crate::worker::Browser;
use crate::hardware_key::HardwareKeys;
use crate::server_endpoint::ServerEndpoint;

/// The authenticator setup link (`otpauth://...`). It holds the person's TOTP secret: show it only as a QR code or a
/// setup key in a protected view, and never log it. `Debug` prints nothing of it, and it is wiped on drop.
pub struct AuthenticatorSetup(Zeroizing<String>);

impl AuthenticatorSetup {
    pub fn otpauth_uri(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthenticatorSetup {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("AuthenticatorSetup(..)")
    }
}

/// What the enrollment thread tells the window.
#[derive(Debug)]
pub enum EnrollmentEvent {
    /// Show this to the person and ask for the first code; answer with `Enrollment::confirm`.
    AuthenticatorSetup(AuthenticatorSetup),
    /// An enrollment through the provider opened its sign-in page in the browser (task T611i): the person finishes
    /// there, or cancels with `Enrollment::cancel`.
    WaitingForBrowser,
    /// Done. Save the record with `device_store::DeviceStore::save`.
    Enrolled(StoredDevice),
    /// Enrollment stopped. `DeviceError::Enrollment(EnrollmentError::ConfirmationUnknown(_))` means the server may
    /// have activated the device; an administrator must recover it.
    Failed(DeviceError),
}

/// Where a new device key is made.
#[derive(Clone)]
pub enum KeySource {
    /// In this process, and kept in the device record (the desktop; the record is sealed there).
    Software,
    /// Inside a hardware key store, under `alias` (task T403); the record only names it.
    Hardware { keys: Arc<dyn HardwareKeys>, alias: String },
}

/// Fresh random bytes for the PKCE verifier and the state.
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    bytes
}

impl fmt::Debug for KeySource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Software => output.write_str("Software"),
            Self::Hardware { alias, .. } => output.debug_struct("Hardware").field("alias", alias).finish_non_exhaustive(),
        }
    }
}

/// The window's handle on one enrollment. Dropping it cancels a pending confirmation. The thread is not joined: it
/// ends by itself within the confirmation window at the latest.
pub struct Enrollment {
    codes: Sender<FirstTotpCode>,
    /// Ends the wait for the browser in an enrollment through the provider (task T611i).
    cancel: Arc<AtomicBool>,
}

impl Drop for Enrollment {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("Enrollment { .. }")
    }
}

impl Enrollment {
    /// Start enrolling at `endpoint` with the invitation `code`. `password` is the account password the person sets
    /// (or their mailbox password, by the server's configuration). `wake` is called after each event.
    pub fn start(
        endpoint: ServerEndpoint,
        code: EnrollmentCode,
        device_name: &str,
        password: &str,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<EnrollmentEvent>)> {
        Self::start_with_window(endpoint, code, device_name, password, MAX_CONFIRMATION_WINDOW, wake)
    }

    /// As `start`, with a shorter time for the whole exchange, including the person typing the first code.
    pub fn start_with_window(
        endpoint: ServerEndpoint,
        code: EnrollmentCode,
        device_name: &str,
        password: &str,
        confirmation_window: Duration,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<EnrollmentEvent>)> {
        Self::start_with_key(endpoint, code, device_name, password, confirmation_window, KeySource::Software, wake)
    }

    /// As `start_with_window`, with the device key made where `key` says.
    pub fn start_with_key(
        endpoint: ServerEndpoint,
        code: EnrollmentCode,
        device_name: &str,
        password: &str,
        confirmation_window: Duration,
        key: KeySource,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<EnrollmentEvent>)> {
        let (codes, code_queue) = mpsc::channel::<FirstTotpCode>();
        let (events, event_queue) = mpsc::channel();
        let device_name = device_name.to_owned();
        let password = Zeroizing::new(password.to_owned());
        thread::Builder::new().name("crewcraft-enrollment".into()).spawn(move || {
            let emit = |event| {
                if events.send(event).is_ok() {
                    wake();
                }
            };
            let generated = match &key {
                KeySource::Software => NewDevice::generate(),
                KeySource::Hardware { keys, alias } => NewDevice::generate_in(keys.clone(), alias),
            };
            let result = generated.and_then(|device| {
                device.enroll(&endpoint, &code, confirmation_window, &device_name, &password, |setup, deadline| {
                    emit(EnrollmentEvent::AuthenticatorSetup(AuthenticatorSetup(Zeroizing::new(setup.protected_uri().to_owned()))));
                    code_queue.recv_timeout(deadline.saturating_duration_since(Instant::now())).ok()
                })
            });
            emit(match result {
                Ok(device) => EnrollmentEvent::Enrolled(device),
                Err(error) => EnrollmentEvent::Failed(error),
            });
        })?;
        Ok((Self { codes, cancel: Arc::new(AtomicBool::new(false)) }, event_queue))
    }

    /// Enroll at `endpoint` through the server's identity provider (task T611i): the device key from `key`, the
    /// provider's sign-in page opened with `browser`, and the whole exchange within `MAX_EXTERNAL_CONFIRMATION_WINDOW`.
    pub fn start_external(
        endpoint: ServerEndpoint,
        code: EnrollmentCode,
        device_name: &str,
        key: KeySource,
        browser: Browser,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<EnrollmentEvent>)> {
        let (codes, _) = mpsc::channel::<FirstTotpCode>();
        let (events, event_queue) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancelled = cancel.clone();
        let device_name = device_name.to_owned();
        thread::Builder::new().name("crewcraft-enrollment".into()).spawn(move || {
            let emit = |event| {
                if events.send(event).is_ok() {
                    wake();
                }
            };
            let generated = match &key {
                KeySource::Software => NewDevice::generate(),
                KeySource::Hardware { keys, alias } => NewDevice::generate_in(keys.clone(), alias),
            };
            let result = generated.and_then(|device| {
                device.enroll_external(&endpoint, &code, MAX_EXTERNAL_CONFIRMATION_WINDOW, &device_name, |start, deadline| {
                    let open = |url: &str| {
                        browser(url)?;
                        emit(EnrollmentEvent::WaitingForBrowser);
                        Ok(())
                    };
                    let timeout = deadline.saturating_duration_since(Instant::now()).min(EXTERNAL_BROWSER_TIMEOUT);
                    browse(start, random_bytes, open, timeout, &|| cancelled.load(Ordering::Acquire)).map_err(|error| browser_problem(&error))
                })
            });
            emit(match result {
                Ok(device) => EnrollmentEvent::Enrolled(device),
                Err(error) => EnrollmentEvent::Failed(error),
            });
        })?;
        Ok((Self { codes, cancel }, event_queue))
    }

    /// Stop waiting for the browser in an enrollment through the provider (task T611i): the enrollment reports
    /// `Failed` with `BrowserProblem::Cancelled`. Nothing happens for any other enrollment.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// Answer `AuthenticatorSetup` with the first code from the authenticator. False if the code is not six digits
    /// (ask again) or the enrollment already ended.
    pub fn confirm(&self, code: &str) -> bool {
        FirstTotpCode::parse(code.to_owned()).is_some_and(|code| self.codes.send(code).is_ok())
    }
}
