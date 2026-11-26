//! The app's whole external sign-in, start to finish (SECURITY-DESIGN.md section 9; task T611g).
//!
//! Owns: the order of the steps and what each needs from the one before: ask the server to begin (its issuer, client
//! id, authorization endpoint and nonce), make the PKCE pair and a state value, listen on the loopback, open the system
//! browser at the provider's sign-in page, wait for the redirect, and give the code, the verifier and the redirect URI
//! to the server to finish. Called by: the connection worker (task T611h). Calls: `loopback`, `crewcraft-oidc` for PKCE and the URL.
//!
//! The steps that talk to the server and open the browser are passed in, so the flow is tested without either.
//!
//! `browse` is the browser part alone (from the server's start to the provider's redirect); enrolling through the
//! provider uses it on the bootstrap connection (task T611i).

use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use crewcraft_oidc::{Provider, Request, authorization_url, pkce, random_value};
use zeroize::Zeroizing;

use crate::chat_session::ExternalStart;
use crate::lab_client::LabError;
use crate::loopback::{Loopback, LoopbackError};

/// How long the person has to finish signing in in the browser.
pub const BROWSER_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
pub enum FlowError {
    /// The server has no identity provider (or refused to begin).
    NotOffered,
    /// The server could not be reached, or refused the finish.
    Server(LabError),
    /// The system browser could not be opened.
    Browser(io::ErrorKind),
    /// The redirect did not come back (timed out, or the provider refused).
    Loopback(LoopbackError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowError::NotOffered => f.write_str("this server does not offer sign-in with an organization account"),
            FlowError::Server(e) => write!(f, "the server: {e:?}"),
            FlowError::Browser(kind) => write!(f, "could not open the browser: {kind}"),
            FlowError::Loopback(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FlowError {}

/// What the provider's redirect hands back, for the server to finish with: the code, the PKCE verifier and the exact
/// redirect URI the provider was given. `Debug` shows only the redirect URI.
pub struct Redirect {
    pub code: Zeroizing<String>,
    pub verifier: Zeroizing<String>,
    pub redirect_uri: String,
}

impl fmt::Debug for Redirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect").field("redirect_uri", &self.redirect_uri).finish_non_exhaustive()
    }
}

/// The browser part of the flow (task T611i): make the PKCE pair and a state from two random draws, listen on the
/// loopback, open the browser at the provider's page for `start`, and wait (until `timeout`, or `cancelled`) for the
/// redirect. Errors are `Browser` or `Loopback`.
pub fn browse(
    start: &ExternalStart,
    mut random: impl FnMut() -> [u8; 32],
    open_browser: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<Redirect, FlowError> {
    let pair = pkce(random());
    let verifier = Zeroizing::new(pair.verifier.clone());
    let state = Zeroizing::new(random_value(random()));
    let loopback = Loopback::bind().map_err(FlowError::Loopback)?;
    let redirect_uri = loopback.redirect_uri();
    let provider = Provider {
        issuer: start.issuer.clone(),
        authorization_endpoint: start.authorization_endpoint.clone(),
        token_endpoint: String::new(),
        jwks_uri: String::new(),
    };
    let url = authorization_url(
        &provider,
        &Request { client_id: &start.client_id, redirect_uri: &redirect_uri, state: &state, nonce: &start.nonce, code_challenge: &pair.challenge },
    );
    open_browser(&url).map_err(|e| FlowError::Browser(e.kind()))?;
    let code = loopback.wait_unless(&state, Instant::now() + timeout, cancelled).map_err(FlowError::Loopback)?;
    if cancelled() {
        return Err(FlowError::Loopback(LoopbackError::Cancelled));
    }
    Ok(Redirect { code: Zeroizing::new(code.0), verifier, redirect_uri })
}

/// The two server calls the flow needs. The worker implements it over `ServerEndpoint` with this device.
pub trait ExternalServer {
    type Session;
    fn begin(&self) -> Result<Option<ExternalStart>, LabError>;
    fn finish(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<Self::Session, LabError>;
}

/// Run the flow. `random` supplies fresh random bytes (two draws: the PKCE verifier and the state); `open_browser`
/// opens the URL (`loopback::open_browser` in the app); `timeout` bounds the wait for the browser.
pub fn run<S: ExternalServer>(
    server: &S,
    random: impl FnMut() -> [u8; 32],
    open_browser: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
) -> Result<S::Session, FlowError> {
    run_unless(server, random, open_browser, timeout, &|| false)
}

/// As `run`, but the wait for the browser ends with `Loopback(Cancelled)` as soon as `cancelled` says so (task T611h:
/// the window's Cancel, or the worker stopping). The finish is not started after a cancel.
pub fn run_unless<S: ExternalServer>(
    server: &S,
    random: impl FnMut() -> [u8; 32],
    open_browser: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<S::Session, FlowError> {
    let start = server.begin().map_err(FlowError::Server)?.ok_or(FlowError::NotOffered)?;
    let redirect = browse(&start, random, open_browser, timeout, cancelled)?;
    server.finish(&redirect.code, &redirect.verifier, &redirect.redirect_uri).map_err(FlowError::Server)
}
