//! Sign-in through an external OpenID Connect provider, on the server (SECURITY-DESIGN.md section 9; task T611e).
//!
//! Owns: the nonce for each device's pending external sign-in (one at a time per device, 10 minutes, used once), the
//! finish step (a loopback redirect URI only; the code exchanged at the provider; the ID token verified with
//! `crewcraft_oidc` against that device's nonce, fetching the provider's keys once more when a token names an unknown
//! key; the provider identity bound to this device's own person; the external authorizer asked and its decision
//! stored durably before anything is granted; then an ordinary session for this device), the HTTPS-backed provider
//! and authorizer, and reading an authorizer's answer (docs/AUTHORIZER.md). Called by: `stored_device_auth`. Calls:
//! `crewcraft-oidc`, `crewcraft-authz`, `crewcraft-https`, the account store.
//!
//! Every refusal is the same `Refused` on the wire; `Refusal` says why, for the server's own log and the tests.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crewcraft_authz::{Access, Answer, Capabilities, Capability, Record, commit_decision};
use crewcraft_https::{Client, Response};
use crewcraft_oidc::{Expected, Identity, Key, Provider as Discovery, parse_discovery, parse_jwks, verify_id_token};
use crewcraft_server_core::account_store::AccountStore;
use serde_json::{Value, json};

/// How long a begun external sign-in may take, in milliseconds.
pub const PENDING_MS: u64 = 10 * 60 * 1000;
/// The least time between two key fetches prompted by an unknown key id, in milliseconds.
pub const KEY_REFRESH_MS: u64 = 60 * 1000;

/// Why an external sign-in was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No begun sign-in for this device, or it expired or was already used.
    NoPendingSignIn,
    /// The redirect URI is not a loopback address.
    NotLoopback,
    /// The provider could not be reached or did not answer properly.
    Provider(String),
    /// The ID token failed a check.
    Token(crewcraft_oidc::Error),
    /// The provider identity is bound to no person, or to another person than this device's.
    NotThisPerson,
    /// The authorizer did not allow it (or could not be asked, or the decision could not be stored).
    NotAuthorized(String),
    /// The account store refused the session.
    Store,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NoPendingSignIn => f.write_str("no pending external sign-in for this device"),
            Refusal::NotLoopback => f.write_str("the redirect URI is not a loopback address"),
            Refusal::Provider(why) => write!(f, "identity provider: {why}"),
            Refusal::Token(e) => write!(f, "ID token: {e}"),
            Refusal::NotThisPerson => f.write_str("the provider identity is not this device's person"),
            Refusal::NotAuthorized(why) => write!(f, "not authorized: {why}"),
            Refusal::Store => f.write_str("the account store refused the session"),
        }
    }
}

/// What the app needs to open the provider's sign-in page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub nonce: String,
}

/// The identity provider, as the server uses it. `HttpsProvider` in production; tests use their own.
pub trait Provider: Send + Sync {
    fn issuer(&self) -> &str;
    fn client_id(&self) -> &str;
    fn authorization_endpoint(&self) -> Result<String, String>;
    /// The provider's signing keys; `refresh` fetches them again.
    fn keys(&self, refresh: bool) -> Result<Vec<Key>, String>;
    /// Exchange a code for the provider's ID token.
    fn exchange(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<String, String>;
}

/// The external authorizer. `HttpsAuthorizer` in production; tests use their own.
pub trait Authorizer: Send + Sync {
    /// Ask about `identity`; `purpose` is `sign-in` or `recheck`. Never fails: no proper answer is `Answer::NoAnswer`.
    fn ask(&self, identity: &Identity, purpose: &str) -> Answer;
}

/// External sign-in for one server: its provider, optional authorizer, rules, and the pending nonces.
pub struct ExternalSignIn {
    provider: Arc<dyn Provider>,
    authorizer: Option<Arc<dyn Authorizer>>,
    require_mfa: bool,
    pending: Mutex<HashMap<u64, (String, u64)>>,
    last_key_refresh_ms: Mutex<Option<u64>>,
}

impl fmt::Debug for ExternalSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The pending nonces are never shown.
        f.debug_struct("ExternalSignIn")
            .field("issuer", &self.provider.issuer())
            .field("authorizer", &self.authorizer.is_some())
            .field("require_mfa", &self.require_mfa)
            .finish_non_exhaustive()
    }
}

impl ExternalSignIn {
    pub fn new(provider: Arc<dyn Provider>, authorizer: Option<Arc<dyn Authorizer>>, require_mfa: bool) -> Self {
        Self { provider, authorizer, require_mfa, pending: Mutex::new(HashMap::new()), last_key_refresh_ms: Mutex::new(None) }
    }

    /// Begin a sign-in for `device_id`: a fresh nonce from `random` (replacing any earlier one for this device).
    pub fn begin(&self, device_id: u64, random: [u8; 32], now_ms: u64) -> Result<Start, Refusal> {
        let authorization_endpoint = self.provider.authorization_endpoint().map_err(Refusal::Provider)?;
        let nonce = crewcraft_oidc::random_value(random);
        let mut pending = self.pending.lock().map_err(|_| Refusal::Store)?;
        pending.retain(|_, (_, expires)| *expires > now_ms);
        pending.insert(device_id, (nonce.clone(), now_ms + PENDING_MS));
        Ok(Start { issuer: self.provider.issuer().to_owned(), client_id: self.provider.client_id().to_owned(), authorization_endpoint, nonce })
    }

    /// Finish the sign-in begun on `device_id`, whose person is `user`, and return the new session token.
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        &self,
        store: &mut AccountStore,
        user: &str,
        device_id: u64,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        random: [u8; 32],
        now_ms: u64,
    ) -> Result<String, Refusal> {
        // The nonce is taken out first, so it is used once whatever happens next.
        let nonce = {
            let mut pending = self.pending.lock().map_err(|_| Refusal::Store)?;
            match pending.remove(&device_id) {
                Some((nonce, expires)) if expires > now_ms => nonce,
                _ => return Err(Refusal::NoPendingSignIn),
            }
        };
        if !is_loopback(redirect_uri) {
            return Err(Refusal::NotLoopback);
        }
        let token = self.provider.exchange(code, verifier, redirect_uri).map_err(Refusal::Provider)?;
        let expected = Expected {
            issuer: self.provider.issuer(),
            client_id: self.provider.client_id(),
            nonce: &nonce,
            now: now_ms / 1000,
            require_mfa: self.require_mfa,
        };
        let keys = self.provider.keys(false).map_err(Refusal::Provider)?;
        let identity = match verify_id_token(&token, &keys, &expected) {
            Err(crewcraft_oidc::Error::UnknownKey) if self.may_refresh_keys(now_ms) => {
                let keys = self.provider.keys(true).map_err(Refusal::Provider)?;
                verify_id_token(&token, &keys, &expected).map_err(Refusal::Token)?
            }
            other => other.map_err(Refusal::Token)?,
        };
        if store.person_for_external(&identity.issuer, &identity.subject) != Some(user) {
            return Err(Refusal::NotThisPerson);
        }
        if let Some(authorizer) = &self.authorizer {
            let answer = authorizer.ask(&identity, "sign-in");
            let record = store.authorization(user).cloned().unwrap_or_default();
            let (next, access) = record.sign_in(&answer, now_ms / 1000);
            match commit_decision(store, user, &next, access) {
                Access::Allowed(caps) if caps.has(Capability::Use) => {}
                Access::Allowed(_) => return Err(Refusal::NotAuthorized("no use".into())),
                Access::Refused(why) => return Err(Refusal::NotAuthorized(why.to_string())),
            }
        }
        store.create_session(random, user, device_id, now_ms).map_err(|_| Refusal::Store)
    }

    fn may_refresh_keys(&self, now_ms: u64) -> bool {
        let Ok(mut last) = self.last_key_refresh_ms.lock() else { return false };
        if last.is_some_and(|at| now_ms < at + KEY_REFRESH_MS) {
            return false;
        }
        *last = Some(now_ms);
        true
    }
}

/// A loopback redirect URI (RFC 8252 section 7.3): `http://127.0.0.1:<port>/...` or `http://[::1]:<port>/...`.
pub fn is_loopback(uri: &str) -> bool {
    let rest = match uri.strip_prefix("http://127.0.0.1:").or_else(|| uri.strip_prefix("http://[::1]:")) {
        Some(rest) => rest,
        None => return false,
    };
    let (port, path) = rest.split_once('/').unwrap_or((rest, ""));
    port.parse::<u16>().is_ok_and(|p| p != 0) && !path.contains(['@', ' ', '#']) && uri.bytes().all(|b| b.is_ascii_graphic())
}

/// An authorizer's answer as CrewCraft reads it (docs/AUTHORIZER.md): anything not well-formed is `NoAnswer`.
pub fn parse_answer(status: u16, body: &[u8]) -> Answer {
    if status != 200 {
        return Answer::NoAnswer;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(body) else { return Answer::NoAnswer };
    if doc.get("api").and_then(Value::as_u64) != Some(1) {
        return Answer::NoAnswer;
    }
    let Some(revision) = doc.get("revision").and_then(Value::as_u64) else { return Answer::NoAnswer };
    match doc.get("decision").and_then(Value::as_str) {
        Some("allow") => {
            let Some(names) = doc.get("capabilities").and_then(Value::as_array) else { return Answer::NoAnswer };
            let capabilities = Capabilities::from_names(names.iter().filter_map(Value::as_str));
            let recheck_after_secs = match doc.get("recheck_after_seconds") {
                None => None,
                Some(v) => match v.as_u64() {
                    Some(secs) => Some(secs),
                    None => return Answer::NoAnswer,
                },
            };
            Answer::Allow { capabilities, revision, recheck_after_secs }
        }
        Some("deny") => Answer::Deny { revision },
        _ => Answer::NoAnswer,
    }
}

/// The request body for an authorizer (docs/AUTHORIZER.md).
pub fn authorize_request(identity: &Identity, purpose: &str) -> Vec<u8> {
    json!({"api": 1, "purpose": purpose, "identity": {"issuer": identity.issuer, "subject": identity.subject, "email": identity.email}})
        .to_string()
        .into_bytes()
}

/// An authorizer reached over HTTPS (`crewcraft-https`), usually with a client certificate.
pub struct HttpsAuthorizer {
    client: Client,
    url: String,
}

impl HttpsAuthorizer {
    /// `base` is the authorizer's base URL; requests go to `{base}/v1/authorize`.
    pub fn new(client: Client, base: &str) -> Self {
        Self { client, url: format!("{}/v1/authorize", base.trim_end_matches('/')) }
    }
}

impl Authorizer for HttpsAuthorizer {
    fn ask(&self, identity: &Identity, purpose: &str) -> Answer {
        match self.client.post(&self.url, "application/json", &authorize_request(identity, purpose)) {
            Ok(Response { status, body, .. }) => parse_answer(status, &body),
            Err(_) => Answer::NoAnswer,
        }
    }
}

/// A provider reached over HTTPS: discovery and keys fetched and cached; the code exchanged as a public client (PKCE,
/// no client secret).
pub struct HttpsProvider {
    client: Client,
    issuer: String,
    client_id: String,
    discovery: Mutex<Option<Discovery>>,
    keys: Mutex<Option<Vec<Key>>>,
}

impl HttpsProvider {
    pub fn new(client: Client, issuer: &str, client_id: &str) -> Self {
        Self { client, issuer: issuer.to_owned(), client_id: client_id.to_owned(), discovery: Mutex::new(None), keys: Mutex::new(None) }
    }

    fn discovery(&self) -> Result<Discovery, String> {
        let mut cached = self.discovery.lock().map_err(|_| "lock".to_owned())?;
        if let Some(found) = cached.as_ref() {
            return Ok(found.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer.trim_end_matches('/'));
        let body = self.client.get(&url).and_then(Response::ok).map_err(|e| e.to_string())?;
        let found = parse_discovery(&body, &self.issuer).map_err(|e| e.to_string())?;
        *cached = Some(found.clone());
        Ok(found)
    }
}

impl Provider for HttpsProvider {
    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn authorization_endpoint(&self) -> Result<String, String> {
        self.discovery().map(|d| d.authorization_endpoint)
    }

    fn keys(&self, refresh: bool) -> Result<Vec<Key>, String> {
        let mut cached = self.keys.lock().map_err(|_| "lock".to_owned())?;
        if let (false, Some(keys)) = (refresh, cached.as_ref()) {
            return Ok(keys.clone());
        }
        let jwks_uri = self.discovery()?.jwks_uri;
        let body = self.client.get(&jwks_uri).and_then(Response::ok).map_err(|e| e.to_string())?;
        let keys = parse_jwks(&body).map_err(|e| e.to_string())?;
        *cached = Some(keys.clone());
        Ok(keys)
    }

    fn exchange(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<String, String> {
        let token_endpoint = self.discovery()?.token_endpoint;
        let form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            form_encode(code),
            form_encode(redirect_uri),
            form_encode(&self.client_id),
            form_encode(verifier)
        );
        let answer = self.client.post(&token_endpoint, "application/x-www-form-urlencoded", form.as_bytes()).map_err(|e| e.to_string())?;
        let body = answer.ok().map_err(|e| e.to_string())?;
        let doc: Value = serde_json::from_slice(&body).map_err(|_| "token answer is not JSON".to_owned())?;
        doc.get("id_token").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| "token answer has no id_token".to_owned())
    }
}

fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The authorization state a re-check starts from: the stored record, or none yet.
pub fn stored_record(store: &AccountStore, user: &str) -> Record {
    store.authorization(user).cloned().unwrap_or_default()
}
