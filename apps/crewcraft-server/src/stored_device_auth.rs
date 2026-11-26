//! Sign-in and per-frame authorization for an admitted CrewCraft device. Task T223. Task T611e adds sign-in through an
//! external identity provider (`with_external`), for this device's own person only.
//!
//! While signed in (task T611j, SECURITY-DESIGN.md section 9): for a person bound to the provider, on a server with an
//! external authorizer, every request checks the person's stored authorization record by the T600 rules
//! (`crewcraft_authz`). When the record is due (10 minutes after a good answer, 60 seconds after a failed ask) the
//! authorizer is asked again (`purpose: recheck`) with no lock held, and the new record is stored before it is used. A
//! refusal (a `deny`, or no confirmation for longer than the grace) ends this session in the store, so it cannot be
//! resumed either; the person's other devices stop at their own next request, by the same record.

use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

use crewcraft_accounts::sessions::token_hash;
use crewcraft_accounts::sign_in::{Credentials, OwnAccount, verify_own};
use crewcraft_accounts::throttle::Throttle;
use crewcraft_authz::{Access, Area, Capability, commit_decision};
use crewcraft_oidc::Identity;
use crewcraft_proto::signin::SignIn;
use crewcraft_server_core::account_store::AccountStore;
use crewcraft_server_core::devices::Device;
use crewcraft_totp::Totp;
use rand_core::{OsRng, RngCore};
use x509_parser::parse_x509_certificate;

use crate::device_session::{AuthError, CommittedSignIn, DeviceAuth};
use crate::external_signin::{ExternalSignIn, Redirect, Start};

/// An opaque, server-side handle to the committed session. The client token is never retained here.
pub struct StoredSession([u8; 32]);

/// One adapter per TLS connection. All connections share the account store and the sign-in throttle.
pub struct StoredDeviceAuth {
    store: Arc<Mutex<AccountStore>>,
    throttle: Arc<Mutex<Throttle>>,
    leaf_der: Vec<u8>,
    validity: RangeInclusive<i64>,
    user: String,
    device_id: u64,
    external: Option<Arc<ExternalSignIn>>,
}

impl StoredDeviceAuth {
    /// Also offer sign-in through an external identity provider (task T611e).
    pub fn with_external(mut self, external: Arc<ExternalSignIn>) -> Self {
        self.external = Some(external);
        self
    }

    /// Bind the exact certificate whose chain and proof of possession the TLS admission layer verified.
    pub fn bind(store: Arc<Mutex<AccountStore>>, throttle: Arc<Mutex<Throttle>>, verified_peer_der: &[u8], now_ms: u64) -> Result<Self, AuthError> {
        let (remaining, certificate) = parse_x509_certificate(verified_peer_der).map_err(|_| AuthError::UnauthorizedDevice)?;
        let validity = certificate.validity().not_before.timestamp()..=certificate.validity().not_after.timestamp();
        if !remaining.is_empty() || !validity.contains(&unix_seconds(now_ms)) {
            return Err(AuthError::UnauthorizedDevice);
        }
        let device = {
            let mut store = store.lock().map_err(|_| AuthError::Unavailable)?;
            enrolled_device(&mut store, verified_peer_der, now_ms)?
        };
        Ok(Self { store, throttle, leaf_der: verified_peer_der.to_vec(), validity, user: device.user, device_id: device.id, external: None })
    }
}

impl DeviceAuth for StoredDeviceAuth {
    type Session = StoredSession;

    fn sign_in(&self, credentials: SignIn<'_>, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        if !self.validity.contains(&unix_seconds(now_ms)) {
            return Err(AuthError::UnauthorizedDevice);
        }
        let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
        let device = enrolled_device(&mut store, &self.leaf_der, now_ms)?;
        if device.id != self.device_id || device.user != self.user {
            return Err(AuthError::UnauthorizedDevice);
        }

        let mut throttle = self.throttle.lock().map_err(|_| AuthError::Unavailable)?;
        if throttle.check(&self.user, now_ms).is_err() {
            return Ok(None);
        }
        let person = store.person(&self.user).ok_or(AuthError::Unavailable)?;
        let secret = store.totp_secret(&self.user).map_err(|_| AuthError::Unavailable)?;
        let totp = Totp::with_defaults(secret.to_vec()).map_err(|_| AuthError::Unavailable)?;
        let account = person.password_phc.as_deref().map(|password_hash| OwnAccount {
            email: &self.user,
            password_hash,
            totp: &totp,
            last_totp_counter: Some(person.last_totp_counter),
        });
        let credentials = Credentials { email: credentials.email, password: credentials.password, code: credentials.code };
        let Some(verified) = verify_own(Some(&self.user), account.as_ref(), credentials, now_ms / 1000) else {
            throttle.fail(&self.user, now_ms);
            return Ok(None);
        };

        let mut random = [0; 32];
        OsRng.try_fill_bytes(&mut random).map_err(|_| AuthError::Unavailable)?;
        let token = store.sign_in(random, &self.user, self.device_id, verified.accepted_counter, now_ms).map_err(|_| AuthError::Unavailable)?;
        throttle.succeed(&self.user);
        let session = StoredSession(token_hash(&token));
        Ok(Some(CommittedSignIn { user: self.user.clone(), token, session }))
    }

    fn resume(&self, token: &str, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        if !self.validity.contains(&unix_seconds(now_ms)) {
            return Err(AuthError::UnauthorizedDevice);
        }
        let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
        if !store.healthy() {
            return Err(AuthError::Unavailable);
        }
        let hash = token_hash(token);
        let Some(live) = store.resume_session_by_hash(&hash, &self.leaf_der, now_ms) else {
            return Ok(None);
        };
        if live.user != self.user || live.device != self.device_id.to_string() {
            return Ok(None);
        }
        Ok(Some(CommittedSignIn { user: self.user.clone(), token: token.to_owned(), session: StoredSession(hash) }))
    }

    fn end(&self, token: &str, now_ms: u64) -> Result<bool, AuthError> {
        let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
        store.end_session_by_hash(&token_hash(token), &self.leaf_der, now_ms).map_err(|_| AuthError::Unavailable)
    }

    fn begin_external(&self, now_ms: u64) -> Result<Option<Start>, AuthError> {
        let Some(external) = &self.external else { return Ok(None) };
        if !self.validity.contains(&unix_seconds(now_ms)) {
            return Err(AuthError::UnauthorizedDevice);
        }
        {
            let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
            let device = enrolled_device(&mut store, &self.leaf_der, now_ms)?;
            if device.id != self.device_id || device.user != self.user {
                return Err(AuthError::UnauthorizedDevice);
            }
        }
        let mut random = [0; 32];
        OsRng.try_fill_bytes(&mut random).map_err(|_| AuthError::Unavailable)?;
        Ok(external.begin(self.device_id, random, now_ms).ok())
    }

    fn finish_external(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        now_ms: u64,
    ) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        let Some(external) = &self.external else { return Ok(None) };
        if !self.validity.contains(&unix_seconds(now_ms)) {
            return Err(AuthError::UnauthorizedDevice);
        }
        let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
        let device = enrolled_device(&mut store, &self.leaf_der, now_ms)?;
        if device.id != self.device_id || device.user != self.user {
            return Err(AuthError::UnauthorizedDevice);
        }
        let mut throttle = self.throttle.lock().map_err(|_| AuthError::Unavailable)?;
        if throttle.check(&self.user, now_ms).is_err() {
            return Ok(None);
        }
        let mut random = [0; 32];
        OsRng.try_fill_bytes(&mut random).map_err(|_| AuthError::Unavailable)?;
        match external.finish(&mut store, &self.user, self.device_id, Redirect { code, verifier, redirect_uri }, random, now_ms) {
            Ok(token) => {
                throttle.succeed(&self.user);
                let session = StoredSession(token_hash(&token));
                Ok(Some(CommittedSignIn { user: self.user.clone(), token, session }))
            }
            Err(_) => {
                throttle.fail(&self.user, now_ms);
                Ok(None)
            }
        }
    }

    fn device(&self) -> Option<u64> {
        Some(self.device_id)
    }

    fn with_live_session<T>(&self, session: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        if !self.validity.contains(&unix_seconds(now_ms)) {
            return Ok(None);
        }
        if !self.still_authorized(session, now_ms)? {
            return Ok(None);
        }
        let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
        if !store.healthy() {
            return Err(AuthError::Unavailable);
        }
        let Some(live) = store.continue_session_by_hash(&session.0, &self.leaf_der, now_ms) else {
            return Ok(None);
        };
        if live.user != self.user || live.device != self.device_id.to_string() {
            return Ok(None);
        }
        // Keep the account guard live until the authorized room operation returns.
        let result = action();
        drop(store);
        Ok(Some(result))
    }
}

impl StoredDeviceAuth {
    /// Whether this person may still use the session by the external authorizer (task T611j). Always true for a person
    /// not bound to the provider, or on a server without an authorizer. A refusal ends this session in the store.
    fn still_authorized(&self, session: &StoredSession, now_ms: u64) -> Result<bool, AuthError> {
        let Some(authorizer) = self.external.as_ref().and_then(|external| external.authorizer()) else { return Ok(true) };
        let now = now_ms / 1000;
        let (record, identity) = {
            let store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
            let Some((issuer, subject)) = store.external_of(&self.user) else { return Ok(true) };
            let identity = Identity {
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                email: Some(self.user.clone()),
                email_verified: false,
                name: None,
                amr: Vec::new(),
            };
            (store.authorization(&self.user).cloned().unwrap_or_default(), identity)
        };
        let access = if now < record.next_check_at {
            record.current(Area::Staff, now)
        } else {
            // The authorizer may be slow or unreachable: it is asked with no lock held.
            let answer = authorizer.ask(&identity, "recheck");
            let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
            // Another connection of this person may have stored a newer record meanwhile: build on what is stored now.
            let current = store.authorization(&self.user).cloned().unwrap_or_default();
            let (next, access) = current.recheck(&answer, Area::Staff, now);
            commit_decision(&mut *store, &self.user, &next, access)
        };
        match access {
            Access::Allowed(capabilities) if capabilities.has(Capability::Use) => Ok(true),
            _ => {
                let mut store = self.store.lock().map_err(|_| AuthError::Unavailable)?;
                let _ = store.end_session_by_hash(&session.0, &self.leaf_der, now_ms);
                Ok(false)
            }
        }
    }
}

fn enrolled_device(store: &mut AccountStore, leaf_der: &[u8], now_ms: u64) -> Result<Device, AuthError> {
    if !store.healthy() {
        return Err(AuthError::Unavailable);
    }
    store.admit(leaf_der, now_ms).map_err(|_| AuthError::UnauthorizedDevice)
}

fn unix_seconds(now_ms: u64) -> i64 {
    (now_ms / 1000) as i64
}
