//! Verify a sign-in for an enrolled person using CrewCraft's own password source.

use crewcraft_totp::Totp;

use crate::{identity, password};

/// A fixed Argon2id PHC string with the same work factors as a newly enrolled account. Its salt and tag are public
/// padding. There is no account associated with it.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The request fields. The transport supplies the enrolled device identity separately.
pub struct Credentials<'a> {
    pub email: &'a str,
    pub password: &'a str,
    pub code: &'a str,
}

/// Server-owned credentials for an active account with a normalized email address.
pub struct OwnAccount<'a> {
    pub email: &'a str,
    pub password_hash: &'a str,
    pub totp: &'a Totp,
    pub last_totp_counter: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedOwnSignIn {
    pub accepted_counter: u64,
    pub needs_password_rehash: bool,
}

/// Check the password and a fresh TOTP code with a one-step clock skew. Pass the enrolled email only after validating
/// its device certificate and looking up the live device on the server. All rejections return `None`.
///
/// Hold the person's lock across verification and saving the accepted counter, or condition the write on the account
/// state read for verification. Issue the session only after the counter is saved. If indicated, replace the password
/// hash after successful sign-in.
///
/// Unknown identities still perform the current Argon2id workload. Existing accounts can have hashes with different
/// parameters. This function does not equalize response time or enforce attempt limits.
pub fn verify_own(
    enrolled_email: Option<&str>,
    account: Option<&OwnAccount<'_>>,
    credentials: Credentials<'_>,
    unix_seconds: u64,
) -> Option<VerifiedOwnSignIn> {
    let entered_email = identity::normalize_email(credentials.email).ok();
    let account = account.filter(|account| enrolled_email == Some(account.email) && entered_email.as_deref() == Some(account.email));
    let password_fits = credentials.password.len() <= password::MAX_BYTES;
    let password_input = if password_fits { credentials.password } else { "" };
    let hash = account.filter(|_| password_fits).map_or(DUMMY_HASH, |account| account.password_hash);
    let password_matches = match password::verify(password_input, hash) {
        Ok(matches) => matches,
        Err(_) => {
            let _ = password::verify(password_input, DUMMY_HASH);
            false
        }
    };

    let account = account?;
    let accepted_counter = account.totp.verify(credentials.code, unix_seconds, 1, account.last_totp_counter)?;
    if !password_fits || !password_matches {
        return None;
    }
    Some(VerifiedOwnSignIn { accepted_counter, needs_password_rehash: password::needs_rehash(account.password_hash) })
}
