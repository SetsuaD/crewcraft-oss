//! Accounts: who a person is to CrewCraft and how they prove it.
//!
//! Owns: the sign-in identity (a normalised email address, [`identity`]), password hashing ([`password`], Argon2id),
//! and the PKCE check of the companion-app sign-in ([`oidc`]); see docs/SECURITY-DESIGN.md section 8, "Standalone
//! accounts, and a shared 2FA for mail clients". Holds no network or storage code: the server stores what these functions return.
//! Called by: `crewcraft-server-core` (sign-in, invitations, the admin console).

pub mod identity;
pub mod oidc;
pub mod password;
pub mod sessions;
pub mod throttle;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Not an address CrewCraft accepts as an identity (see [`identity::normalize_email`]).
    BadEmail,
    /// Fewer than [`password::MIN_CHARS`] characters.
    PasswordTooShort,
    /// More than [`password::MAX_BYTES`] bytes of UTF-8.
    PasswordTooLong,
    /// A stored hash that is not an Argon2id PHC string.
    BadHash,
    /// The hashing library refused its input (for example a salt of the wrong length).
    Hashing,
    /// A PKCE code verifier outside RFC 7636's length or character rules.
    BadVerifier,
}
