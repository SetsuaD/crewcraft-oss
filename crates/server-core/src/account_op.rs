//! The account store's changes as records (`account_store`, written to its own `journal::Journal` file, separate from
//! the room journal of `durable`). Each accepted change is exactly one record, so a change is on disk whole or not at
//! all. Issue #35.
//!
//! Wire format, integers big-endian; `str` is a `u32` byte length then that many bytes of UTF-8, at most `MAX_STR`;
//! `sealed` is `8 key id | 24 nonce | u32 length | ciphertext with tag` (length at most `MAX_SEALED`). A record is
//! `u8 tag | fields`:
//! - tag 1 `Created`: `u32 format | 8 key id`. Always the first record of a store.
//! - tag 2 `InviteIssued`: `str email | 32 bootstrap public key | u64 expires_ms | u64 now_ms`
//! - tag 3 `InviteRevoked`: `32 bootstrap public key`
//! - tag 4 `Activated`: `32 bootstrap public key | u8 new person (0 or 1) | [if 1: u8 has password (0 or 1) |
//!   [if 1: str password PHC] | sealed TOTP secret] | u64 device id | str device name | u32 length | the issued leaf
//!   certificate (DER, at most `MAX_CERT`) | 32 SHA-256 of its SubjectPublicKeyInfo | u64 accepted TOTP counter |
//!   u64 now_ms`. The device's certificate fingerprint is the SHA-256 of that exact leaf, so it is not stored twice.
//! - tag 5 `TotpAccepted`: `str email | u64 counter`
//! - tag 6 `PasswordChanged`: `str email | str password PHC`
//! - tag 7 `DeviceRevoked`: `str email | u64 device id` (also ends every session on that device)
//! - tag 8 `SessionCreated`: `32 SHA-256 of the session token | str email | u64 device id | u64 created_ms`
//! - tag 9 `SessionRevoked`: `32 SHA-256 of the session token`
//!
//! A raw session token is never in a record: only its SHA-256.
//!
//! The person's email is NOT in `Activated`: it comes from the invitation the record redeems, so a client can never
//! choose whose account it joins.

use std::fmt;

use crewcraft_proto::message::CodecError;

use crate::seal::{KEY_ID_BYTES, NONCE_BYTES, Sealed, TAG_BYTES};

/// Longest string field, in bytes.
pub const MAX_STR: usize = 1 << 12;
/// Longest sealed ciphertext (with its tag), in bytes.
pub const MAX_SEALED: usize = crate::seal::MAX_PLAINTEXT + TAG_BYTES;
/// Longest issued leaf certificate, in bytes.
pub const MAX_CERT: usize = 16 * 1024;
/// The store format this code writes and reads.
pub const FORMAT: u32 = 1;

/// A first device's person, created by its activation.
#[derive(Clone, PartialEq, Eq)]
pub struct NewPerson {
    /// The Argon2id PHC string with the `own` password source; `None` with the `mailbox` source, which stores nothing.
    pub password_phc: Option<String>,
    pub totp: Sealed,
}

impl fmt::Debug for NewPerson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewPerson").field("own_password", &self.password_phc.is_some()).field("totp", &self.totp).finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum AccountOp {
    Created {
        format: u32,
        key_id: [u8; KEY_ID_BYTES],
    },
    InviteIssued {
        email: String,
        bootstrap_pub: [u8; 32],
        expires_ms: u64,
        now_ms: u64,
    },
    InviteRevoked {
        bootstrap_pub: [u8; 32],
    },
    Activated {
        bootstrap_pub: [u8; 32],
        new_person: Option<NewPerson>,
        device_id: u64,
        device_name: String,
        certificate: Vec<u8>,
        spki_sha256: [u8; 32],
        counter: u64,
        now_ms: u64,
    },
    TotpAccepted {
        email: String,
        counter: u64,
    },
    PasswordChanged {
        email: String,
        phc: String,
    },
    DeviceRevoked {
        email: String,
        device_id: u64,
    },
    SessionCreated {
        token_sha256: [u8; 32],
        email: String,
        device_id: u64,
        created_ms: u64,
    },
    SessionRevoked {
        token_sha256: [u8; 32],
    },
}

impl fmt::Debug for AccountOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountOp::Created { format, .. } => write!(f, "Created {{ format: {format}, .. }}"),
            AccountOp::InviteIssued { email, expires_ms, .. } => write!(f, "InviteIssued {{ email: {email:?}, expires_ms: {expires_ms}, .. }}"),
            AccountOp::InviteRevoked { .. } => f.write_str("InviteRevoked { .. }"),
            AccountOp::Activated { new_person, device_id, counter, .. } => {
                write!(f, "Activated {{ new_person: {}, device_id: {device_id}, counter: {counter}, .. }}", new_person.is_some())
            }
            AccountOp::TotpAccepted { email, counter } => write!(f, "TotpAccepted {{ email: {email:?}, counter: {counter} }}"),
            AccountOp::PasswordChanged { email, .. } => write!(f, "PasswordChanged {{ email: {email:?}, .. }}"),
            AccountOp::DeviceRevoked { email, device_id } => write!(f, "DeviceRevoked {{ email: {email:?}, device_id: {device_id} }}"),
            AccountOp::SessionCreated { email, device_id, .. } => write!(f, "SessionCreated {{ email: {email:?}, device_id: {device_id}, .. }}"),
            AccountOp::SessionRevoked { .. } => f.write_str("SessionRevoked { .. }"),
        }
    }
}

pub fn encode_account_op(op: &AccountOp) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    match op {
        AccountOp::Created { format, key_id } => {
            out.push(1);
            out.extend_from_slice(&format.to_be_bytes());
            out.extend_from_slice(key_id);
        }
        AccountOp::InviteIssued { email, bootstrap_pub, expires_ms, now_ms } => {
            out.push(2);
            put_str(&mut out, email)?;
            out.extend_from_slice(bootstrap_pub);
            out.extend_from_slice(&expires_ms.to_be_bytes());
            out.extend_from_slice(&now_ms.to_be_bytes());
        }
        AccountOp::InviteRevoked { bootstrap_pub } => {
            out.push(3);
            out.extend_from_slice(bootstrap_pub);
        }
        AccountOp::Activated { bootstrap_pub, new_person, device_id, device_name, certificate, spki_sha256, counter, now_ms } => {
            out.push(4);
            out.extend_from_slice(bootstrap_pub);
            match new_person {
                None => out.push(0),
                Some(person) => {
                    out.push(1);
                    match &person.password_phc {
                        None => out.push(0),
                        Some(phc) => {
                            out.push(1);
                            put_str(&mut out, phc)?;
                        }
                    }
                    put_sealed(&mut out, &person.totp)?;
                }
            }
            out.extend_from_slice(&device_id.to_be_bytes());
            put_str(&mut out, device_name)?;
            if certificate.is_empty() || certificate.len() > MAX_CERT {
                return Err(CodecError::FieldLength);
            }
            out.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
            out.extend_from_slice(certificate);
            out.extend_from_slice(spki_sha256);
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&now_ms.to_be_bytes());
        }
        AccountOp::TotpAccepted { email, counter } => {
            out.push(5);
            put_str(&mut out, email)?;
            out.extend_from_slice(&counter.to_be_bytes());
        }
        AccountOp::PasswordChanged { email, phc } => {
            out.push(6);
            put_str(&mut out, email)?;
            put_str(&mut out, phc)?;
        }
        AccountOp::DeviceRevoked { email, device_id } => {
            out.push(7);
            put_str(&mut out, email)?;
            out.extend_from_slice(&device_id.to_be_bytes());
        }
        AccountOp::SessionCreated { token_sha256, email, device_id, created_ms } => {
            out.push(8);
            out.extend_from_slice(token_sha256);
            put_str(&mut out, email)?;
            out.extend_from_slice(&device_id.to_be_bytes());
            out.extend_from_slice(&created_ms.to_be_bytes());
        }
        AccountOp::SessionRevoked { token_sha256 } => {
            out.push(9);
            out.extend_from_slice(token_sha256);
        }
    }
    Ok(out)
}

pub fn decode_account_op(bytes: &[u8]) -> Result<AccountOp, CodecError> {
    let mut r = Reader { bytes, pos: 0 };
    let tag = r.u8()?;
    let op = match tag {
        1 => AccountOp::Created { format: r.u32()?, key_id: r.array()? },
        2 => AccountOp::InviteIssued { email: r.str()?, bootstrap_pub: r.array()?, expires_ms: r.u64()?, now_ms: r.u64()? },
        3 => AccountOp::InviteRevoked { bootstrap_pub: r.array()? },
        4 => {
            let bootstrap_pub = r.array()?;
            let new_person = match r.u8()? {
                0 => None,
                1 => {
                    let password_phc = match r.u8()? {
                        0 => None,
                        1 => Some(r.str()?),
                        other => return Err(CodecError::BadKind(other)),
                    };
                    Some(NewPerson { password_phc, totp: r.sealed()? })
                }
                other => return Err(CodecError::BadKind(other)),
            };
            AccountOp::Activated {
                bootstrap_pub,
                new_person,
                device_id: r.u64()?,
                device_name: r.str()?,
                certificate: r.cert()?,
                spki_sha256: r.array()?,
                counter: r.u64()?,
                now_ms: r.u64()?,
            }
        }
        5 => AccountOp::TotpAccepted { email: r.str()?, counter: r.u64()? },
        6 => AccountOp::PasswordChanged { email: r.str()?, phc: r.str()? },
        7 => AccountOp::DeviceRevoked { email: r.str()?, device_id: r.u64()? },
        8 => AccountOp::SessionCreated { token_sha256: r.array()?, email: r.str()?, device_id: r.u64()?, created_ms: r.u64()? },
        9 => AccountOp::SessionRevoked { token_sha256: r.array()? },
        other => return Err(CodecError::BadKind(other)),
    };
    if r.pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(op)
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), CodecError> {
    if s.len() > MAX_STR {
        return Err(CodecError::FieldLength);
    }
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_sealed(out: &mut Vec<u8>, sealed: &Sealed) -> Result<(), CodecError> {
    if sealed.ciphertext.len() > MAX_SEALED {
        return Err(CodecError::FieldLength);
    }
    out.extend_from_slice(&sealed.key_id);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&(sealed.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed.ciphertext);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(CodecError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }
    fn str(&mut self) -> Result<String, CodecError> {
        let len = self.u32()? as usize;
        if len > MAX_STR {
            return Err(CodecError::FieldLength);
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| CodecError::BadUtf8)
    }
    fn cert(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()? as usize;
        if !(1..=MAX_CERT).contains(&len) {
            return Err(CodecError::FieldLength);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn sealed(&mut self) -> Result<Sealed, CodecError> {
        let key_id = self.array::<KEY_ID_BYTES>()?;
        let nonce = self.array::<NONCE_BYTES>()?;
        let len = self.u32()? as usize;
        if !(TAG_BYTES..=MAX_SEALED).contains(&len) {
            return Err(CodecError::FieldLength);
        }
        Ok(Sealed { key_id, nonce, ciphertext: self.take(len)?.to_vec() })
    }
}
