//! The keys that seal saved device records, kept in the operating system's key store. Task T313.
//!
//! Owns: the `KeyVault` trait (one random 32-byte key per server profile), `MemoryVault` (in the process only, for
//! tests and for anything that must not touch the person's key store) and `SystemVault`, the per-user key store of
//! the operating system:
//!
//! - Windows: a generic credential in Credential Manager (crate `windows-native-keyring-store`), which Windows keeps
//!   encrypted under the person's logon (DPAPI).
//! - macOS: a generic password in the login Keychain (crate `apple-native-keyring-store`).
//! - Linux and the BSDs: an item in the Secret Service's default collection (GNOME Keyring, KWallet, KeePassXC and
//!   others) over D-Bus, in Rust through zbus (crate `zbus-secret-service-keyring-store`).
//!
//! Other platforms have no `SystemVault` yet; opening one says so. Nothing here falls back to a file: when there is
//! no key store, `SystemVault::open` fails and the caller decides what to tell the person.
//!
//! Called by: `device_store` (sealing and opening records) and `app` (which opens the vault). Calls: `keyring-core`
//! and the platform's store crate; every call may block while the platform asks the person to unlock their key store.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use zeroize::{Zeroize, Zeroizing};

/// Length of the key that seals one record.
pub const KEY_BYTES: usize = 32;

/// A record key. Wiped when dropped.
pub type VaultKey = Zeroizing<[u8; KEY_BYTES]>;

/// The service name the keys are filed under in the key store; the profile is the account.
pub const SERVICE: &str = "crewcraft-device-record";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// There is no key store, it is locked, or it refused access (for example the person declined a prompt).
    Unavailable,
    /// The key store holds something under this profile that is not a record key.
    Damaged,
}

/// Where the record keys live: one key per profile.
pub trait KeyVault: Send + Sync + fmt::Debug {
    /// The key saved for `profile`, or `None` if there is none.
    fn load(&self, profile: &str) -> Result<Option<VaultKey>, VaultError>;
    /// Save `key` for `profile`, replacing any earlier one.
    fn store(&self, profile: &str, key: &[u8; KEY_BYTES]) -> Result<(), VaultError>;
    /// Delete `profile`'s key. False if there was none.
    fn remove(&self, profile: &str) -> Result<bool, VaultError>;
}

/// Opens a vault when it is first needed (`app::Controller::start_with_vault` calls it at most once).
pub type OpenVault<'a> = Box<dyn FnOnce() -> Result<Arc<dyn KeyVault>, VaultError> + 'a>;

/// A vault held in the process only. Clones share their keys, like two handles on one key store. Its `Debug` shows
/// only the profile names.
#[derive(Clone, Default)]
pub struct MemoryVault {
    inner: Arc<Mutex<Memory>>,
}

#[derive(Default)]
struct Memory {
    keys: HashMap<String, VaultKey>,
    unavailable: bool,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// This vault as the shared handle `device_store` takes.
    pub fn shared(&self) -> Arc<dyn KeyVault> {
        Arc::new(self.clone())
    }

    /// Hands out this vault (shared, not copied) when asked.
    pub fn opener(&self) -> OpenVault<'static> {
        let vault = self.clone();
        Box::new(move || Ok(vault.shared()))
    }

    /// Make every call fail with `Unavailable` (true), as a locked or missing key store does, or work again (false).
    pub fn set_unavailable(&self, unavailable: bool) {
        if let Ok(mut memory) = self.inner.lock() {
            memory.unavailable = unavailable;
        }
    }

    /// Whether a key is saved for `profile`.
    pub fn contains(&self, profile: &str) -> bool {
        self.inner.lock().is_ok_and(|memory| memory.keys.contains_key(profile))
    }

    fn with<T>(&self, act: impl FnOnce(&mut HashMap<String, VaultKey>) -> T) -> Result<T, VaultError> {
        let mut memory = self.inner.lock().map_err(|_| VaultError::Unavailable)?;
        if memory.unavailable {
            return Err(VaultError::Unavailable);
        }
        Ok(act(&mut memory.keys))
    }
}

impl fmt::Debug for MemoryVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut profiles = self.inner.lock().map(|memory| memory.keys.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
        profiles.sort();
        f.debug_struct("MemoryVault").field("profiles", &profiles).finish_non_exhaustive()
    }
}

impl KeyVault for MemoryVault {
    fn load(&self, profile: &str) -> Result<Option<VaultKey>, VaultError> {
        self.with(|keys| keys.get(profile).cloned())
    }

    fn store(&self, profile: &str, key: &[u8; KEY_BYTES]) -> Result<(), VaultError> {
        self.with(|keys| {
            keys.insert(profile.to_owned(), Zeroizing::new(*key));
        })
    }

    fn remove(&self, profile: &str) -> Result<bool, VaultError> {
        self.with(|keys| keys.remove(profile).is_some())
    }
}

/// The operating system's per-user key store.
pub struct SystemVault {
    store: Arc<keyring_core::CredentialStore>,
}

impl fmt::Debug for SystemVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemVault").field("store", &self.store.vendor()).finish()
    }
}

impl SystemVault {
    /// Reach this computer's key store. `Unavailable` where there is none: on Linux and the BSDs, when no Secret
    /// Service answers on the session bus; on other platforms than Windows, macOS, Linux and the BSDs, always.
    pub fn open() -> Result<Self, VaultError> {
        platform_store().map(|store| Self { store }).map_err(|_| VaultError::Unavailable)
    }

    /// Opens the system vault when asked; what the app passes to `Controller::start_with_vault`.
    pub fn opener() -> OpenVault<'static> {
        Box::new(|| Self::open().map(|vault| Arc::new(vault) as Arc<dyn KeyVault>))
    }

    fn entry(&self, profile: &str) -> Result<keyring_core::Entry, VaultError> {
        self.store.build(SERVICE, profile, None).map_err(|_| VaultError::Unavailable)
    }
}

impl KeyVault for SystemVault {
    fn load(&self, profile: &str) -> Result<Option<VaultKey>, VaultError> {
        match self.entry(profile)?.get_secret() {
            Ok(mut secret) => {
                let key = <[u8; KEY_BYTES]>::try_from(secret.as_slice()).map(Zeroizing::new).map_err(|_| VaultError::Damaged);
                secret.zeroize();
                key.map(Some)
            }
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(vault_error(&error)),
        }
    }

    fn store(&self, profile: &str, key: &[u8; KEY_BYTES]) -> Result<(), VaultError> {
        self.entry(profile)?.set_secret(key).map_err(|error| vault_error(&error))
    }

    fn remove(&self, profile: &str) -> Result<bool, VaultError> {
        match self.entry(profile)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(error) => Err(vault_error(&error)),
        }
    }
}

fn vault_error(error: &keyring_core::Error) -> VaultError {
    match error {
        keyring_core::Error::BadEncoding(_) | keyring_core::Error::BadDataFormat(..) | keyring_core::Error::Ambiguous(_) => VaultError::Damaged,
        _ => VaultError::Unavailable,
    }
}

#[cfg(windows)]
fn platform_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    let store: Arc<keyring_core::CredentialStore> = windows_native_keyring_store::Store::new()?;
    Ok(store)
}

#[cfg(target_os = "macos")]
fn platform_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    let store: Arc<keyring_core::CredentialStore> = apple_native_keyring_store::keychain::Store::new()?;
    Ok(store)
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
fn platform_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    let store: Arc<keyring_core::CredentialStore> = zbus_secret_service_keyring_store::Store::new()?;
    Ok(store)
}

#[cfg(not(any(windows, all(unix, not(any(target_os = "ios", target_os = "android"))))))]
fn platform_store() -> keyring_core::Result<Arc<keyring_core::CredentialStore>> {
    Err(keyring_core::Error::NoDefaultStore)
}

#[cfg(test)]
mod tests {
    use super::{KEY_BYTES, KeyVault, MemoryVault, VaultError};

    #[test]
    fn memory_vault_clones_share_keys_and_debug_shows_no_key() {
        let vault = MemoryVault::new();
        let other = vault.clone();
        assert_eq!(vault.load("work"), Ok(None));
        assert_eq!(vault.store("work", &[7; KEY_BYTES]), Ok(()));
        assert_eq!(other.load("work").map(|key| key.map(|key| *key)), Ok(Some([7; KEY_BYTES])));
        assert_eq!(format!("{other:?}"), "MemoryVault { profiles: [\"work\"], .. }");
        other.set_unavailable(true);
        assert_eq!(vault.load("work"), Err(VaultError::Unavailable));
        other.set_unavailable(false);
        assert_eq!(vault.remove("work"), Ok(true));
        assert_eq!(vault.remove("work"), Ok(false));
        assert!(!other.contains("work"));
    }
}
