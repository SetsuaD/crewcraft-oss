//! The iPhone's hardware key store (task T422): the device key is a P-256 key generated in the Secure Enclave, kept
//! in the app's Keychain under its alias, used only for signing, and never exported. Implements
//! `hardware_key::HardwareKeys`.
//!
//! Owns: the Security framework calls, through the safe `security-framework` crate: `SecKey::new` with the Secure
//! Enclave token (software only on the simulator, which has no Secure Enclave), adding the key to the Keychain under
//! its alias (`ItemAddOptions`; a generated key is not stored on its own on iOS), finding and deleting it
//! (`ItemSearchOptions`), and `ECDSASignatureMessageX962SHA256` to sign. Called by: `ios` (the app's controller).

use std::fmt;
use std::sync::Arc;

use security_framework::item::{AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

use crate::hardware_key::{HardwareKey, HardwareKeyError, HardwareKeys, KeyLocation, p256_spki, valid_alias};

/// `errSecItemNotFound`.
const ERR_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecDuplicateItem`.
const ERR_DUPLICATE_ITEM: i32 = -25299;

/// The iPhone's Keychain and Secure Enclave.
#[derive(Debug, Default)]
pub struct IosKeychain;

impl IosKeychain {
    pub fn new() -> Self {
        Self
    }
}

impl HardwareKeys for IosKeychain {
    fn generate(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        if !valid_alias(alias) {
            return Err(HardwareKeyError::Invalid);
        }
        let _ = delete_items(alias);
        let make = |token| {
            let mut options = GenerateKeyOptions::default();
            options.set_key_type(KeyType::ec_sec_prime_random()).set_size_in_bits(256).set_token(token).set_label(alias);
            SecKey::new(&options)
        };
        // The Secure Enclave first; a device without one (none that iOS 17 supports) gets a software key, said in
        // the log.
        let key = make(Token::SecureEnclave)
            .or_else(|enclave| {
                log::warn!("CrewCraft: no Secure Enclave key ({}); making the key in software", enclave.code());
                make(Token::Software)
            })
            .map_err(|error| {
                log::warn!("CrewCraft: the key could not be made ({})", error.code());
                HardwareKeyError::Unavailable
            })?;
        let mut add = ItemAddOptions::new(ItemAddValue::Ref(AddRef::Key(key)));
        add.set_label(alias);
        match add.add() {
            // A Secure Enclave key may already be in the Keychain as it is made (errSecDuplicateItem).
            Ok(()) => {}
            Err(error) if error.code() == ERR_DUPLICATE_ITEM => {}
            Err(error) => {
                log::warn!("CrewCraft: the Keychain refused the key ({})", error.code());
                return Err(HardwareKeyError::Unavailable);
            }
        }
        // Read it back from the Keychain: the key that is returned is the one a later start will find.
        self.open(alias).inspect_err(|error| log::warn!("CrewCraft: the new key is not in the Keychain ({error})"))
    }

    fn open(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        if !valid_alias(alias) {
            return Err(HardwareKeyError::NotFound);
        }
        let found = ItemSearchOptions::new().class(ItemClass::key()).label(alias).load_refs(true).search();
        let results = match found {
            Ok(results) => results,
            Err(error) if error.code() == ERR_ITEM_NOT_FOUND => return Err(HardwareKeyError::NotFound),
            Err(_) => return Err(HardwareKeyError::Unavailable),
        };
        let key = results
            .into_iter()
            .find_map(|result| match result {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            })
            .ok_or(HardwareKeyError::NotFound)?;
        IosKey::make(alias, key)
    }

    fn delete(&self, alias: &str) -> Result<bool, HardwareKeyError> {
        if !valid_alias(alias) {
            return Ok(false);
        }
        delete_items(alias)
    }
}

/// Delete the Keychain keys labelled `alias`. False if there were none.
fn delete_items(alias: &str) -> Result<bool, HardwareKeyError> {
    match ItemSearchOptions::new().class(ItemClass::key()).label(alias).delete() {
        Ok(()) => Ok(true),
        Err(error) if error.code() == ERR_ITEM_NOT_FOUND => Ok(false),
        Err(_) => Err(HardwareKeyError::Unavailable),
    }
}

/// One Keychain key: its alias, its public key and where it lives.
struct IosKey {
    alias: String,
    key: SecKey,
    spki: Vec<u8>,
    location: KeyLocation,
}

impl fmt::Debug for IosKey {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("IosKey").field("alias", &self.alias).finish_non_exhaustive()
    }
}

impl IosKey {
    fn make(alias: &str, key: SecKey) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        let public = key.public_key().and_then(|public| public.external_representation()).ok_or(HardwareKeyError::Invalid)?;
        let spki = p256_spki(public.bytes()).ok_or(HardwareKeyError::Invalid)?;
        // A Secure Enclave private key cannot be exported; a software one (the simulator) can.
        let location = if key.external_representation().is_none() { KeyLocation::TrustedEnvironment } else { KeyLocation::Software };
        Ok(Arc::new(Self { alias: alias.to_owned(), key, spki, location }))
    }
}

// SecKey is a reference-counted CoreFoundation object that the Security framework documents as safe to use from any
// thread; `security-framework` marks it `Send` and `Sync`.
impl HardwareKey for IosKey {
    fn alias(&self) -> &str {
        &self.alias
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
        self.key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message).map_err(|_| HardwareKeyError::SignFailed)
    }

    fn location(&self) -> KeyLocation {
        self.location
    }
}
