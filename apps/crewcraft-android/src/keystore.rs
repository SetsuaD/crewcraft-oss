//! The Android Keystore as the phone's hardware key store (task T403): the device key is a P-256 key generated inside
//! the Keystore (in StrongBox when the phone has one, otherwise in its trusted environment), used only for signing,
//! and never exported. Implements `crewcraft::hardware_key::HardwareKeys`.
//!
//! Owns: the Java calls, made from Rust through JNI with no Java source: `KeyPairGenerator` with a
//! `KeyGenParameterSpec` to make a key, `KeyStore("AndroidKeyStore")` to find and delete one, `Signature
//! ("SHA256withECDSA")` to sign, and `KeyInfo` to say where a key lives. Called by: `shell` (the app's controller) and
//! `selftest`. Calls: the JVM through the `jni` crate; the JVM handle comes from `ndk-context`, which
//! `android-activity` fills in before `android_main` runs.

use std::fmt;
use std::sync::Arc;

use crewcraft::hardware_key::{HardwareKey, HardwareKeyError, HardwareKeys, KeyLocation, p256_point, valid_alias};
use jni::objects::{JByteArray, JObject};
use jni::{Env, JValue, JavaVM, jni_sig, jni_str};

type JniResult<T> = jni::errors::Result<T>;

/// `KeyProperties.PURPOSE_SIGN`.
const PURPOSE_SIGN: i32 = 4;
/// `KeyProperties.SECURITY_LEVEL_*` (API 31).
const SECURITY_LEVEL_TRUSTED_ENVIRONMENT: i32 = 1;
const SECURITY_LEVEL_STRONGBOX: i32 = 2;
const SECURITY_LEVEL_SOFTWARE: i32 = 0;
/// `Build.VERSION_CODES.S`: `KeyInfo.getSecurityLevel` exists from here on.
const API_31: i32 = 31;

/// The Android Keystore, reached through the app's JVM.
pub struct AndroidKeystore {
    vm: Arc<JavaVM>,
}

impl fmt::Debug for AndroidKeystore {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("AndroidKeystore")
    }
}

impl AndroidKeystore {
    /// The Keystore of the running app; `Unavailable` if the JVM handle is missing.
    pub fn new() -> Result<Self, HardwareKeyError> {
        java_vm().map(|vm| Self { vm: Arc::new(vm) }).ok_or(HardwareKeyError::Unavailable)
    }

    /// Run `call` with this thread attached to the JVM. A Java exception becomes `Unavailable` unless `call` turns it
    /// into something more specific, and is never left pending.
    fn with_env<T>(&self, call: impl FnOnce(&mut Env) -> Result<T, HardwareKeyError>) -> Result<T, HardwareKeyError> {
        self.vm
            .attach_current_thread(|env| -> Result<Result<T, HardwareKeyError>, jni::errors::Error> {
                let result = call(env);
                if env.exception_check() {
                    env.exception_clear();
                }
                Ok(result)
            })
            .unwrap_or(Err(HardwareKeyError::Unavailable))
    }
}

// The only unsafe code here (see Cargo.toml): turning the JVM pointer android-activity recorded into a handle.
#[expect(unsafe_code, reason = "the JVM pointer comes from ndk-context, which android-activity sets before android_main runs")]
fn java_vm() -> Option<JavaVM> {
    let vm = ndk_context::android_context().vm();
    if vm.is_null() {
        return None;
    }
    // SAFETY: `vm` is the process's `JavaVM*`, valid for the life of the process; android-activity recorded it in
    // ndk-context when the activity was created, before calling `android_main`.
    Some(unsafe { JavaVM::from_raw(vm.cast()) })
}

impl HardwareKeys for AndroidKeystore {
    fn generate(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        if !valid_alias(alias) {
            return Err(HardwareKeyError::Invalid);
        }
        let (spki, location) = self.with_env(|env| {
            // StrongBox first; a phone without it throws StrongBoxUnavailableException, and the key is made in the
            // trusted environment instead.
            let spki = match generate_key(env, alias, true) {
                Ok(spki) => spki,
                Err(_) => {
                    env.exception_clear();
                    generate_key(env, alias, false).map_err(|_| HardwareKeyError::Unavailable)?
                }
            };
            let location = key_location(env, alias);
            Ok((spki, location))
        })?;
        AndroidKey::make(self.vm.clone(), alias, spki, location)
    }

    fn open(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        if !valid_alias(alias) {
            return Err(HardwareKeyError::NotFound);
        }
        let (spki, location) = self.with_env(|env| {
            let store = key_store(env).map_err(|_| HardwareKeyError::Unavailable)?;
            let spki = certificate_public_key(env, &store, alias).map_err(|_| HardwareKeyError::Unavailable)?.ok_or(HardwareKeyError::NotFound)?;
            Ok((spki, key_location(env, alias)))
        })?;
        AndroidKey::make(self.vm.clone(), alias, spki, location)
    }

    fn delete(&self, alias: &str) -> Result<bool, HardwareKeyError> {
        if !valid_alias(alias) {
            return Ok(false);
        }
        self.with_env(|env| {
            let store = key_store(env).map_err(|_| HardwareKeyError::Unavailable)?;
            let name = env.new_string(alias).map_err(|_| HardwareKeyError::Unavailable)?;
            let held = env
                .call_method(&store, jni_str!("containsAlias"), jni_sig!("(Ljava/lang/String;)Z"), &[JValue::from(&name)])
                .and_then(|value| value.z())
                .map_err(|_| HardwareKeyError::Unavailable)?;
            if held {
                env.call_method(&store, jni_str!("deleteEntry"), jni_sig!("(Ljava/lang/String;)V"), &[JValue::from(&name)])
                    .map_err(|_| HardwareKeyError::Unavailable)?;
            }
            Ok(held)
        })
    }
}

/// One key in the Keystore: its alias, its public key (read once) and where it lives.
struct AndroidKey {
    vm: Arc<JavaVM>,
    alias: String,
    spki: Vec<u8>,
    location: KeyLocation,
}

impl AndroidKey {
    fn make(vm: Arc<JavaVM>, alias: &str, spki: Vec<u8>, location: KeyLocation) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        p256_point(&spki).ok_or(HardwareKeyError::Invalid)?;
        Ok(Arc::new(Self { vm, alias: alias.to_owned(), spki, location }))
    }
}

impl HardwareKey for AndroidKey {
    fn alias(&self) -> &str {
        &self.alias
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
        let keystore = AndroidKeystore { vm: self.vm.clone() };
        keystore.with_env(|env| sign(env, &self.alias, message).map_err(|_| HardwareKeyError::SignFailed))
    }

    fn location(&self) -> KeyLocation {
        self.location
    }
}

/// `KeyStore.getInstance("AndroidKeyStore")`, loaded.
fn key_store<'local>(env: &mut Env<'local>) -> JniResult<JObject<'local>> {
    let provider = env.new_string("AndroidKeyStore")?;
    let store = env
        .call_static_method(
            jni_str!("java/security/KeyStore"),
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljava/security/KeyStore;"),
            &[JValue::from(&provider)],
        )?
        .l()?;
    let none = JObject::null();
    env.call_method(&store, jni_str!("load"), jni_sig!("(Ljava/security/KeyStore$LoadStoreParameter;)V"), &[JValue::from(&none)])?;
    Ok(store)
}

/// The DER public key of the certificate the Keystore holds for `alias`, or `None` if it holds none.
fn certificate_public_key(env: &mut Env<'_>, store: &JObject<'_>, alias: &str) -> JniResult<Option<Vec<u8>>> {
    let name = env.new_string(alias)?;
    let certificate = env
        .call_method(store, jni_str!("getCertificate"), jni_sig!("(Ljava/lang/String;)Ljava/security/cert/Certificate;"), &[JValue::from(&name)])?
        .l()?;
    if certificate.is_null() {
        return Ok(None);
    }
    let public = env.call_method(&certificate, jni_str!("getPublicKey"), jni_sig!("()Ljava/security/PublicKey;"), &[])?.l()?;
    encoded(env, &public).map(Some)
}

/// `key.getEncoded()` as bytes.
fn encoded(env: &mut Env<'_>, key: &JObject<'_>) -> JniResult<Vec<u8>> {
    let bytes = env.call_method(key, jni_str!("getEncoded"), jni_sig!("()[B"), &[])?.l()?;
    let bytes = env.cast_local::<JByteArray>(bytes)?;
    env.convert_byte_array(&bytes)
}

/// Make a P-256 signing key under `alias` (SHA-256 digests only), in StrongBox if `strongbox`. Returns its DER
/// public key.
fn generate_key(env: &mut Env<'_>, alias: &str, strongbox: bool) -> JniResult<Vec<u8>> {
    let name = env.new_string(alias)?;
    let builder = env.new_object(
        jni_str!("android/security/keystore/KeyGenParameterSpec$Builder"),
        jni_sig!("(Ljava/lang/String;I)V"),
        &[JValue::from(&name), JValue::Int(PURPOSE_SIGN)],
    )?;
    let curve_name = env.new_string("secp256r1")?;
    let curve = env.new_object(jni_str!("java/security/spec/ECGenParameterSpec"), jni_sig!("(Ljava/lang/String;)V"), &[JValue::from(&curve_name)])?;
    env.call_method(
        &builder,
        jni_str!("setAlgorithmParameterSpec"),
        jni_sig!("(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
        &[JValue::from(&curve)],
    )?;
    let sha256 = env.new_string("SHA-256")?;
    let digests = env.new_object_array(1, jni_str!("java/lang/String"), &sha256)?;
    env.call_method(
        &builder,
        jni_str!("setDigests"),
        jni_sig!("([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
        &[JValue::from(&digests)],
    )?;
    if strongbox {
        env.call_method(
            &builder,
            jni_str!("setIsStrongBoxBacked"),
            jni_sig!("(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
            &[JValue::Bool(true)],
        )?;
    }
    let spec = env.call_method(&builder, jni_str!("build"), jni_sig!("()Landroid/security/keystore/KeyGenParameterSpec;"), &[])?.l()?;
    let (algorithm, provider) = (env.new_string("EC")?, env.new_string("AndroidKeyStore")?);
    let generator = env
        .call_static_method(
            jni_str!("java/security/KeyPairGenerator"),
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;"),
            &[JValue::from(&algorithm), JValue::from(&provider)],
        )?
        .l()?;
    env.call_method(&generator, jni_str!("initialize"), jni_sig!("(Ljava/security/spec/AlgorithmParameterSpec;)V"), &[JValue::from(&spec)])?;
    let pair = env.call_method(&generator, jni_str!("generateKeyPair"), jni_sig!("()Ljava/security/KeyPair;"), &[])?.l()?;
    let public = env.call_method(&pair, jni_str!("getPublic"), jni_sig!("()Ljava/security/PublicKey;"), &[])?.l()?;
    encoded(env, &public)
}

/// The private key the Keystore holds under `alias` (a handle; its bytes never leave the Keystore).
fn private_key<'local>(env: &mut Env<'local>, alias: &str) -> JniResult<JObject<'local>> {
    let store = key_store(env)?;
    let name = env.new_string(alias)?;
    let none = JObject::null();
    env.call_method(&store, jni_str!("getKey"), jni_sig!("(Ljava/lang/String;[C)Ljava/security/Key;"), &[JValue::from(&name), JValue::from(&none)])?
        .l()
}

/// `SHA256withECDSA` over `message` with the key under `alias`: a DER signature.
fn sign(env: &mut Env<'_>, alias: &str, message: &[u8]) -> JniResult<Vec<u8>> {
    let key = private_key(env, alias)?;
    if key.is_null() {
        return Err(jni::errors::Error::NullPtr("no key under this alias"));
    }
    let algorithm = env.new_string("SHA256withECDSA")?;
    let signature = env
        .call_static_method(
            jni_str!("java/security/Signature"),
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljava/security/Signature;"),
            &[JValue::from(&algorithm)],
        )?
        .l()?;
    env.call_method(&signature, jni_str!("initSign"), jni_sig!("(Ljava/security/PrivateKey;)V"), &[JValue::from(&key)])?;
    let data = env.byte_array_from_slice(message)?;
    env.call_method(&signature, jni_str!("update"), jni_sig!("([B)V"), &[JValue::from(&data)])?;
    let signed = env.call_method(&signature, jni_str!("sign"), jni_sig!("()[B"), &[])?.l()?;
    let signed = env.cast_local::<JByteArray>(signed)?;
    env.convert_byte_array(&signed)
}

/// Where the Keystore says the key under `alias` lives (`KeyInfo`); `Unknown` if it will not say.
fn key_location(env: &mut Env<'_>, alias: &str) -> KeyLocation {
    let location = (|| -> JniResult<KeyLocation> {
        let key = private_key(env, alias)?;
        let algorithm = env.call_method(&key, jni_str!("getAlgorithm"), jni_sig!("()Ljava/lang/String;"), &[])?.l()?;
        let provider = env.new_string("AndroidKeyStore")?;
        let factory = env
            .call_static_method(
                jni_str!("java/security/KeyFactory"),
                jni_str!("getInstance"),
                jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyFactory;"),
                &[JValue::from(&algorithm), JValue::from(&provider)],
            )?
            .l()?;
        let info_class = env.find_class(jni_str!("android/security/keystore/KeyInfo"))?;
        let info = env
            .call_method(
                &factory,
                jni_str!("getKeySpec"),
                jni_sig!("(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;"),
                &[JValue::from(&key), JValue::from(&info_class)],
            )?
            .l()?;
        let api = env.get_static_field(jni_str!("android/os/Build$VERSION"), jni_str!("SDK_INT"), jni_sig!("I"))?.i()?;
        if api >= API_31 {
            let level = env.call_method(&info, jni_str!("getSecurityLevel"), jni_sig!("()I"), &[])?.i()?;
            return Ok(match level {
                SECURITY_LEVEL_STRONGBOX => KeyLocation::SecureElement,
                SECURITY_LEVEL_TRUSTED_ENVIRONMENT => KeyLocation::TrustedEnvironment,
                SECURITY_LEVEL_SOFTWARE => KeyLocation::Software,
                _ => KeyLocation::Unknown,
            });
        }
        let inside = env.call_method(&info, jni_str!("isInsideSecureHardware"), jni_sig!("()Z"), &[])?.z()?;
        Ok(if inside { KeyLocation::TrustedEnvironment } else { KeyLocation::Software })
    })();
    if env.exception_check() {
        env.exception_clear();
    }
    location.unwrap_or(KeyLocation::Unknown)
}
