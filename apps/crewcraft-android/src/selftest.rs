//! The emulator self-test for task T403, built only with the `selftest` feature (`cargo xtask apk --self-test`),
//! never in a release. Instead of the window it runs, against a real `crewcraft-server`, what the app does with the
//! Android Keystore: join from an invitation link, make the device key in the Keystore, enroll (the certificate
//! request is signed there), save the record, read it back, and sign in over mutual TLS (every handshake signed
//! there). Started a second time, it finds the saved record and only signs in. Each step and the result go to the log
//! (tag `CrewCraft`) as lines starting `CrewCraft self-test:`.
//!
//! The invitation link, the email and the password are fixed when the APK is built (`CREWCRAFT_SELFTEST_LINK`,
//! `CREWCRAFT_SELFTEST_EMAIL`, `CREWCRAFT_SELFTEST_PASSWORD`): a self-test APK is made for one test server and
//! thrown away. It answers the authenticator step itself from the setup link the server sends, which only a test
//! may do. Called by: `shell`. Calls: `crewcraft`, `keystore`.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft::app::{JOIN_TIMEOUT, PROFILE, join_from_link};
use crewcraft::device::NewDevice;
use crewcraft::device_store::{DeviceStore, StoreError};
use crewcraft::enroll_client::FirstTotpCode;
use crewcraft::hardware_key::{HardwareKeys, new_alias};
use crewcraft::signed_in::Credentials;
use crewcraft_totp::{Totp, base32};

use crate::keystore::AndroidKeystore;

const LINK: &str = env!("CREWCRAFT_SELFTEST_LINK");
const EMAIL: &str = env!("CREWCRAFT_SELFTEST_EMAIL");
const PASSWORD: &str = env!("CREWCRAFT_SELFTEST_PASSWORD");
/// The file in the data folder that keeps the test account's authenticator secret between the two runs (test only).
const SECRET_FILE: &str = "selftest-totp";

/// Run the self-test and log `PASS` or `FAIL` with the reason.
pub fn run(dir: Option<&Path>) {
    match test(dir) {
        Ok(summary) => log::info!("CrewCraft self-test: PASS {summary}"),
        Err(problem) => log::error!("CrewCraft self-test: FAIL {problem}"),
    }
}

fn test(dir: Option<&Path>) -> Result<String, String> {
    let dir = dir.ok_or("no data folder")?;
    let keys: Arc<dyn HardwareKeys> = Arc::new(AndroidKeystore::new().map_err(|error| format!("keystore: {error}"))?);
    let store = DeviceStore::open_hardware(dir, keys.clone()).map_err(|error| format!("store: {error:?}"))?;
    let enrolled_now = match store.load(PROFILE) {
        Ok(_) => false,
        Err(StoreError::NotFound) => {
            enroll(dir, &store, keys.clone())?;
            true
        }
        Err(error) => return Err(format!("load: {error:?}")),
    };
    // Read the record back as a fresh start would, then sign in with a code from the next time step (the server
    // refuses a code it has already accepted).
    let device = store.load(PROFILE).map_err(|error| format!("reload: {error:?}"))?;
    let alias = device.hardware_alias().ok_or("the record names no hardware key")?.to_owned();
    let location = keys.open(&alias).map_err(|error| format!("open key: {error}"))?.location();
    log::info!("CrewCraft self-test: record loaded, key {alias} in {location:?}");
    let record = std::fs::read(store.path(PROFILE).map_err(|error| format!("path: {error:?}"))?).map_err(|error| format!("read: {error}"))?;
    if !record.starts_with(b"crewcraft device v3\n") {
        return Err("the record is not a hardware-key record".into());
    }
    let totp = read_secret(dir)?;
    let code = next_code(&totp);
    let credentials = Credentials::new(EMAIL, PASSWORD, &code).ok_or("credentials")?;
    let mut session = device.sign_in(&credentials).map_err(|error| format!("sign in: {error:?}"))?;
    let rooms = session.list_rooms().map_err(|error| format!("rooms: {error:?}"))?.map_or(0, |rooms| rooms.len());
    Ok(format!("enrolled_now={enrolled_now} key_location={location:?} rooms={rooms}"))
}

fn enroll(dir: &Path, store: &DeviceStore, keys: Arc<dyn HardwareKeys>) -> Result<(), String> {
    let (endpoint, code) = join_from_link(JOIN_TIMEOUT)(LINK)?;
    log::info!("CrewCraft self-test: joined {}", endpoint.address());
    let device = NewDevice::generate_in(keys, &new_alias(PROFILE)).map_err(|error| format!("generate: {error:?}"))?;
    log::info!("CrewCraft self-test: key made in the Keystore");
    let mut secret = None;
    let enrolled = device
        .enroll(&endpoint, &code, Duration::from_secs(120), "CrewCraft self-test on Android", PASSWORD, |setup, _deadline| {
            let totp = totp_from_uri(setup.protected_uri())?;
            let first = totp.generate(now());
            secret = Some(totp);
            FirstTotpCode::parse(first)
        })
        .map_err(|error| format!("enroll: {error:?}"))?;
    let totp = secret.ok_or("the server sent no authenticator setup")?;
    std::fs::write(dir.join(SECRET_FILE), base32::encode_nopad(totp.secret())).map_err(|error| format!("secret: {error}"))?;
    store.save(PROFILE, &enrolled).map_err(|error| format!("save: {error:?}"))?;
    log::info!("CrewCraft self-test: enrolled and saved");
    Ok(())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// A code from the next time step, waiting for it to start.
fn next_code(totp: &Totp) -> String {
    let step = totp.step().max(1);
    let wait = step - now() % step + 1;
    std::thread::sleep(Duration::from_secs(wait));
    totp.generate(now())
}

fn totp_from_uri(uri: &str) -> Option<Totp> {
    let query = uri.split_once('?')?.1;
    let secret = query.split('&').find_map(|pair| pair.strip_prefix("secret="))?;
    Totp::with_defaults(base32::decode(secret).ok()?).ok()
}

fn read_secret(dir: &Path) -> Result<Totp, String> {
    let text = std::fs::read_to_string(dir.join(SECRET_FILE)).map_err(|error| format!("secret: {error}"))?;
    Totp::with_defaults(base32::decode(text.trim()).map_err(|_| "secret: not base32")?).map_err(|_| "secret: unusable".to_owned())
}
