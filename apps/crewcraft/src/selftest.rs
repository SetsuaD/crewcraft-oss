//! The phone self-test (tasks T403 and T422), built only with the `selftest` feature, never in a release. On the
//! Android emulator and the iOS simulator it runs, against a real `crewcraft-server`, what the app does with the
//! platform's hardware key store: join from an invitation link, make the device key in the key store, enroll (the
//! certificate request is signed there), save the record, read it back, and sign in over mutual TLS (every handshake
//! signed there). Started a second time, it finds the saved record and only signs in.
//!
//! The platform shell passes the key store and the test account, fixed when the test app is built. The test answers
//! the authenticator step itself from the setup link the server sends, which only a test may do. Each step is reported
//! through `say`, as a line starting `CrewCraft self-test:`. Called by: the Android and iOS shells. Calls: `device`,
//! `device_store`, `app`.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_totp::{Totp, base32};

use crate::app::{JOIN_TIMEOUT, PROFILE, join_from_link};
use crate::device::NewDevice;
use crate::device_store::{DeviceStore, StoreError};
use crate::enroll_client::FirstTotpCode;
use crate::hardware_key::{HardwareKeys, new_alias};
use crate::signed_in::Credentials;

/// The file in the data folder that keeps the test account's authenticator secret between the two runs (test only).
const SECRET_FILE: &str = "selftest-totp";

/// The test server's account: its invitation link, the person's email and the password the test sets.
#[derive(Clone, Copy)]
pub struct Account<'a> {
    pub link: &'a str,
    pub email: &'a str,
    pub password: &'a str,
}

/// Run the self-test with the device key in `keys` and the record in `dir`, reporting each step through `say`, and
/// report `PASS` or `FAIL` with the reason last.
pub fn run(dir: Option<&Path>, keys: Arc<dyn HardwareKeys>, account: Account<'_>, device_name: &str, say: &dyn Fn(&str)) {
    match test(dir, keys, account, device_name, say) {
        Ok(summary) => say(&format!("CrewCraft self-test: PASS {summary}")),
        Err(problem) => say(&format!("CrewCraft self-test: FAIL {problem}")),
    }
}

fn test(dir: Option<&Path>, keys: Arc<dyn HardwareKeys>, account: Account<'_>, device_name: &str, say: &dyn Fn(&str)) -> Result<String, String> {
    let dir = dir.ok_or("no data folder")?;
    let store = DeviceStore::open_hardware(dir, keys.clone()).map_err(|error| format!("store: {error:?}"))?;
    let enrolled_now = match store.load(PROFILE) {
        Ok(_) => false,
        Err(StoreError::NotFound) => {
            enroll(dir, &store, keys.clone(), account, device_name, say)?;
            true
        }
        Err(error) => return Err(format!("load: {error:?}")),
    };
    // Read the record back as a fresh start would, then sign in with a code from the next time step (the server
    // refuses a code it has already accepted).
    let device = store.load(PROFILE).map_err(|error| format!("reload: {error:?}"))?;
    let alias = device.hardware_alias().ok_or("the record names no hardware key")?.to_owned();
    let location = keys.open(&alias).map_err(|error| format!("open key: {error}"))?.location();
    say(&format!("CrewCraft self-test: record loaded, key {alias} in {location:?}"));
    let record = std::fs::read(store.path(PROFILE).map_err(|error| format!("path: {error:?}"))?).map_err(|error| format!("read: {error}"))?;
    if !record.starts_with(b"crewcraft device v3\n") {
        return Err("the record is not a hardware-key record".into());
    }
    let totp = read_secret(dir)?;
    let code = next_code(&totp);
    let credentials = Credentials::new(account.email, account.password, &code).ok_or("credentials")?;
    let mut session = device.sign_in(&credentials).map_err(|error| format!("sign in: {error:?}"))?;
    let rooms = session.list_rooms().map_err(|error| format!("rooms: {error:?}"))?.map_or(0, |rooms| rooms.len());
    Ok(format!("enrolled_now={enrolled_now} key_location={location:?} rooms={rooms}"))
}

fn enroll(
    dir: &Path,
    store: &DeviceStore,
    keys: Arc<dyn HardwareKeys>,
    account: Account<'_>,
    device_name: &str,
    say: &dyn Fn(&str),
) -> Result<(), String> {
    let (endpoint, code) = join_from_link(JOIN_TIMEOUT)(account.link)?;
    say(&format!("CrewCraft self-test: joined {}", endpoint.address()));
    let device = NewDevice::generate_in(keys, &new_alias(PROFILE)).map_err(|error| format!("generate: {error:?}"))?;
    say("CrewCraft self-test: key made in the key store");
    let mut secret = None;
    let enrolled = device
        .enroll(&endpoint, &code, Duration::from_secs(120), device_name, account.password, |setup, _deadline| {
            let totp = totp_from_uri(setup.protected_uri())?;
            let first = totp.generate(now());
            secret = Some(totp);
            FirstTotpCode::parse(first)
        })
        .map_err(|error| format!("enroll: {error:?}"))?;
    let totp = secret.ok_or("the server sent no authenticator setup")?;
    std::fs::write(dir.join(SECRET_FILE), base32::encode_nopad(totp.secret())).map_err(|error| format!("secret: {error}"))?;
    store.save(PROFILE, &enrolled).map_err(|error| format!("save: {error:?}"))?;
    say("CrewCraft self-test: enrolled and saved");
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
