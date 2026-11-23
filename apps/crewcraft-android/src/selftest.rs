//! The emulator self-test for task T403, built only with the `selftest` feature (`cargo xtask apk --self-test`),
//! never in a release: `crewcraft::selftest` with the device key in the Android Keystore, in place of the window.
//! Each step goes to the log (tag `CrewCraft`) as a line starting `CrewCraft self-test:`.
//!
//! The invitation link, the email and the password are fixed when the APK is built (`CREWCRAFT_SELFTEST_LINK`,
//! `CREWCRAFT_SELFTEST_EMAIL`, `CREWCRAFT_SELFTEST_PASSWORD`): a self-test APK is made for one test server and
//! thrown away. Called by: `shell`. Calls: `crewcraft::selftest`, `keystore`.

use std::path::Path;
use std::sync::Arc;

use crewcraft::hardware_key::HardwareKeys;
use crewcraft::selftest::Account;

use crate::keystore::AndroidKeystore;

const ACCOUNT: Account<'static> =
    Account { link: env!("CREWCRAFT_SELFTEST_LINK"), email: env!("CREWCRAFT_SELFTEST_EMAIL"), password: env!("CREWCRAFT_SELFTEST_PASSWORD") };

/// Run the self-test and log each step, then `PASS` or `FAIL` with the reason.
pub fn run(dir: Option<&Path>) {
    let say = |line: &str| {
        if line.contains("FAIL") { log::error!("{line}") } else { log::info!("{line}") }
    };
    match AndroidKeystore::new() {
        Ok(keys) => {
            let keys: Arc<dyn HardwareKeys> = Arc::new(keys);
            crewcraft::selftest::run(dir, keys, ACCOUNT, "CrewCraft self-test on Android", &say);
        }
        Err(error) => say(&format!("CrewCraft self-test: FAIL keystore: {error}")),
    }
}
