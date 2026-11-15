#![allow(clippy::unwrap_used)]

use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{BootstrapStream, LabOptions, Timeouts};
use crewcraft_server::lab_state::LabState;

const NOW_MS: u64 = 1_800_000_000_000;

struct StatePath(PathBuf);

impl StatePath {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("crewcraft-t227-{}-{nonce}", std::process::id())))
    }
}

impl Drop for StatePath {
    fn drop(&mut self) {
        for name in ["service.key", "issuer.state", "accounts.journal", "rooms.journal", "state.lock"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn binds_loaded_state_and_keeps_exclusive_ownership_during_serve_setup() {
    let path = StatePath::new();
    let initial = LabInstallation::initialize(&path.0, NOW_MS).unwrap();
    let pin = initial.issuer.root_fingerprint();
    let (_, issuer) = initial.issuer.into_parts();
    let issuer_der = issuer.certificate().to_vec();
    drop(issuer);
    drop(initial.accounts);
    drop(initial.rooms);
    drop(initial.ownership);

    let installation = LabInstallation::open(&path.0, pin, NOW_MS).unwrap();
    let limit = Duration::from_secs(2);
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(1).unwrap(),
        timeouts: Timeouts { handshake: limit, sign_in: limit, signed_in_frame: limit, bootstrap: limit },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "lab".into() },
    };
    let runtime = LabRuntime::bind(installation, options, || NOW_MS).unwrap();
    let address = runtime.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    assert!(matches!(LabState::open(&path.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock));

    let mut factory_called = false;
    runtime
        .serve(&AtomicBool::new(true), |accounts, authority| {
            assert!(matches!(LabState::open(&path.0), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            assert_eq!(authority.certificate(), issuer_der.as_slice());
            assert!(accounts.lock().unwrap().healthy());
            factory_called = true;
            Ok(|_: [u8; 32], _: &mut BootstrapStream| {})
        })
        .unwrap();
    assert!(factory_called);
    assert!(LabInstallation::open(&path.0, pin, NOW_MS).is_ok());
}
