// Update rules (REQUIREMENTS 2.21): versions, signed manifests, artifact checks, server decisions, rollback, rollout.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_strict_toml::Error as TomlError;
use crewcraft_update::{
    ArtifactVerifier, Channel, ClientOffer, InstallEvent, InstallState, Kind, ReleaseError, Rollout, ServerDecision, ServerPolicy, SignatureCheck,
    UpdateMode, Version, WebClientStatus, Window, decide_server, offer_client, open_release, parse_manifest, rollout_bucket, step, verify_artifact,
    web_client_status,
};

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

// SHA-256 of b"abc".
const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn manifest(version: &str, channel: &str, min_client: &str) -> String {
    format!(
        "[release]\nproduct = \"crewcraft\"\nversion = \"{version}\"\nchannel = \"{channel}\"\npublished = \"2026-11-14\"\nmin-client = \"{min_client}\"\n\n\
         [artifact.server-linux]\nkind = \"server\"\nplatform = \"linux-x64\"\nfile = \"crewcraft-server-linux-x64.tar.zst\"\nsize = 3\nsha256 = \"{ABC}\"\n\n\
         [artifact.desktop-windows]\nkind = \"desktop\"\nplatform = \"windows-x64\"\nfile = \"crewcraft-setup.exe\"\nsize = 3\nsha256 = \"{ABC}\"\n"
    )
}

/// Accepts exactly one signature value, so tests can tell "checked" from "not checked".
struct FakeKey;
impl SignatureCheck for FakeKey {
    fn verify(&self, _message: &[u8], signature: &[u8]) -> bool {
        signature == b"good"
    }
}

fn policy(mode: UpdateMode) -> ServerPolicy {
    ServerPolicy { product: "crewcraft".into(), channel: Channel::Stable, mode, paused: false, held_back: vec![] }
}

#[test]
fn versions_parse_and_order() {
    assert_eq!(v("1.4.0").to_string(), "1.4.0");
    assert_eq!(v("1.4.0-beta.2").to_string(), "1.4.0-beta.2");
    for bad in ["1.4", "1.4.0.a", "01.4.0", "1.4.x", "1.4.0-", "1.4.0-beta_2", "", "-1.0.0"] {
        assert_eq!(Version::parse(bad), None, "{bad}");
    }
    let ordered = [
        "0.9.9",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.10.0",
        "2.0.0",
    ];
    for pair in ordered.windows(2) {
        assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
    }
}

#[test]
fn manifest_parses() {
    let release = parse_manifest(&manifest("1.4.0", "stable", "1.2.0")).unwrap();
    assert_eq!(release.product, "crewcraft");
    assert_eq!(release.version, v("1.4.0"));
    assert_eq!(release.channel, Channel::Stable);
    assert_eq!(release.min_client, v("1.2.0"));
    assert_eq!(release.artifacts.len(), 2);
    let desktop = release.artifact(Kind::Desktop, "windows-x64").unwrap();
    assert_eq!(desktop.file, "crewcraft-setup.exe");
    assert_eq!(desktop.size, 3);
    assert!(release.artifact(Kind::Android, "android").is_none());
}

#[test]
fn manifest_refusals() {
    let ok = manifest("1.4.0", "stable", "1.2.0");
    let cases = [
        ok.replacen("channel = \"stable\"", "channel = \"nightly\"", 1),
        ok.replacen("min-client = \"1.2.0\"", "min-client = \"1.5.0\"", 1),
        ok.replacen("published = \"2026-11-14\"", "published = \"14/11/2026\"", 1),
        ok.replacen("platform = \"linux-x64\"", "platform = \"android\"", 1),
        ok.replacen("file = \"crewcraft-setup.exe\"", "file = \"../crewcraft-setup.exe\"", 1),
        ok.replacen("file = \"crewcraft-setup.exe\"", "file = \"sub/setup.exe\"", 1),
        ok.replacen("size = 3\nsha256", "size = 0\nsha256", 1),
        ok.replacen(&format!("sha256 = \"{ABC}\""), "sha256 = \"abc\"", 1),
        ok.replacen("kind = \"desktop\"", "kind = \"plugin\"", 1),
        ok.replacen("platform = \"windows-x64\"", "platform = \"linux-x64\"\nplatform-extra = 1", 1),
    ];
    for text in &cases {
        assert!(parse_manifest(text).is_err(), "{text}");
    }
    // Two artifacts for the same kind and platform.
    let dup = ok.replacen("kind = \"desktop\"\nplatform = \"windows-x64\"", "kind = \"server\"\nplatform = \"linux-x64\"", 1);
    assert!(matches!(parse_manifest(&dup), Err(TomlError::BadValue { .. })));
    assert!(matches!(parse_manifest(&format!("{ok}\n[extra]\n")), Err(TomlError::UnknownSection { .. })));
}

#[test]
fn unsigned_manifests_are_never_read() {
    let text = manifest("1.4.0", "stable", "1.2.0");
    assert_eq!(open_release(text.as_bytes(), b"forged", &FakeKey).unwrap_err(), ReleaseError::BadSignature);
    // Even garbage is refused for its signature first, before anyone parses it.
    assert_eq!(open_release(&[0xff, 0x00], b"forged", &FakeKey).unwrap_err(), ReleaseError::BadSignature);
    assert_eq!(open_release(&[0xff, 0x00], b"good", &FakeKey).unwrap_err(), ReleaseError::NotUtf8);
    assert_eq!(open_release(text.as_bytes(), b"good", &FakeKey).unwrap().version, v("1.4.0"));
}

#[test]
fn artifacts_are_checked_by_size_and_hash() {
    let release = parse_manifest(&manifest("1.4.0", "stable", "1.2.0")).unwrap();
    let artifact = release.artifact(Kind::Server, "linux-x64").unwrap();
    assert_eq!(verify_artifact(artifact, b"abc"), Ok(()));
    assert_eq!(verify_artifact(artifact, b"abd"), Err(ReleaseError::HashMismatch));
    assert_eq!(verify_artifact(artifact, b"ab"), Err(ReleaseError::SizeMismatch { expected: 3, actual: 2 }));

    let mut streaming = ArtifactVerifier::new(artifact);
    streaming.update(b"a").unwrap();
    streaming.update(b"bc").unwrap();
    assert_eq!(streaming.finish(), Ok(()));

    // A download that runs long fails at the chunk that overruns, not at the end.
    let mut long = ArtifactVerifier::new(artifact);
    long.update(b"ab").unwrap();
    assert_eq!(long.update(b"cd"), Err(ReleaseError::SizeMismatch { expected: 3, actual: 4 }));
}

#[test]
fn server_never_downgrades_and_checks_product_and_channel() {
    let release = parse_manifest(&manifest("1.4.0", "stable", "1.2.0")).unwrap();
    let auto = policy(UpdateMode::Automatic { window: None });
    assert_eq!(decide_server(&v("1.3.9"), &release, &auto, 3, None), Ok(ServerDecision::Install));
    assert_eq!(decide_server(&v("1.4.0"), &release, &auto, 3, None), Ok(ServerDecision::UpToDate));
    assert!(matches!(decide_server(&v("1.5.0"), &release, &auto, 3, None), Err(ReleaseError::Downgrade { .. })));

    let other = ServerPolicy { product: "something-else".into(), ..auto.clone() };
    assert!(matches!(decide_server(&v("1.3.9"), &release, &other, 3, None), Err(ReleaseError::WrongProduct { .. })));

    let beta = parse_manifest(&manifest("1.5.0-beta.1", "beta", "1.2.0")).unwrap();
    assert_eq!(decide_server(&v("1.4.0"), &beta, &auto, 3, None), Err(ReleaseError::WrongChannel));
    let on_beta = ServerPolicy { channel: Channel::Beta, ..auto };
    assert_eq!(decide_server(&v("1.4.0"), &beta, &on_beta, 3, None), Ok(ServerDecision::Install));
    assert_eq!(decide_server(&v("1.3.0"), &release, &on_beta, 3, None), Ok(ServerDecision::Install));
}

#[test]
fn server_policy_modes() {
    let release = parse_manifest(&manifest("1.4.0", "stable", "1.2.0")).unwrap();
    let running = v("1.3.0");
    let night = policy(UpdateMode::Automatic { window: Some(Window { start_hour: 22, end_hour: 4 }) });
    assert_eq!(decide_server(&running, &release, &night, 23, None), Ok(ServerDecision::Install));
    assert_eq!(decide_server(&running, &release, &night, 3, None), Ok(ServerDecision::Install));
    assert_eq!(decide_server(&running, &release, &night, 4, None), Ok(ServerDecision::WaitForWindow));
    assert_eq!(decide_server(&running, &release, &night, 12, None), Ok(ServerDecision::WaitForWindow));

    let approval = policy(UpdateMode::Approval);
    assert_eq!(decide_server(&running, &release, &approval, 12, None), Ok(ServerDecision::WaitForApproval));
    assert_eq!(decide_server(&running, &release, &approval, 12, Some(&v("1.3.5"))), Ok(ServerDecision::WaitForApproval));
    assert_eq!(decide_server(&running, &release, &approval, 12, Some(&v("1.4.0"))), Ok(ServerDecision::Install));

    assert_eq!(decide_server(&running, &release, &policy(UpdateMode::Pinned(v("1.3.5"))), 12, None), Ok(ServerDecision::Pinned));
    assert_eq!(decide_server(&running, &release, &policy(UpdateMode::Pinned(v("1.4.0"))), 12, None), Ok(ServerDecision::Install));

    let paused = ServerPolicy { paused: true, ..policy(UpdateMode::Automatic { window: None }) };
    assert_eq!(decide_server(&running, &release, &paused, 12, None), Ok(ServerDecision::Paused));
    let held = ServerPolicy { held_back: vec![v("1.4.0")], ..policy(UpdateMode::Automatic { window: None }) };
    assert_eq!(decide_server(&running, &release, &held, 12, None), Ok(ServerDecision::HeldBack));
}

#[test]
fn windows() {
    let all_day = Window { start_hour: 5, end_hour: 5 };
    assert!((0..24).all(|h| all_day.contains(h)));
    let day = Window { start_hour: 9, end_hour: 17 };
    assert!(day.contains(9) && day.contains(16) && !day.contains(17) && !day.contains(8));
}

#[test]
fn install_commits_or_rolls_back() {
    let staged = step(InstallState::Idle, InstallEvent::Staged { from: v("1.3.0"), to: v("1.4.0") }).unwrap();
    let waiting = step(staged, InstallEvent::Restarted).unwrap();
    assert_eq!(waiting, InstallState::AwaitingHealth { from: v("1.3.0"), to: v("1.4.0") });
    assert_eq!(step(waiting.clone(), InstallEvent::HealthOk).unwrap(), InstallState::Committed { version: v("1.4.0") });
    assert_eq!(
        step(waiting.clone(), InstallEvent::HealthFailed("database check failed".into())).unwrap(),
        InstallState::RolledBack { failed: v("1.4.0"), restored: v("1.3.0"), reason: "database check failed".into() }
    );
    assert!(matches!(step(waiting, InstallEvent::HealthTimeout).unwrap(), InstallState::RolledBack { .. }));
}

#[test]
fn install_refuses_out_of_order_events() {
    assert!(step(InstallState::Idle, InstallEvent::HealthOk).is_err());
    assert!(step(InstallState::Idle, InstallEvent::Restarted).is_err());
    // Staging an older or equal version is refused: the update path never goes back.
    assert!(step(InstallState::Idle, InstallEvent::Staged { from: v("1.4.0"), to: v("1.3.0") }).is_err());
    assert!(step(InstallState::Idle, InstallEvent::Staged { from: v("1.4.0"), to: v("1.4.0") }).is_err());
    let staged = InstallState::Staged { from: v("1.3.0"), to: v("1.4.0") };
    let err = step(staged.clone(), InstallEvent::HealthOk).unwrap_err();
    assert_eq!(err.state, staged);
    // After a rollback or a commit, a new attempt can start.
    let rolled = InstallState::RolledBack { failed: v("1.4.0"), restored: v("1.3.0"), reason: "x".into() };
    assert!(step(rolled, InstallEvent::Staged { from: v("1.3.0"), to: v("1.4.1") }).is_ok());
}

#[test]
fn rollout_buckets_are_stable_and_spread() {
    let version = v("1.4.0");
    assert_eq!(rollout_bucket(&version, "device-1"), rollout_bucket(&version, "device-1"));
    let buckets: Vec<u8> = (0..1000).map(|i| rollout_bucket(&version, &format!("device-{i}"))).collect();
    assert!(buckets.iter().all(|b| *b < 100));
    let under_half = buckets.iter().filter(|b| **b < 50).count();
    assert!((400..=600).contains(&under_half), "{under_half} of 1000 under 50");
}

#[test]
fn clients_are_offered_updates_by_rollout() {
    let release = parse_manifest(&manifest("1.4.0", "stable", "1.2.0")).unwrap();
    let everyone = Rollout { percent: 100, ..Rollout::default() };
    let nobody = Rollout::default();

    assert_eq!(offer_client(&release, &v("1.4.0"), Kind::Desktop, "windows-x64", "d", &everyone), ClientOffer::UpToDate);
    assert_eq!(
        offer_client(&release, &v("1.3.0"), Kind::Desktop, "windows-x64", "d", &everyone),
        ClientOffer::Available { version: v("1.4.0"), required: false }
    );
    assert_eq!(offer_client(&release, &v("1.3.0"), Kind::Desktop, "windows-x64", "d", &nobody), ClientOffer::NotYet);
    let pilot = Rollout { pilot_devices: vec!["pilot-pc".into()], ..Rollout::default() };
    assert!(matches!(offer_client(&release, &v("1.3.0"), Kind::Desktop, "windows-x64", "pilot-pc", &pilot), ClientOffer::Available { .. }));
    let paused = Rollout { percent: 100, paused: true, ..Rollout::default() };
    assert_eq!(offer_client(&release, &v("1.3.0"), Kind::Desktop, "windows-x64", "d", &paused), ClientOffer::NotYet);

    // Too old to be accepted: offered regardless of rollout or pause.
    assert_eq!(
        offer_client(&release, &v("1.1.0"), Kind::Desktop, "windows-x64", "d", &paused),
        ClientOffer::Available { version: v("1.4.0"), required: true }
    );
    assert_eq!(offer_client(&release, &v("1.1.0"), Kind::Desktop, "macos-universal", "d", &everyone), ClientOffer::NoBuild { required: true });
    assert_eq!(offer_client(&release, &v("1.3.0"), Kind::Android, "android", "d", &everyone), ClientOffer::NoBuild { required: false });

    // Percentage rollout follows the bucket exactly.
    let half = Rollout { percent: 50, ..Rollout::default() };
    for i in 0..200 {
        let device = format!("device-{i}");
        let offered = matches!(offer_client(&release, &v("1.3.0"), Kind::Desktop, "windows-x64", &device, &half), ClientOffer::Available { .. });
        assert_eq!(offered, rollout_bucket(&release.version, &device) < 50, "{device}");
    }
}

#[test]
fn web_clients_reload_when_told() {
    let release = parse_manifest(&manifest("1.4.0", "stable", "1.2.0")).unwrap();
    assert_eq!(web_client_status(&v("1.4.0"), &release), WebClientStatus::Current);
    assert_eq!(web_client_status(&v("1.3.0"), &release), WebClientStatus::ReloadOffered);
    assert_eq!(web_client_status(&v("1.1.9"), &release), WebClientStatus::ReloadRequired);
}
