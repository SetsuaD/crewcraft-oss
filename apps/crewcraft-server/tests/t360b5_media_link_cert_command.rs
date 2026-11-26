//! T360b5: `crewcraft-server media-link-cert <data-directory> <media-server-name> <media-output-directory>` issues the
//! media control link's certificates (the link itself is proved in apps/crewcraft-media-server's T360b5 test).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_server::media_link::{CHAT_LINK_FILES, MEDIA_LINK_FILES};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_command_writes_both_ends_and_refuses_a_bad_name() {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("crewcraft-t360b5-command-{}-{nanos}", std::process::id())));
    let (data, media) = (scratch.0.join("data"), scratch.0.join("media"));
    std::fs::create_dir_all(&data).unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_crewcraft-server"));

    let out = Command::new(binary).arg("media-link-cert").arg(&data).arg("media.example.org").arg(&media).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Copy media.pem, media-key.pem and chat-ca.pem"));
    for name in CHAT_LINK_FILES {
        assert!(data.join(name).is_file(), "{name} in the data directory");
    }
    for name in MEDIA_LINK_FILES {
        assert!(media.join(name).is_file(), "{name} for the media server");
    }

    let refused = Command::new(binary).arg("media-link-cert").arg(&data).arg("not a name").arg(&media).output().unwrap();
    assert!(!refused.status.success(), "a name that is no server name is refused");
}
