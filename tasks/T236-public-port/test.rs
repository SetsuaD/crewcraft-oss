//! T236: a server behind port forwarding records the port people connect to, and invitations carry it.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_server::server_install::{self, PUBLIC_PORT_FILE, ServerConfig};
use crewcraft_server::server_name::ServerName;

fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t236-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(listen: &str) -> ServerConfig {
    ServerConfig { name: ServerName::parse("chat.example.org").unwrap(), listen: listen.parse().unwrap() }
}

#[test]
fn links_use_the_listen_port_unless_a_public_port_is_recorded() {
    let config = config("0.0.0.0:7443");
    assert_eq!(server_install::link_server(&config, None), "chat.example.org:7443");
    assert_eq!(server_install::link_server(&config, Some(443)), "chat.example.org:443");
    let v6 = ServerConfig { name: ServerName::parse("2001:db8::7").unwrap(), listen: "[::]:7443".parse().unwrap() };
    assert_eq!(server_install::link_server(&v6, Some(8443)), "[2001:db8::7]:8443");
}

#[test]
fn the_public_port_is_recorded_once_and_read_back() {
    let dir = scratch("record");
    assert_eq!(server_install::read_public_port(&dir).unwrap(), None);
    server_install::write_public_port(&dir, 443).unwrap();
    assert_eq!(server_install::read_public_port(&dir).unwrap(), Some(443));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join(PUBLIC_PORT_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Recorded once: a second write is refused and the first value stays.
    assert_eq!(server_install::write_public_port(&dir, 8443).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(server_install::read_public_port(&dir).unwrap(), Some(443));
    assert!(server_install::write_public_port(&scratch("zero-write"), 0).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_damaged_public_port_file_is_refused() {
    for (tag, text) in [("word", "https\n"), ("zero", "0\n"), ("big", "70000\n"), ("long", "12345678901234567890\n")] {
        let dir = scratch(tag);
        let path = dir.join(PUBLIC_PORT_FILE);
        fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(server_install::read_public_port(&dir).is_err(), "{tag}");
        let _ = fs::remove_dir_all(&dir);
    }
}
