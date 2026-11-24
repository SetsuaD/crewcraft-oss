//! The resume ticket kept between runs of the app (task T240): the file `resume-ticket` in the app's data folder, next
//! to the device record. It holds the person's email and the session token, one per line.
//!
//! Owns: reading, writing (a new owner-only file, synced, then renamed over the old one) and deleting that file. Called
//! by the connection worker, through `worker::TicketKeeper`. The token alone opens nothing: the server accepts it only
//! over a TLS connection signed with this device's key, within 12 hours of the sign-in, so a copied file is useless
//! without the device key (which the OS key store seals, or a hardware key store holds). On Unix the file is `0600`
//! and a looser or linked file is ignored.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::signed_in::ResumeTicket;
use crate::worker::TicketKeeper;

/// The file's name in the data folder.
pub const TICKET_FILE: &str = "resume-ticket";
/// No ticket file is longer than this.
const MAX_TICKET_FILE: u64 = 512;

/// The ticket file in one data folder.
#[derive(Debug, Clone)]
pub struct TicketFile {
    dir: PathBuf,
}

impl TicketFile {
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf() }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(TICKET_FILE)
    }

    fn read(&self) -> Option<ResumeTicket> {
        let path = self.path();
        let link = fs::symlink_metadata(&path).ok()?;
        if !link.file_type().is_file() || !private(&link) {
            return None;
        }
        let mut text = Zeroizing::new(String::new());
        File::open(&path).ok()?.take(MAX_TICKET_FILE).read_to_string(&mut text).ok()?;
        let mut lines = text.lines();
        let (email, token) = (lines.next()?, lines.next()?);
        if lines.next().is_some() {
            return None;
        }
        ResumeTicket::new(email, token)
    }

    fn write(&self, ticket: &ResumeTicket) -> std::io::Result<()> {
        let text = Zeroizing::new(format!("{}\n{}\n", ticket.email(), ticket.token()));
        let temporary = self.dir.join(format!(".{TICKET_FILE}.{}.tmp", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let written = options.open(&temporary).and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        });
        let renamed = written.and_then(|()| fs::rename(&temporary, self.path()));
        if renamed.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        renamed
    }
}

impl TicketKeeper for TicketFile {
    fn load(&self) -> Option<ResumeTicket> {
        self.read()
    }

    fn save(&self, ticket: &ResumeTicket) {
        // A ticket that cannot be saved only means the next start asks for a code again.
        if self.write(ticket).is_err() {
            let _ = fs::remove_file(self.path());
        }
    }

    fn clear(&self) {
        let _ = fs::remove_file(self.path());
    }
}

#[cfg(unix)]
fn private(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private(_: &fs::Metadata) -> bool {
    true
}
