//! Drive the durable enrollment handler on the listener's admitted bootstrap stream.

use std::io::Write;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crewcraft_accounts::password;
use crewcraft_bootstrap::{BootstrapConnection, Enroller, Environment, ExternalEnrollment, StoreServices, receive_shared};
use crewcraft_pki::Authority;
use crewcraft_proto::bootstrap::{MAX_CSR, MAX_DEVICE_NAME, MAX_PASSWORD};
use crewcraft_proto::frame::read_frame;
use crewcraft_proto::signin::{MAX_AUTH_CODE_BYTES, MAX_REDIRECT_BYTES, MAX_VERIFIER_LEN};
use crewcraft_server_core::account_store::AccountStore;

use crate::lab_server::BootstrapStream;

// One tag, a request id and three length-prefixed fields.
const MAX_BOOTSTRAP_REQUEST: usize = 1 + 4 + 3 * 2 + MAX_DEVICE_NAME + MAX_CSR + MAX_PASSWORD;
// `ConfirmExternal` (task T611i), the other three-field request, fits too.
const _: () = assert!(1 + 4 + 3 * 2 + MAX_AUTH_CODE_BYTES + MAX_VERIFIER_LEN + MAX_REDIRECT_BYTES <= MAX_BOOTSTRAP_REQUEST);

pub fn bootstrap_handler(
    accounts: Arc<Mutex<AccountStore>>,
    authority: Authority,
    environment: impl Environment + Send + 'static,
) -> impl Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static {
    bootstrap_handler_with(accounts, authority, environment, None)
}

/// As `bootstrap_handler`; with `external`, invitations are redeemed through the server's identity provider instead of
/// a password and an authenticator (task T611i).
pub fn bootstrap_handler_with(
    accounts: Arc<Mutex<AccountStore>>,
    authority: Authority,
    environment: impl Environment + Send + 'static,
    external: Option<Arc<dyn ExternalEnrollment>>,
) -> impl Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static {
    let enroller = Enroller::new(authority, StoreServices::new_shared(accounts, environment));
    let handler = Mutex::new(match external {
        Some(external) => enroller.with_external(external),
        None => enroller,
    });
    move |key, stream| {
        let mut connection = BootstrapConnection::new(key, &source_key(stream.peer_ip()));
        while let Ok(Some(frame)) = read_frame(stream, MAX_BOOTSTRAP_REQUEST) {
            let reply = receive_shared(&mut connection, &handler, &|secret| password::hash(secret).ok(), frame.as_bytes());
            if !reply.bytes.is_empty() && stream.write_all(&reply.bytes).and_then(|()| stream.flush()).is_err() {
                return;
            }
            if !reply.open {
                return;
            }
        }
    }
}

/// The bucket a peer's enrollment calls are counted in: an IPv4 address on its own, an IPv6 address by its /64
/// prefix, because a single IPv6 host is usually given a whole /64 and could otherwise pick a new address per guess.
/// An IPv4 address carried in IPv6 (`::ffff:a.b.c.d`) counts as that IPv4 address.
pub fn source_key(peer: IpAddr) -> String {
    match peer.to_canonical() {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let [a, b, c, d, ..] = address.segments();
            format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
        }
    }
}
