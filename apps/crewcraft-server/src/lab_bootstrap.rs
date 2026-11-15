//! Drive the durable enrollment handler on the listener's admitted bootstrap stream.

use std::io::Write;
use std::sync::{Arc, Mutex};

use crewcraft_accounts::password;
use crewcraft_bootstrap::{BootstrapConnection, Enroller, Environment, StoreServices, receive_shared};
use crewcraft_pki::Authority;
use crewcraft_proto::bootstrap::{MAX_CSR, MAX_DEVICE_NAME, MAX_PASSWORD};
use crewcraft_proto::frame::read_frame;
use crewcraft_server_core::account_store::AccountStore;

use crate::lab_server::BootstrapStream;

// One tag, a request id and three length-prefixed fields.
const MAX_BOOTSTRAP_REQUEST: usize = 1 + 4 + 3 * 2 + MAX_DEVICE_NAME + MAX_CSR + MAX_PASSWORD;

pub fn bootstrap_handler(
    accounts: Arc<Mutex<AccountStore>>,
    authority: Authority,
    environment: impl Environment + Send + 'static,
) -> impl Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static {
    let handler = Mutex::new(Enroller::new(authority, StoreServices::new_shared(accounts, environment)));
    move |key, stream| {
        // Every peer on the lab listener comes from the IPv4 loopback address.
        let mut connection = BootstrapConnection::new(key, "127.0.0.1");
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
