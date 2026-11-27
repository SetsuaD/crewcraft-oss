//! Separate loopback HTTPS ingress for the synthetic browser guest lobby.

mod http;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crewcraft_server_core::durable::DurableServer;
use crewcraft_strict_toml as toml;
use crewcraft_tls::{DeadlineSocket, Identity};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use zeroize::Zeroizing;

use crate::listener::Listener;
use crate::server_install::read_file;

pub const CONFIG_FILE: &str = "guest-lab.toml";
const CERTIFICATE_FILE: &str = "guest-lab.pem";
const PRIVATE_KEY_FILE: &str = "guest-lab-key.pem";
const SETTINGS_LIMIT: u64 = 4 * 1024;
const PEM_LIMIT: u64 = 64 * 1024;
const CONNECTION_LIMIT: usize = 16;
const DEADLINE: Duration = Duration::from_secs(5);

struct ConnectionBudget {
    expires: Instant,
    total: u16,
    per_source: BTreeMap<IpAddr, u16>,
}

impl ConnectionBudget {
    fn take(&mut self, peer: IpAddr, now: Instant) -> bool {
        if now >= self.expires {
            self.expires = now + Duration::from_secs(1);
            self.total = 0;
            self.per_source.clear();
        }
        if self.total == 256 {
            return false;
        }
        let count = self.per_source.entry(peer).or_default();
        if *count == 64 {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}

/// A guest listener with its own HTTPS identity. It shares no staff accept or authentication path.
pub struct GuestLab {
    listener: Listener,
    authority: String,
    config: Arc<ServerConfig>,
}

impl GuestLab {
    /// Only loopback can be bound. The allowed host is localhost or the listener's literal address.
    pub fn bind(address: SocketAddr, host: &str, identity: Identity) -> io::Result<Self> {
        let host = if host.eq_ignore_ascii_case("localhost") {
            "localhost".to_owned()
        } else {
            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) if address.ip() == IpAddr::V4(ip) => ip.to_string(),
                Ok(IpAddr::V6(ip)) if address.ip() == IpAddr::V6(ip) => format!("[{ip}]"),
                _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "guest lab host must match the loopback listener")),
            }
        };
        let capacity = NonZeroUsize::new(CONNECTION_LIMIT).unwrap_or(NonZeroUsize::MIN);
        let listener = Listener::bind(address, capacity)?;
        let port = listener.local_addr()?.port();
        let authority = if port == 443 { host } else { format!("{host}:{port}") };
        let tls = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(identity.0, identity.1)
            .map_err(io::Error::other)?;
        Ok(Self { listener, authority, config: Arc::new(tls) })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run until shutdown with separate TLS and HTTP I/O deadlines and a budget before either.
    pub fn serve(self, shutdown: &AtomicBool, rooms: Arc<Mutex<DurableServer>>, now_ms: impl Fn() -> u64 + Send + Sync + 'static) -> io::Result<()> {
        let Self { listener, authority, config } = self;
        let origin = format!("https://{authority}");
        let budget = Mutex::new(ConnectionBudget { expires: Instant::now(), total: 0, per_source: BTreeMap::new() });
        listener.serve(shutdown, move |tcp| {
            let Ok(peer) = tcp.peer_addr() else { return };
            let peer = peer.ip().to_canonical();
            if !peer.is_loopback() || !budget.lock().is_ok_and(|mut state| state.take(peer, Instant::now())) {
                return;
            }
            let Ok(connection) = ServerConnection::new(config.clone()) else { return };
            let mut stream = StreamOwned::new(connection, DeadlineSocket::new(tcp, Instant::now() + DEADLINE));
            while stream.conn.is_handshaking() {
                if stream.conn.complete_io(&mut stream.sock).is_err() {
                    return;
                }
            }
            stream.sock.set_deadline(Instant::now() + DEADLINE);
            let _ = http::serve(&mut stream, &authority, &origin, &rooms, peer, &now_ms);
            stream.conn.send_close_notify();
            let _ = stream.flush();
        })
    }
}

/// Guest serving is disabled by default. A configured listener uses fixed, separate lab PEM files.
pub fn load(data: &Path) -> io::Result<Option<GuestLab>> {
    let bytes = match read_file(&data.join(CONFIG_FILE), SETTINGS_LIMIT, false) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let doc = toml::parse(text, SETTINGS_LIMIT as usize).map_err(io::Error::other)?;
    doc.check_sections(&["guest-lab"], &[]).map_err(io::Error::other)?;
    let options = doc.require("guest-lab").map_err(io::Error::other)?;
    options.check_keys("guest-lab", &["listen", "host"]).map_err(io::Error::other)?;
    let (address, _) = options.req_str("guest-lab", "listen").map_err(io::Error::other)?;
    let address: SocketAddr = address.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid guest lab listen address"))?;
    if !address.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "guest lab listener must bind to loopback"));
    }
    let (host, _) = options.req_str("guest-lab", "host").map_err(io::Error::other)?;
    let certificate = read_file(&data.join(CERTIFICATE_FILE), PEM_LIMIT, false)?;
    let key = Zeroizing::new(read_file(&data.join(PRIVATE_KEY_FILE), PEM_LIMIT, true)?);
    let identity = crewcraft_tls::pem::identity(&certificate, &key)?;
    GuestLab::bind(address, host, identity).map(Some)
}
