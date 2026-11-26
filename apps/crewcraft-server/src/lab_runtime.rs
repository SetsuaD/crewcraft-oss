//! Wire installed state to the server: the lab's loopback listener with a `localhost` certificate (task T227), or a
//! listener on any address with a certificate for the configured server name (task T230). Either way the server
//! presents the chain leaf, issuing authority, root, so a client can fetch the root it pins by fingerprint (T232).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crewcraft_accounts::throttle::Throttle;
use crewcraft_admission::Admission;
use crewcraft_bootstrap::SystemEnvironment;
use crewcraft_pki::{Authority, ServerIdentity};
use crewcraft_server_core::account_store::AccountStore;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_tls::Identity;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

#[cfg(unix)]
use crate::control::ControlSocket;
use crate::external_signin::ExternalSignIn;
use crate::lab_bootstrap::bootstrap_handler_with;
use crate::lab_installation::LabInstallation;
use crate::lab_server::{BootstrapStream, LabOptions, LabServer};
use crate::lab_state::LabState;
use crate::media_link::MediaLink;
use crate::server_name::ServerName;
use crate::stored_device_auth::StoredDeviceAuth;

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
type Bind = fn(LabOptions, Identity, RootCertStore, Arc<dyn Admission>, DurableServer) -> io::Result<LabServer>;

pub struct LabRuntime {
    server: LabServer,
    accounts: Arc<Mutex<AccountStore>>,
    issuer: Authority,
    now_ms: Clock,
    ownership: LabState,
    /// Sign-in through an external identity provider, when `identity.toml` configures one (task T611f).
    external: Option<Arc<ExternalSignIn>>,
    /// The media server's control connection, when `media.toml` configures one (task T360b3).
    media: Option<MediaLink>,
}

impl LabRuntime {
    /// Also offer sign-in through an external identity provider on every device connection (task T611f), and redeem
    /// invitations through it instead of a password and an authenticator (task T611i).
    pub fn with_external(mut self, external: Arc<ExternalSignIn>) -> Self {
        self.external = Some(external);
        self
    }

    /// Issue media credentials for `issuer`'s media server on every started or joined call (task T360b2), and run
    /// `link` beside the listener to tell that media server whom to drop (task T360b3).
    pub fn with_media(mut self, issuer: crewcraft_server_core::media::MediaIssuer, link: MediaLink) -> io::Result<Self> {
        self.server.rooms().lock().map_err(|_| io::Error::other("the room store is unavailable"))?.set_media(issuer);
        self.media = Some(link);
        Ok(self)
    }

    /// Bind with the installation's original trust anchor and a freshly signed localhost server certificate.
    /// `now_ms` supplies the server's current Unix time in milliseconds.
    pub fn bind(installation: LabInstallation, options: LabOptions, now_ms: impl Fn() -> u64 + Send + Sync + 'static) -> io::Result<Self> {
        Self::bind_as(installation, options, "localhost", LabServer::bind, Arc::new(now_ms))
    }

    /// Bind any local address (`options.address`), with a freshly signed server certificate for `name`, the name
    /// clients are told to verify. Everything else is as `bind`.
    pub fn bind_network(
        installation: LabInstallation,
        options: LabOptions,
        name: &ServerName,
        now_ms: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::bind_as(installation, options, &name.certificate_name(), LabServer::bind_network, Arc::new(now_ms))
    }

    fn bind_as(installation: LabInstallation, options: LabOptions, name: &str, bind: Bind, now_ms: Clock) -> io::Result<Self> {
        let LabInstallation { ownership, issuer, accounts, rooms } = installation;
        let (root, issuer) = issuer.into_parts();
        let ServerIdentity { mut chain, key_pkcs8 } =
            issuer.server_certificate(name, now_ms()).map_err(|_| io::Error::other("could not sign the server certificate"))?;
        // The chain ends with the root, so a client holding only the invitation's root fingerprint can fetch the root
        // it pins (task T232). The root is public; a client still accepts it only by that fingerprint.
        chain.push(root.clone());
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root)).map_err(io::Error::other)?;
        let identity = (chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(key_pkcs8).into());

        let accounts = Arc::new(Mutex::new(accounts));
        let admission: Arc<dyn Admission> = Arc::new(InstalledAdmission { accounts: accounts.clone(), now_ms: now_ms.clone() });
        let server = bind(options, identity, roots, admission, rooms)?;
        Ok(Self { server, accounts, issuer, now_ms, ownership, external: None, media: None })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.server.local_addr()
    }

    /// Serve normal device sign-in and the explicitly admitted invitation flow.
    pub fn serve_enrolled(self, shutdown: &AtomicBool) -> io::Result<()> {
        let external = self.enrollment();
        self.serve(shutdown, move |accounts, issuer| Ok(bootstrap_handler_with(accounts, issuer, SystemEnvironment, external)))
    }

    /// The provider invitations are redeemed through, if `identity.toml` configures one (task T611i).
    fn enrollment(&self) -> Option<Arc<dyn crewcraft_bootstrap::ExternalEnrollment>> {
        self.external.clone().map(|external| external as Arc<dyn crewcraft_bootstrap::ExternalEnrollment>)
    }

    /// As `serve_enrolled`, and answer `invite`, `room` and `add-member` on `control` while serving (task T238). The
    /// requests change the same live account store and room journal as the device sessions, under the same locks.
    /// The socket is removed when serving stops, before the data directory is released.
    #[cfg(unix)]
    pub fn serve_enrolled_with_control(self, shutdown: &AtomicBool, control: ControlSocket) -> io::Result<()> {
        let beside = move |stopped: &dyn Fn() -> bool, accounts: &Mutex<AccountStore>, rooms: &Mutex<DurableServer>, now_ms: &dyn Fn() -> u64| {
            control.serve(stopped, accounts, rooms, now_ms)
        };
        let external = self.enrollment();
        self.serve_beside(shutdown, move |accounts, issuer| Ok(bootstrap_handler_with(accounts, issuer, SystemEnvironment, external)), Some(beside))
    }

    /// Build the handler with the same account store used by TLS admission and chat authentication.
    /// The listener owns the connection deadlines and joins its handlers before returning.
    pub fn serve<B>(self, shutdown: &AtomicBool, make_bootstrap: impl FnOnce(Arc<Mutex<AccountStore>>, Authority) -> io::Result<B>) -> io::Result<()>
    where
        B: Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static,
    {
        self.serve_beside(shutdown, make_bootstrap, None::<Beside>)
    }

    /// Serve, with `beside` (if any) running on its own thread over the live stores until serving stops. It is told
    /// to stop by its first argument and is joined before the data directory is released.
    fn serve_beside<B, S>(
        self,
        shutdown: &AtomicBool,
        make_bootstrap: impl FnOnce(Arc<Mutex<AccountStore>>, Authority) -> io::Result<B>,
        beside: Option<S>,
    ) -> io::Result<()>
    where
        B: Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static,
        S: FnOnce(&dyn Fn() -> bool, &Mutex<AccountStore>, &Mutex<DurableServer>, &dyn Fn() -> u64) + Send,
    {
        let Self { server, accounts, issuer, now_ms, ownership, external, media } = self;
        let bootstrap = make_bootstrap(accounts.clone(), issuer)?;
        let throttle = Arc::new(Mutex::new(Throttle::new()));
        let rooms = server.rooms();
        let finished = AtomicBool::new(false);
        let result = thread::scope(|scope| {
            let side = match beside {
                Some(beside) => {
                    let (accounts, rooms, now_ms, finished) = (&accounts, &rooms, &now_ms, &finished);
                    let stopped = move || shutdown.load(Ordering::Acquire) || finished.load(Ordering::Acquire);
                    Some(thread::Builder::new().name("control".into()).spawn_scoped(scope, move || beside(&stopped, accounts, rooms, &**now_ms))?)
                }
                None => None,
            };
            // The media server's control connection, on its own thread over the live room store (task T360b3).
            let media_side = match &media {
                Some(link) => {
                    let (rooms, now_ms, finished) = (&rooms, &now_ms, &finished);
                    let stopped = move || shutdown.load(Ordering::Acquire) || finished.load(Ordering::Acquire);
                    Some(thread::Builder::new().name("media".into()).spawn_scoped(scope, move || link.run(&stopped, rooms, &**now_ms))?)
                }
                None => None,
            };
            let (device_accounts, clock) = (accounts.clone(), now_ms.clone());
            let result = server.serve(
                shutdown,
                move || clock(),
                move |der, now| {
                    let auth = StoredDeviceAuth::bind(device_accounts.clone(), throttle.clone(), der, now)?;
                    Ok(match &external {
                        Some(external) => auth.with_external(external.clone()),
                        None => auth,
                    })
                },
                bootstrap,
            );
            finished.store(true, Ordering::Release);
            if let Some(side) = side {
                let _ = side.join();
            }
            if let Some(side) = media_side {
                let _ = side.join();
            }
            result
        });
        drop(ownership);
        result
    }
}

type Beside = fn(&dyn Fn() -> bool, &Mutex<AccountStore>, &Mutex<DurableServer>, &dyn Fn() -> u64);

struct InstalledAdmission {
    accounts: Arc<Mutex<AccountStore>>,
    now_ms: Clock,
}

impl fmt::Debug for InstalledAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstalledAdmission").finish_non_exhaustive()
    }
}

impl Admission for InstalledAdmission {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        let now_ms = (self.now_ms)();
        self.accounts.lock().is_ok_and(|mut accounts| accounts.admit(certificate, now_ms).is_ok())
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        let now_ms = (self.now_ms)();
        self.accounts.lock().is_ok_and(|accounts| accounts.is_invite_pending(public_key, now_ms))
    }
}
