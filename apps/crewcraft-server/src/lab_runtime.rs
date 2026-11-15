//! Wire installed state to the lab's loopback server. Task T227.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use crewcraft_accounts::throttle::Throttle;
use crewcraft_admission::Admission;
use crewcraft_pki::{Authority, ServerIdentity};
use crewcraft_server_core::account_store::AccountStore;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::lab_installation::LabInstallation;
use crate::lab_server::{BootstrapStream, LabOptions, LabServer};
use crate::lab_state::LabState;
use crate::stored_device_auth::StoredDeviceAuth;

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct LabRuntime {
    server: LabServer,
    accounts: Arc<Mutex<AccountStore>>,
    issuer: Authority,
    now_ms: Clock,
    ownership: LabState,
}

impl LabRuntime {
    /// Bind with the installation's original trust anchor and a freshly signed localhost server certificate.
    /// `now_ms` supplies the server's current Unix time in milliseconds.
    pub fn bind(installation: LabInstallation, options: LabOptions, now_ms: impl Fn() -> u64 + Send + Sync + 'static) -> io::Result<Self> {
        let LabInstallation { ownership, issuer, accounts, rooms } = installation;
        let (root, issuer) = issuer.into_parts();
        let ServerIdentity { chain, key_pkcs8 } =
            issuer.server_certificate("localhost", now_ms()).map_err(|_| io::Error::other("could not sign the lab server certificate"))?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root)).map_err(io::Error::other)?;
        let identity = (chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(key_pkcs8).into());

        let accounts = Arc::new(Mutex::new(accounts));
        let now_ms: Clock = Arc::new(now_ms);
        let admission = Arc::new(InstalledAdmission { accounts: accounts.clone(), now_ms: now_ms.clone() });
        let server = LabServer::bind(options, identity, roots, admission, rooms)?;
        Ok(Self { server, accounts, issuer, now_ms, ownership })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.server.local_addr()
    }

    /// Build the handler with the same account store used by TLS admission and chat authentication.
    /// The listener owns the connection deadlines and joins its handlers before returning.
    pub fn serve<B>(self, shutdown: &AtomicBool, make_bootstrap: impl FnOnce(Arc<Mutex<AccountStore>>, Authority) -> io::Result<B>) -> io::Result<()>
    where
        B: Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static,
    {
        let Self { server, accounts, issuer, now_ms, ownership } = self;
        let bootstrap = make_bootstrap(accounts.clone(), issuer)?;
        let throttle = Arc::new(Mutex::new(Throttle::new()));
        let result =
            server.serve(shutdown, move || now_ms(), move |der, now| StoredDeviceAuth::bind(accounts.clone(), throttle.clone(), der, now), bootstrap);
        drop(ownership);
        result
    }
}

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
