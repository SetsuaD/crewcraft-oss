//! DTLS for str0m (task T362a): `dimpl` in its RustCrypto mode, with the certificate from [`crate::certificate`].

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider, ProtocolVersion};
use str0m_proto::crypto::{CryptoError, DtlsVersion};

/// The DTLS provider.
#[derive(Debug)]
pub struct Dtls;

impl DtlsProvider for Dtls {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        crate::certificate::self_signed()
    }

    fn new_dtls(&self, cert: &DtlsCert, now: Instant, dtls_version: DtlsVersion, mtu: Option<usize>) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        // ICE has already proven the peer answers at its address before DTLS starts (its connectivity checks are
        // authenticated with the session's ICE password), so DTLS's own cookie round trip would only add latency.
        let mut builder = dimpl::Config::builder().with_crypto_provider(dimpl::crypto::rust_crypto::default_provider()).use_server_cookie(false);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        let config = Arc::new(builder.build()?);
        let cert = cert.clone();
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, cert, now),
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, cert, now),
            other => return Err(CryptoError::Other(format!("DTLS version not supported: {other}"))),
        };
        Ok(Box::new(Instance(dtls)))
    }
}

/// One DTLS connection.
struct Instance(dimpl::Dtls);

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DtlsInstance")
    }
}

impl DtlsInstance for Instance {
    fn set_active(&mut self, active: bool) {
        self.0.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.0.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.0.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.0.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<usize, DtlsImplError> {
        self.0.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.0.is_active()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.0.protocol_version()
    }

    fn is_closing(&self) -> bool {
        self.0.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.0.close()
    }
}
