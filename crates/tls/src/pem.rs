//! PEM files for the configurations this crate builds (task T360b3): a certificate chain, its private key, and the
//! CAs a peer must chain to. Reading the files (sizes, owner-only keys) is the caller's; this only parses them.

use std::io;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::Identity;

fn invalid(what: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {error}"))
}

/// Every certificate in `pem`, in order (a chain is leaf first). At least one.
pub fn certificates(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let certificates = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>().map_err(|e| invalid("certificates", e))?;
    if certificates.is_empty() {
        return Err(invalid("certificates", "none in the file"));
    }
    Ok(certificates)
}

/// The certificate chain in `chain_pem` and the private key in `key_pem`, as one identity.
pub fn identity(chain_pem: &[u8], key_pem: &[u8]) -> io::Result<Identity> {
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| invalid("private key", e))?;
    Ok((certificates(chain_pem)?, key))
}

/// The CAs in `pem`, as the only roots a peer may chain to.
pub fn roots(pem: &[u8]) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(pem)? {
        roots.add(certificate).map_err(|e| invalid("CA certificate", e))?;
    }
    Ok(roots)
}
