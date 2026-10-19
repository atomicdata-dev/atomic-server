//! Explicit TLS configuration for the WebSocket client.
//!
//! On Android, `tokio_tungstenite::connect_async` cannot build a working TLS
//! config by itself: no default rustls `CryptoProvider` is installed and the
//! platform verifier needs JNI initialisation. So the config is built here from
//! an explicit ring provider and an explicit root store.

use std::sync::Arc;
#[cfg(target_os = "android")]
use std::sync::OnceLock;

use rustls::{ClientConfig, RootCertStore};

/// Trust roots: the bundled Mozilla set, plus the system's CA certificates on
/// Android. The bundled set is always added, so an empty or unreadable system
/// store still yields a working client. Unparsable system certificates are
/// skipped.
pub(crate) fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    #[cfg(target_os = "android")]
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    roots
}

/// A client config using the ring provider explicitly (never the process
/// default) and [`root_store`].
pub(crate) fn build_client_config() -> Result<ClientConfig, rustls::Error> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store())
            .with_no_client_auth(),
    )
}

/// The shared, lazily built client config.
#[cfg(target_os = "android")]
pub(crate) fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            Arc::new(build_client_config().expect("ring supports the default TLS versions"))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_store_is_not_empty() {
        assert!(!root_store().is_empty());
    }

    #[test]
    fn config_builds_without_default_provider() {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        build_client_config().expect("config builds with explicit ring provider");
    }
}
