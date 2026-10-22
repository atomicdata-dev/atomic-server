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

/// See [`super::install_default_crypto_provider`].
pub(crate) fn install_default_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Err means another provider is already installed: fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Trust roots: the bundled Mozilla set, plus the system's CA certificates on
/// Android. The bundled set is always added, so an empty or unreadable system
/// store still yields a working client. Unparsable system certificates are
/// skipped.
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub(crate) fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    #[cfg(target_os = "android")]
    for der in super::helpers::android_root_ders() {
        let _ = roots.add(rustls::pki_types::CertificateDer::from(der.clone()));
    }
    roots
}

/// A client config using the ring provider explicitly (never the process
/// default) and [`root_store`].
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
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
        build_client_config().expect("config builds with explicit ring provider");
    }

    /// The panic seen on macOS: with both `ring` and `aws-lc-rs` enabled,
    /// `ClientConfig::builder()` panics unless a default provider is installed.
    #[test]
    fn default_builder_works_after_install() {
        crate::client::install_default_crypto_provider();
        crate::client::install_default_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        let _ = ClientConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth();
    }
}
