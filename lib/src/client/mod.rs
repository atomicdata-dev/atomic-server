/*!
# Client

Functions for fetching data from an instance of AtomicServer.

*/

pub mod helpers;
pub use helpers::*;
pub mod connected;
pub mod search;
#[cfg(feature = "ws")]
pub(crate) mod tls;
#[cfg(feature = "ws")]
pub mod ws;

/// Installs the ring rustls `CryptoProvider` as the process default, once.
///
/// rustls 0.23 panics at the first TLS use ("Could not automatically determine
/// the process-level CryptoProvider") when no default is installed and its
/// features do not name exactly one backend. Here `ring` (this crate's rustls,
/// iroh's reqwest) and `aws-lc-rs` (reqwest 0.13) are both enabled, so the
/// automatic choice is impossible. Safe to call from anywhere, any number of
/// times; a provider installed earlier by someone else is left in place.
pub fn install_default_crypto_provider() {
    #[cfg(feature = "ws")]
    tls::install_default_provider();
}
