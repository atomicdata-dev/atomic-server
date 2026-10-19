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
