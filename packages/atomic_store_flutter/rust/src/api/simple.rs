use atomic_lib::Storelike;
use flutter_rust_bridge::frb;

#[cfg(not(target_arch = "wasm32"))]
mod compaction_check;
#[cfg(test)]
mod dial_tests;
#[cfg(test)]
mod peer_tests;
pub(crate) mod directory;
mod peer_search;
pub(crate) mod state;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod store_open_tests;
#[cfg(test)]
pub(crate) mod tests;
pub mod types;
pub mod ws_sync;

pub use atomic_lib::{Commit, Db};

use state::{db, err, node, set_db};
use atomic_lib::host::activity_status::{self, begin as busy, Kind};
pub use types::{AgentInfo, SetupResult, StoreRecovery, VersionMetadata};

pub(crate) mod local_write;
pub mod store;
pub mod agent;
pub mod files;
pub mod drive;
pub mod resource;
pub mod sync;
pub mod peers;

pub(crate) use local_write::*;
pub use store::*;
pub use agent::*;
pub use files::*;
pub use drive::*;
pub use resource::*;
pub use sync::*;
pub use peers::*;
