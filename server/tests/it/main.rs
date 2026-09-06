//! Single integration-test binary. Each module is one test suite; a single
//! binary means the server is linked once instead of once per file, keeping
//! `target/` and link times manageable.
//!
//! Run one suite with: cargo test -p atomic-server --test it <module_name>

mod common;

mod blob_sync;
mod drive_presence;
mod drive_presence_shared;
mod file_search_repro;
mod history_attribution;
mod iroh_pairing;
mod loro_ephemeral_sync;
mod multi_client_sync;
mod put_blob;
mod replicate;
mod server_cli;
mod sync;
mod ws_auth_gate;
mod ws_commit;
mod ws_commit_isolation;
mod ws_destroy;
mod ws_drive_membership;
mod ws_errors;
mod ws_get;
mod ws_get_unauthorized_latency;
mod ws_unsub;
