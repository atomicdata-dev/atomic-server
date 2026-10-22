//! File bytes: local reads and remote fetches.

use super::*;

/// The bytes of a File resource (a profile picture) when this device holds
/// them; `None` when the File or its bytes are not here (yet) or too large.
pub async fn read_file_bytes(file: String) -> Result<Option<Vec<u8>>, String> {
    atomic_lib::host::own_profile::file_bytes(db()?, &file)
        .await
        .map_err(err)
}

/// The bytes of a File resource (a profile picture): from this device when it
/// holds them, else downloaded from the connected server the way the web app
/// does (signed by the agent, checked against the blob's hash, an image of at
/// most 16 MB) and kept in the store. Fails with the reason (HTTP status
/// included) when they cannot be had.
pub async fn fetch_file_bytes(file: String) -> Result<Vec<u8>, String> {
    let origins: Vec<String> = state::connected_server().into_iter().collect();
    atomic_lib::host::own_profile::fetch_file_bytes(db()?, &file, &origins)
        .await
        .map_err(err)
}
