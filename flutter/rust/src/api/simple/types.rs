pub struct SetupResult {
    pub agent_secret: String,
    pub agent_subject: String,
    pub drive_subject: String,
}

/// What `open_db` did about a store it could not open (`store_recovery`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRecovery {
    /// The broken file, kept under a new name next to the new store.
    pub kept_path: String,
    /// Why the store could not be opened, for the log and a bug report.
    pub reason: String,
    /// `true`: a repaired copy of the old store is in use (the last moments
    /// before the crash may be missing). `false`: the app starts on an
    /// empty store and gets its data back by syncing.
    pub repaired: bool,
}

pub struct AgentInfo {
    pub secret: String,
    pub subject: String,
    pub public_key: String,
    pub name: Option<String>,
}

/// Db event forwarded to Flutter (`poll_db_event`).
#[derive(serde::Serialize)]
pub struct DbEventDto {
    pub kind: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added: Option<bool>,
}

/// Metadata for a single historical version of a resource.
pub struct VersionMetadata {
    pub id: Vec<u8>,
    pub timestamp: i64,
    pub peer_id: String,
    pub lamport: u64,
    pub len: i32,
    pub message: Option<String>,
}
