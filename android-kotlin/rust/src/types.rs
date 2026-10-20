//! The records Kotlin reads. Plain data: no behaviour, no JSON.

/// This device's agent. `secret` is the backup string (shown only on request).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AgentInfo {
    pub secret: String,
    pub subject: String,
    pub public_key: String,
    pub name: Option<String>,
}

/// What first-run setup made.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SetupResult {
    pub agent: AgentInfo,
    pub drive_subject: String,
}

/// A drive of this agent.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DriveRow {
    pub subject: String,
    pub name: String,
    pub emoji: Option<String>,
}

/// One resource as a list row, for every home list and for search.
///
/// `opened_at` is the time that orders the list (opened, last message, last
/// activity) in unix ms, 0 when unknown. `detail` is a second line when the
/// list has one (the newest message of a conversation).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ResourceRow {
    pub subject: String,
    pub title: String,
    pub class_name: String,
    pub emoji: Option<String>,
    pub drive: String,
    pub opened_at: i64,
    pub detail: String,
}

/// The home lists a screen can ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HomeList {
    Recents,
    AiChats,
    Favorites,
    Messages,
}

/// A full-text search hit, best first.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SearchHit {
    pub subject: String,
    pub title: String,
    pub class_name: String,
    pub emoji: Option<String>,
    pub drive: String,
    pub score: f64,
}

/// What `open_store` did about a store it could not open.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct StoreRecovery {
    pub kept_path: String,
    pub reason: String,
    pub repaired: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreEventKind {
    Changed,
    Destroyed,
    QueryMembership,
}

/// A change in the store, to refresh the lists on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct StoreEvent {
    pub kind: StoreEventKind,
    pub subject: String,
}

/// Kotlin implements this; the Rust side calls it from a background thread
/// for every store event until the subscription is cancelled.
#[uniffi::export(with_foreign)]
pub trait StoreListener: Send + Sync {
    fn on_event(&self, event: StoreEvent);
}

/// Kotlin implements this to push store changes into the embedded page: the
/// resources (a burst of events, deduplicated, without the page's own writes)
/// it should read again. Called on a background thread.
#[uniffi::export(with_foreign)]
pub trait EmbedListener: Send + Sync {
    fn on_changed(&self, subjects: Vec<String>);
}

// ── Sync, servers, peers, profile ──────────────────────────────────────────

/// How a start-up with a saved session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ResumeStatus {
    /// The drive is on this device.
    Ready,
    /// The drive has to arrive first (a server, a paired device).
    NeedsSync,
}

/// What looking for the server a drive lives on did.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DiscoveryResult {
    /// The server that verified and was connected to.
    pub origin: Option<String>,
    /// One line per origin that did not work out, for showing when none did.
    pub log: Vec<String>,
}

/// What a server says about itself (`GET /server`); every field is absent when
/// it does not report it or cannot be reached.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct ServerInfo {
    pub node_id: Option<String>,
    pub version: Option<String>,
    pub managed: bool,
    pub portal_url: Option<String>,
}

/// What a drive stores on a server.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DriveUsage {
    pub drive_name: Option<String>,
    pub resource_count: u64,
    pub blob_bytes: u64,
    pub loro_bytes: u64,
}

/// A paired device.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PeerRow {
    pub node_id: String,
    pub name: String,
    /// Unix ms of the last completed sync, if any.
    pub last_synced: Option<u64>,
    /// Whether a live connection to it is open right now.
    pub live: bool,
}

/// What a sync with one device moved, in both directions.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PeerSyncOutcome {
    pub imported: i32,
    pub pushed: i32,
    pub in_sync: bool,
    pub peer_name: Option<String>,
}

/// The result of looking for the person's devices.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConnectivityReport {
    pub imported: i32,
    pub live_peers: u32,
    pub message: String,
}

/// A parsed pairing code (see `pairing.rs`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PairingCode {
    pub node_id: String,
    pub name: String,
    pub server_url: Option<String>,
    pub drives: Vec<String>,
}

/// The profile of this device's agent.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OwnProfile {
    pub subject: String,
    pub name: String,
    pub description: String,
    pub emoji: Option<String>,
    pub image_url: Option<String>,
}

/// Something that happened on the sync side: a device connected, went away, or
/// a sync moved resources. `kind` is `sync`, `connected` or `disconnected`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SyncEvent {
    pub kind: String,
    pub remote_node_id: String,
    pub resources_imported: u32,
}

/// Kotlin implements this to hear about sync events, on a background thread.
#[uniffi::export(with_foreign)]
pub trait SyncListener: Send + Sync {
    fn on_event(&self, event: SyncEvent);
}
