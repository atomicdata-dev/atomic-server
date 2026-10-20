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
