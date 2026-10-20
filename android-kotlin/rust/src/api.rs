//! What Kotlin calls. Free functions over the process's one store; async
//! where the Rust is async (they run on UniFFI's tokio runtime).

use crate::{
    error::CoreResult,
    home,
    state::{self, conversations, db, node, now_ms, recents},
    store,
    types::*,
};
use atomic_lib::{host::NoPush, Storelike};
use std::sync::Arc;

/// Library version, to check that the bindings and the `.so` belong together.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ── Store ──────────────────────────────────────────────────────────────────

/// Open the store in `path`. Call on app start; a second call in the same
/// process (Android recreates the activity in the same process) keeps the
/// store that is already open. Never panics and never deletes the person's
/// data: see [`store_recovery`].
#[uniffi::export(async_runtime = "tokio")]
pub async fn open_store(path: String) -> CoreResult<()> {
    store::init_logging();
    let _opening = state::OPEN_LOCK.lock().await;
    if state::is_open() {
        tracing::info!("open_store: the store is already open in this process; keeping it");
        return Ok(());
    }
    let dir = std::path::PathBuf::from(&path);
    let (opened, recovery) = store::open_native_store(&dir).await?;
    if let Some(recovery) = recovery {
        state::set_recovery(recovery);
    }
    state::set_db(opened);
    let db = db()?.clone();
    store::catch_up_search_index(db.clone()).await;
    recents().load(&dir);
    recents().clone().spawn_listener(db);
    Ok(())
}

/// Set when the last `open_store` had to set a damaged store aside.
#[uniffi::export]
pub fn store_recovery() -> Option<StoreRecovery> {
    state::recovery()
}

/// Make every write so far durable now (call when the app goes to the
/// background; the store otherwise flushes on a 100 ms tick).
#[uniffi::export]
pub fn flush_store() -> CoreResult<()> {
    db()?.flush()?;
    recents().persist();
    Ok(())
}

// ── Agent and drives ───────────────────────────────────────────────────────

fn agent_info(agent: &atomic_lib::agents::Agent) -> CoreResult<AgentInfo> {
    Ok(AgentInfo {
        secret: agent.build_secret()?,
        subject: agent.subject.to_string(),
        public_key: agent.public_key.clone(),
        name: agent.name.clone(),
    })
}

/// First run: create an agent and its private drive in one call. Local only.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_agent_and_drive(name: String) -> CoreResult<SetupResult> {
    let (agent, drive_subject) = db()?.setup(&name).await?;
    Ok(SetupResult { agent: agent_info(&agent)?, drive_subject })
}

/// This device's agent, `None` before first run.
#[uniffi::export]
pub fn active_agent() -> CoreResult<Option<AgentInfo>> {
    match db()?.get_default_agent() {
        Ok(agent) => Ok(Some(agent_info(&agent)?)),
        Err(_) => Ok(None),
    }
}

/// Sign in with a backup secret. Returns the agent subject, or `needs_sync`
/// when the secret names a drive this device does not hold yet.
#[uniffi::export(async_runtime = "tokio")]
pub async fn load_agent(secret: String) -> CoreResult<String> {
    let result = db()?.load_agent_from_secret(&secret).await?;
    Ok(if result.drive_needs_sync {
        "needs_sync".to_string()
    } else {
        result.agent.subject.to_string()
    })
}

/// The drive the app opened on, if any.
#[uniffi::export]
pub fn active_drive() -> CoreResult<Option<String>> {
    Ok(db()?.get_active_drive())
}

/// The agent's drives, with names and icons.
#[uniffi::export(async_runtime = "tokio")]
pub async fn list_drives() -> CoreResult<Vec<DriveRow>> {
    home::drives(db()?).await
}

// ── Home lists and search ──────────────────────────────────────────────────

/// One of the home lists, newest first, at most `limit` rows.
#[uniffi::export(async_runtime = "tokio")]
pub async fn home_list(which: HomeList, limit: u32) -> CoreResult<Vec<ResourceRow>> {
    home::list(db()?, recents(), conversations(), which, limit as usize).await
}

/// Full-text search across every drive, best first. Cheap enough to call on
/// every keystroke; an empty query returns nothing.
#[uniffi::export(async_runtime = "tokio")]
pub async fn search(query: String, limit: u32) -> CoreResult<Vec<SearchHit>> {
    let store = db()?.clone();
    // The index read is blocking work; keep it off the async workers.
    tokio::task::spawn_blocking(move || home::search(&store, &query, limit as usize))
        .await
        .map_err(|e| format!("search task failed: {e}"))?
}

/// Record that this device opened `subject` in `drive` (local only).
#[uniffi::export]
pub fn note_resource_opened(drive: String, subject: String) {
    recents().note_opened(&drive, &subject, now_ms());
}

// ── Writes the first-run flow and the debug seed use ───────────────────────

async fn create_of_class(drive: &str, class_url: &str, name: &str) -> CoreResult<String> {
    Ok(
        atomic_lib::host::create::create_resource_of_class(&node()?, &NoPush, drive, class_url, name)
            .await?,
    )
}

/// A new document in `drive`. Returns its subject.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_document(drive: String, name: String) -> CoreResult<String> {
    create_of_class(&drive, atomic_lib::urls::DOCUMENT_V2, &name).await
}

/// A new folder in `drive`. Returns its subject.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_folder(drive: String, name: String) -> CoreResult<String> {
    create_of_class(&drive, atomic_lib::urls::FOLDER, &name).await
}

/// A new drive. Returns its subject.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_drive(name: String) -> CoreResult<String> {
    Ok(db()?.create_drive(&name).await?)
}

/// A new AI chat in the private drive. Returns its subject.
#[uniffi::export(async_runtime = "tokio")]
pub async fn create_ai_chat(name: String) -> CoreResult<String> {
    Ok(atomic_lib::host::chats::create_ai_chat(&node()?, &NoPush, &name).await?)
}

/// Add `subject` to the favorites of the private drive (what the web app's
/// star does).
#[uniffi::export(async_runtime = "tokio")]
pub async fn add_favorite(subject: String) -> CoreResult<()> {
    home_favorite(&subject).await
}

async fn home_favorite(subject: &str) -> CoreResult<()> {
    use atomic_lib::host::rows::FAVORITES;
    let store = db()?;
    let home = store.private_drive_subject()?;
    let mut drive = store.get_resource(&home.as_str().into()).await?;
    let mut list = drive
        .get(FAVORITES)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default();
    if list.iter().any(|s| s == subject) {
        return Ok(());
    }
    list.push(subject.to_string());
    let _ = drive.set_unsafe(
        FAVORITES.into(),
        atomic_lib::Value::ResourceArray(list.into_iter().map(Into::into).collect()),
    );
    node()?.save_locally(&mut drive).await?;
    Ok(())
}

// ── Store events ───────────────────────────────────────────────────────────

/// A running event subscription; drop it or call [`Subscription::cancel`] to
/// stop.
#[derive(uniffi::Object)]
pub struct Subscription {
    task: tokio::task::AbortHandle,
}

#[uniffi::export]
impl Subscription {
    pub fn cancel(&self) {
        self.task.abort();
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn event_of(event: atomic_lib::DbEvent) -> StoreEvent {
    use atomic_lib::DbEvent;
    match event {
        DbEvent::Changed { subject, .. } => StoreEvent {
            kind: StoreEventKind::Changed,
            subject: subject.to_string(),
        },
        DbEvent::Destroyed { subject, .. } => StoreEvent {
            kind: StoreEventKind::Destroyed,
            subject: subject.to_string(),
        },
        DbEvent::QueryMembershipChanged { subject, .. } => StoreEvent {
            kind: StoreEventKind::QueryMembership,
            subject,
        },
    }
}

/// Call `listener` for every change in the store, on a background thread,
/// until the returned subscription is cancelled.
#[uniffi::export(async_runtime = "tokio")]
pub async fn subscribe_events(listener: Arc<dyn StoreListener>) -> CoreResult<Arc<Subscription>> {
    use tokio::sync::broadcast::error::RecvError;
    let store = db()?.clone();
    let mut rx = store.subscribe_events();
    let handle = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => listener.on_event(event_of(event)),
                // Events were dropped: tell the listener to read everything again.
                Err(RecvError::Lagged(_)) => listener.on_event(StoreEvent {
                    kind: StoreEventKind::QueryMembership,
                    subject: String::new(),
                }),
                Err(RecvError::Closed) => break,
            }
        }
    });
    Ok(Arc::new(Subscription { task: handle.abort_handle() }))
}

// ── The embedded renderer ──────────────────────────────────────────────────

/// One call from the embedded page (`NativeClientDb` and the crypto provider
/// in `browser/lib/src/client-db.native.ts`): `method` and its arguments as a
/// JSON array, answered as JSON. Reads, signing and applying commits all go
/// through here; the page holds no store and no secret. An error is the text
/// the page's promise rejects with.
#[uniffi::export(async_runtime = "tokio")]
pub async fn embed_dispatch(method: String, args_json: String) -> CoreResult<String> {
    Ok(crate::embed::embed()?.call(&method, &args_json).await?)
}

/// Push store changes to the embedded page: `listener` hears the subjects to
/// read again, until the subscription is cancelled.
#[uniffi::export(async_runtime = "tokio")]
pub async fn subscribe_embed(listener: Arc<dyn EmbedListener>) -> CoreResult<Arc<Subscription>> {
    Ok(Arc::new(Subscription { task: crate::embed::spawn_pusher(listener)? }))
}

// ── Signing in again ───────────────────────────────────────────────────────

/// Start-up of a device that has signed in before: load the agent from the
/// secret the app kept (the store does not keep it) and make `drive` (what the
/// app remembered, empty for none) the active drive. `true` when that drive is
/// in this store; `false` means it still has to arrive (see the sync calls).
#[uniffi::export(async_runtime = "tokio")]
pub async fn resume_agent(secret: String, drive: Option<String>) -> CoreResult<bool> {
    crate::session::resume(db()?, &secret, drive.as_deref()).await
}

/// Set the active drive (what tapping a drive does).
#[uniffi::export]
pub fn set_active_drive(subject: String) -> CoreResult<()> {
    Ok(db()?.set_active_drive(&subject)?)
}

/// Forget the agent held in memory (sign out). The data stays in the store.
#[uniffi::export]
pub fn clear_agent() -> CoreResult<()> {
    db()?.clear_default_agent();
    Ok(())
}
