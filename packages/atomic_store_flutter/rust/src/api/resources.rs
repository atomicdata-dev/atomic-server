//! Generic, typed resource access: the bridge half of the Dart `Store` and
//! `Resource` (`packages/atomic_store`), which mirror `@tomic/lib`.
//!
//! Unlike the older flat functions these return typed values
//! ([`ResourceData`], [`AtomicValue`]) and fail with [`AtomicError`]. Writes
//! take the same path as every other local write: a signed commit, queued in
//! the outbox and pushed (`push_local_write`).
//!
//! [`AtomicStore`] is an open store with its signing agent and drive. The
//! free functions are the same calls on the process-wide default store that
//! `open_db` and `load_agent` set.

use super::error::AtomicError;
use super::simple::local_write::push_write;
use super::simple::state::OpenStore;
use super::simple::ws_sync::SyncSession;
use atomic_lib::host::{
    chat_rooms::ChatRooms, conversations::Conversations, profiles::AgentProfiles, recents::RecentsIndex,
};
use atomic_lib::{
    commit::CommitBuilder, host::lists, resources::PropVals, values::SubResource, Commit, Storelike, Value,
};

/// The datatype of an [`AtomicValue`]; says which of its fields is filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datatype {
    /// `text`.
    String,
    /// `text`.
    Markdown,
    /// `text`.
    Slug,
    /// `text`, an ISO date.
    Date,
    /// `text`.
    Uri,
    /// `text` is the linked resource's subject.
    Link,
    /// `text`, decimal (lossless on the web, where 64-bit ints are not exact).
    Integer,
    /// `text`, decimal.
    Float,
    /// `text`, Unix epoch milliseconds, decimal.
    Timestamp,
    /// `text` is `true` or `false`.
    Boolean,
    /// `items`: links and nested resources.
    Array,
    /// `props`: a resource without a subject of its own, inside another.
    Nested,
    /// `text` is JSON.
    Json,
    /// `props`: each property is a BCP 47 language tag, each value a string.
    Localized,
    /// `text` describes a value this bridge cannot interpret (a Loro
    /// document, an unknown datatype); `unsupported_datatype` names it.
    Unsupported,
}

/// One change or destroy somewhere in the store (see
/// [`AtomicStore::wait_for_store_event`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEvent {
    pub kind: ResourceEvent,
    /// The resource it happened to; empty for [`ResourceEvent::Timeout`].
    pub subject: String,
}

/// A property value. `datatype` says which of the other fields carries it;
/// the rest are empty. (One flat struct instead of an enum with fields:
/// flutter_rust_bridge generates those with `freezed`, which this app does not
/// use. `packages/atomic_store` turns it into sealed Dart classes.)
#[derive(Debug, Clone, PartialEq)]
pub struct AtomicValue {
    pub datatype: Datatype,
    pub text: String,
    pub items: Vec<AtomicValue>,
    pub props: Vec<PropValue>,
    pub unsupported_datatype: Option<String>,
}

impl AtomicValue {
    fn scalar(datatype: Datatype, text: impl Into<String>) -> Self {
        AtomicValue {
            datatype,
            text: text.into(),
            items: Vec::new(),
            props: Vec::new(),
            unsupported_datatype: None,
        }
    }
}

/// One property of a resource.
#[derive(Debug, Clone, PartialEq)]
pub struct PropValue {
    /// The property's URL.
    pub property: String,
    pub value: AtomicValue,
}

/// A resource as the local store holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceData {
    pub subject: String,
    /// Sorted by property URL, so two reads of one state are equal.
    pub props: Vec<PropValue>,
}

/// One full-text search hit.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub subject: String,
    pub title: String,
    pub class_name: String,
    /// The drive the hit lives in, empty when unknown.
    pub drive: String,
    pub score: f64,
}

/// What `wait_for_resource_event` saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceEvent {
    Changed,
    Destroyed,
    /// Nothing happened within the timeout; call again.
    Timeout,
}

// ── Conversion ─────────────────────────────────────────────────────────────

fn sub_resource_to_value(sub: &SubResource) -> AtomicValue {
    match sub {
        SubResource::Subject(s) => AtomicValue::scalar(Datatype::Link, s.to_string()),
        SubResource::Nested(props) => AtomicValue {
            props: propvals_to_list(props),
            ..AtomicValue::scalar(Datatype::Nested, "")
        },
    }
}

pub(crate) fn value_to_atomic(value: &Value) -> AtomicValue {
    use Datatype::*;
    match value {
        Value::String(v) => AtomicValue::scalar(String, v),
        Value::Markdown(v) => AtomicValue::scalar(Markdown, v),
        Value::Slug(v) => AtomicValue::scalar(Slug, v),
        Value::Date(v) => AtomicValue::scalar(Date, v),
        Value::Uri(v) => AtomicValue::scalar(Uri, v),
        Value::AtomicUrl(s) => AtomicValue::scalar(Link, s.to_string()),
        Value::Integer(v) => AtomicValue::scalar(Integer, v.to_string()),
        Value::Float(v) => AtomicValue::scalar(Float, v.to_string()),
        Value::Timestamp(v) => AtomicValue::scalar(Timestamp, v.to_string()),
        Value::Boolean(v) => AtomicValue::scalar(Boolean, v.to_string()),
        Value::ResourceArray(items) => AtomicValue {
            items: items.iter().map(sub_resource_to_value).collect(),
            ..AtomicValue::scalar(Array, "")
        },
        Value::NestedResource(sub) => sub_resource_to_value(sub),
        Value::Json(v) => AtomicValue::scalar(Json, v.to_string()),
        Value::LocalizedText(map) => AtomicValue {
            props: map
                .iter()
                .map(|(language, text)| PropValue {
                    property: language.clone(),
                    value: AtomicValue::scalar(String, text),
                })
                .collect(),
            ..AtomicValue::scalar(Localized, "")
        },
        Value::LoroDoc(bytes) => AtomicValue {
            unsupported_datatype: Some("loroDoc".into()),
            ..AtomicValue::scalar(Unsupported, format!("{} bytes", bytes.len()))
        },
        Value::Unsupported(u) => AtomicValue {
            unsupported_datatype: Some(u.datatype.clone()),
            ..AtomicValue::scalar(Unsupported, &u.value)
        },
    }
}

fn propvals_to_list(props: &PropVals) -> Vec<PropValue> {
    let mut list: Vec<PropValue> = props
        .iter()
        .map(|(property, value)| PropValue {
            property: property.clone(),
            value: value_to_atomic(value),
        })
        .collect();
    list.sort_by(|a, b| a.property.cmp(&b.property));
    list
}

fn atomic_to_sub_resource(value: &AtomicValue) -> Result<SubResource, AtomicError> {
    match value.datatype {
        Datatype::Link => Ok(SubResource::from(value.text.as_str())),
        Datatype::Nested => Ok(SubResource::Nested(list_to_propvals(&value.props)?)),
        _ => Err(AtomicError::invalid(
            "An array holds links and nested resources only",
        )),
    }
}

fn parse<T: std::str::FromStr>(value: &AtomicValue) -> Result<T, AtomicError> {
    value.text.trim().parse().map_err(|_| {
        AtomicError::invalid(format!("{:?} is not a valid {:?}", value.text, value.datatype))
    })
}

pub(crate) fn atomic_to_value(value: &AtomicValue) -> Result<Value, AtomicError> {
    let text = || value.text.clone();
    Ok(match value.datatype {
        Datatype::String => Value::String(text()),
        Datatype::Markdown => Value::Markdown(text()),
        Datatype::Slug => Value::Slug(text()),
        Datatype::Date => Value::Date(text()),
        Datatype::Uri => Value::Uri(text()),
        Datatype::Link => Value::AtomicUrl(value.text.as_str().into()),
        Datatype::Integer => Value::Integer(parse(value)?),
        Datatype::Float => Value::Float(parse(value)?),
        Datatype::Timestamp => Value::Timestamp(parse(value)?),
        Datatype::Boolean => Value::Boolean(parse(value)?),
        Datatype::Array => Value::ResourceArray(
            value
                .items
                .iter()
                .map(atomic_to_sub_resource)
                .collect::<Result<_, _>>()?,
        ),
        Datatype::Nested => Value::NestedResource(SubResource::Nested(list_to_propvals(&value.props)?)),
        Datatype::Json => Value::Json(
            serde_json::from_str(&value.text)
                .map_err(|e| AtomicError::invalid(format!("Not valid JSON: {e}")))?,
        ),
        Datatype::Localized => Value::LocalizedText(
            value
                .props
                .iter()
                .map(|p| (p.property.clone(), p.value.text.clone()))
                .collect(),
        ),
        Datatype::Unsupported => {
            return Err(AtomicError::invalid("An unsupported value cannot be written"))
        }
    })
}

fn list_to_propvals(list: &[PropValue]) -> Result<PropVals, AtomicError> {
    list.iter()
        .map(|p| Ok((p.property.clone(), atomic_to_value(&p.value)?)))
        .collect()
}

// ── The store handle ───────────────────────────────────────────────────────

/// An open store with the agent that signs its writes and the drive it works
/// in: what `@tomic/lib`'s `Store` is to a page. Open one with
/// [`AtomicStore::open`]; the functions below this struct without a handle
/// (`get_resource_data`, ...) are the same calls on the app's default store,
/// the one `open_db` and `load_agent` set up.
///
/// A file is opened once per process: two handles on one path share the
/// store (reads, indexes, events) and differ in agent and drive only.
///
/// Each handle has its own server session ([`AtomicStore::open_ws_sync`]):
/// a write through it is signed by its agent, stored, queued in the store's
/// outbox and sent over that session. The Iroh peer is one per process
/// (`start_peer`, pairing): it serves the default store, and so also a handle
/// on the default store's file. Handles on other files do not take part in
/// peer sync.
#[flutter_rust_bridge::frb(opaque)]
pub struct AtomicStore {
    pub(crate) db: std::sync::Arc<atomic_lib::Db>,
    drive: std::sync::Mutex<Option<String>>,
    /// This handle is the process-wide default (`state::default_store`).
    default: bool,
    pub(crate) sync: std::sync::Arc<SyncSession>,
    /// Shared by every handle on the file.
    pub(crate) recents: std::sync::Arc<RecentsIndex>,
    pub(crate) conversations: Conversations,
    pub(crate) chat_rooms: ChatRooms,
    pub(crate) profiles: AgentProfiles,
    /// A run of `follow_conversations` is going.
    pub(crate) following: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl AtomicStore {
    #[flutter_rust_bridge::frb(ignore)]
    fn build(open: OpenStore, db: atomic_lib::Db, drive: Option<String>, default: bool) -> AtomicStore {
        let db = std::sync::Arc::new(db);
        let sync = std::sync::Arc::new(SyncSession::default());
        let profiles = AgentProfiles::new(std::sync::Arc::new(crate::host::ServerProfileFetcher {
            db: db.clone(),
            sync: sync.clone(),
        }));
        AtomicStore {
            db,
            drive: std::sync::Mutex::new(drive),
            default,
            sync,
            recents: open.recents,
            conversations: Conversations::new(profiles.clone()),
            chat_rooms: ChatRooms::new(profiles.clone()),
            profiles,
            following: Default::default(),
        }
    }

    /// The default store: the file `open_db` opened, signing as the agent
    /// `load_agent` sets (the store's own, shared by clones of its `Db`).
    #[flutter_rust_bridge::frb(ignore)]
    pub(crate) fn new_default(open: OpenStore) -> AtomicStore {
        let db = (*open.db).clone();
        AtomicStore::build(open, db, None, true)
    }

    /// Open the store in the directory `path` (created when missing) for
    /// `agent_secret` (none: no agent yet, see [`AtomicStore::setup`]),
    /// working in `drive` (none: the store's active drive).
    pub async fn open(
        path: String,
        agent_secret: Option<String>,
        drive: Option<String>,
    ) -> Result<AtomicStore, AtomicError> {
        use super::simple::state::OPEN_DB_LOCK;
        #[cfg(not(target_arch = "wasm32"))]
        let _opening = OPEN_DB_LOCK.lock().await;
        let (shared, _recovery, fresh) =
            super::simple::open_shared(std::path::Path::new(&path))
                .await
                .map_err(AtomicError::storage)?;
        #[cfg(not(target_arch = "wasm32"))]
        if fresh {
            super::simple::catch_up_search_index(shared.db.clone()).await;
            shared.start_recents(std::path::Path::new(&path));
        }
        #[cfg(target_arch = "wasm32")]
        let _ = fresh;
        let agent = agent_secret
            .map(|secret| atomic_lib::agents::Agent::from_secret(&secret))
            .transpose()
            .map_err(|e| AtomicError::invalid(e.to_string()))?;
        let db = shared.db.with_own_agent(agent);
        Ok(AtomicStore::build(shared, db, drive, false))
    }

    /// The default store, as `open_db` and `load_agent` left it.
    #[flutter_rust_bridge::frb(ignore)]
    pub(crate) fn global() -> Result<&'static AtomicStore, AtomicError> {
        super::simple::state::default_store().map_err(AtomicError::storage)
    }

    /// Whether this handle is on the default store's file (whose peer sync
    /// the process runs).
    #[cfg(test)]
    fn on_default_store(&self) -> bool {
        super::simple::state::db()
            .map(|g| std::sync::Arc::ptr_eq(&g.kv, &self.db.kv))
            .unwrap_or(false)
    }

    /// The pusher of this handle's writes: its session, and the peers when
    /// it is on the default store.
    #[flutter_rust_bridge::frb(ignore)]
    pub(crate) fn pusher(&self) -> std::sync::Arc<dyn atomic_lib::host::LocalWritePusher> {
        std::sync::Arc::new(crate::host::BridgePusher {
            db: self.db.clone(),
            sync: self.sync.clone(),
        })
    }

    /// Pin the working drive of a handle that is not the default (the
    /// default follows the store's active drive).
    #[flutter_rust_bridge::frb(ignore)]
    fn pin_drive(&self, drive: &str) {
        if !self.default {
            *self.drive.lock().unwrap_or_else(|e| e.into_inner()) = Some(drive.to_string());
        }
    }

    /// Whether both handles are on the same open store.
    #[flutter_rust_bridge::frb(sync)]
    pub fn shares_store_with(&self, other: &AtomicStore) -> bool {
        std::sync::Arc::ptr_eq(&self.db.kv, &other.db.kv)
    }

    /// Create an agent named `name` and its private drive in this store, and
    /// sign with that agent from now on, working in the new drive. Returns
    /// the agent's secret (to keep) and the drive's subject.
    pub async fn setup(&self, name: String) -> Result<StoreSetup, AtomicError> {
        let (agent, drive) = self.db.setup(&name).await?;
        self.pin_drive(&drive);
        // Other devices find this one in the new drive's record.
        super::simple::peer_search_again();
        Ok(StoreSetup {
            agent_secret: agent.build_secret()?,
            agent_subject: agent.subject.to_string(),
            drive,
        })
    }

    /// The subject of the agent that signs, if one is set.
    #[flutter_rust_bridge::frb(sync)]
    pub fn agent_subject(&self) -> Option<String> {
        self.db.get_default_agent().ok().map(|a| a.subject.to_string())
    }

    /// The drive this handle works in: the one set on it, else the store's
    /// active drive.
    #[flutter_rust_bridge::frb(sync)]
    pub fn drive(&self) -> Option<String> {
        self.drive
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .or_else(|| self.db.get_active_drive())
    }

    /// Work in `drive` from now on (this handle only).
    #[flutter_rust_bridge::frb(sync)]
    pub fn set_drive(&self, drive: String) {
        *self.drive.lock().unwrap_or_else(|e| e.into_inner()) = Some(drive);
    }

    // ── Reads ──

    /// The resource `subject` as the local store holds it. [`AtomicError::NotFound`]
    /// when this device does not have it (sync first, or ask the server).
    pub async fn get_resource_data(&self, subject: String) -> Result<ResourceData, AtomicError> {
        let resource = self.db.get_resource(&subject.as_str().into()).await?;
        Ok(ResourceData {
            subject: resource.get_subject().to_string(),
            props: propvals_to_list(resource.get_propvals()),
        })
    }

    /// The subjects under `parent`, in the order the sidebar shows them (at
    /// most `limit`), without the folders the web hides.
    pub async fn get_child_subjects(
        &self,
        parent: String,
        limit: u32,
    ) -> Result<Vec<String>, AtomicError> {
        let listed = lists::list_children(&self.db, &parent, limit as usize).await?;
        Ok(listed["children"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| r["subject"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Full-text search, best first, across every drive or only under `drive`
    /// (the hit is `drive` itself or has it among its ancestors). With `is_a`
    /// (a class URL) only resources of that class are returned; the class is
    /// filtered in the index, before `limit`.
    pub async fn search_resources(
        &self,
        query: String,
        drive: Option<String>,
        limit: u32,
        is_a: Option<String>,
    ) -> Result<Vec<SearchHit>, AtomicError> {
        let classes: Vec<String> = is_a.into_iter().filter(|c| !c.is_empty()).collect();
        let rows = lists::search_classes(&self.db, drive.as_deref(), &query, limit as usize, &classes)?;
        let text =
            |row: &serde_json::Value, key: &str| row[key].as_str().unwrap_or_default().to_string();
        Ok(rows
            .iter()
            .map(|row| SearchHit {
                subject: text(row, "subject"),
                title: text(row, "title"),
                class_name: text(row, "class_name"),
                drive: text(row, "drive"),
                score: row["score"].as_f64().unwrap_or_default(),
            })
            .collect())
    }

    // ── Writes ──

    #[flutter_rust_bridge::frb(ignore)]
    pub(crate) fn node(&self) -> atomic_lib::runtime::AtomicNode {
        atomic_lib::runtime::AtomicNode::from_db((*self.db).clone())
    }

    async fn push(&self, response: &atomic_lib::commit::CommitResponse) {
        push_write(response, self.db.as_ref(), &self.sync).await;
    }

    /// Set the `changes` properties and remove the `remove` ones of an
    /// existing resource, as one signed commit by this handle's agent.
    pub async fn save_resource_changes(
        &self,
        subject: String,
        changes: Vec<PropValue>,
        remove: Vec<String>,
    ) -> Result<(), AtomicError> {
        let mut resource = self.db.get_resource(&subject.as_str().into()).await?;
        for p in &changes {
            resource.set_unsafe(p.property.clone(), atomic_to_value(&p.value)?)?;
        }
        for property in &remove {
            resource.remove_propval(property)?;
        }
        let response = self.node().save_locally(&mut resource).await?;
        self.push(&response).await;
        Ok(())
    }

    /// Create a resource with a new subject (a DID derived from the signed
    /// genesis commit) holding `values`, signed by this handle's agent.
    /// Returns its subject. `values` should include `isA` and `parent`.
    pub async fn create_resource_with_values(
        &self,
        values: Vec<PropValue>,
    ) -> Result<String, AtomicError> {
        if values.is_empty() {
            return Err(AtomicError::invalid("A new resource needs properties"));
        }
        let agent = self.db.get_default_agent()?;
        let mut builder = CommitBuilder::new("placeholder".into());
        for p in &values {
            builder.set(p.property.clone(), atomic_to_value(&p.value)?);
        }
        let commit = Commit::create_did(builder, &agent, self.db.as_ref()).await?;
        let subject = commit.subject.to_string();
        let response = self
            .node()
            .apply_local_commit(commit, &atomic_lib::host::own_commit_opts())
            .await?;
        self.push(&response).await;
        Ok(subject)
    }

    /// Destroy `subject` and, recursively, its children: a signed destroy
    /// commit by this handle's agent, queued for the server like any write.
    /// [`AtomicError::NotFound`] when this device does not have it.
    pub async fn destroy_resource(&self, subject: String) -> Result<(), AtomicError> {
        let subject = atomic_lib::Subject::from(subject.as_str());
        let resource = self.db.get_resource(&subject).await?;
        let agent = self.db.get_default_agent()?;
        let mut builder = CommitBuilder::new(subject);
        builder.destroy(true);
        let commit = builder.sign(&agent, self.db.as_ref(), &resource).await?;
        let response = self
            .node()
            .apply_local_commit(commit, &atomic_lib::host::own_commit_opts())
            .await?;
        self.push(&response).await;
        Ok(())
    }

    /// Create a drive named `name`, which this handle works in from now on.
    /// Returns its subject.
    pub async fn new_drive(&self, name: String) -> Result<String, AtomicError> {
        let drive = self.db.create_drive(&name).await?;
        self.pin_drive(&drive);
        Ok(drive)
    }

    // ── Agent ──

    /// Sign as the agent of `secret` from now on (this handle only). When
    /// the secret names a drive, this handle works in it. `needs_sync` says
    /// that drive is not in the store yet: fetch it from a server
    /// ([`AtomicStore::open_ws_sync`]) or a paired device first.
    pub async fn load_agent(&self, secret: String) -> Result<StoreAgentLoad, AtomicError> {
        let loaded = self.db.load_agent_from_secret(&secret).await?;
        if let Some(drive) = &loaded.agent.initial_drive {
            self.pin_drive(&drive.to_string());
        }
        Ok(StoreAgentLoad {
            agent_subject: loaded.agent.subject.to_string(),
            needs_sync: loaded.drive_needs_sync,
        })
    }

    /// Sign in as the agent of `secret` like [`AtomicStore::load_agent`], and
    /// when this handle was signed in as a different agent that has work, bring
    /// that work along: the old agent adds the new one to `write` on every drive
    /// it can write, and the drives are listed on the new agent's home (see
    /// `Db::bring_along`). Both writes are local and sync later.
    ///
    /// `previous_secret` is the old agent's secret whenever there was a
    /// different old agent, work or not. The package never stores it: the app
    /// decides where it is archived.
    pub async fn sign_in(&self, secret: String) -> Result<StoreSignIn, AtomicError> {
        let previous = self.db.get_default_agent().ok();
        let loaded = self.db.load_agent_from_secret(&secret).await?;
        if let Some(drive) = &loaded.agent.initial_drive {
            self.pin_drive(&drive.to_string());
        }
        let mut brought_along = Vec::new();
        let mut previous_secret = None;
        if let Some(previous) =
            previous.filter(|p| p.subject != loaded.agent.subject && p.private_key.is_some())
        {
            if self.db.has_work_to_bring(&previous).await? {
                brought_along = self.db.bring_along(&previous, &loaded.agent).await?.drives;
            }
            previous_secret = Some(previous.build_secret()?);
        }
        // The account's other devices look for this one in the secret's drive:
        // announce there and search it now, when the peer already runs. (The
        // search loop reads the drives each round and announces on a change.)
        super::simple::peer_search_again();
        Ok(StoreSignIn {
            agent_subject: loaded.agent.subject.to_string(),
            needs_sync: loaded.drive_needs_sync,
            brought_along,
            previous_secret,
        })
    }

    // ── Sync ──

    /// Open this handle's own WebSocket session to the server at
    /// `server_origin`: sign in as this handle's agent, subscribe to its
    /// drive (fetching it when missing), apply what the server sends, and send
    /// what waits in the store's outbox. Replaces the session this handle had.
    /// Writes through this handle go out over it from now on.
    pub async fn open_ws_sync(&self, server_origin: String) -> Result<(), AtomicError> {
        let drive = self.drive();
        let have_drive = self
            .sync
            .open(&self.db, drive.clone(), &server_origin)
            .await
            .map_err(AtomicError::network)?;
        if have_drive {
            if let (true, Some(drive)) = (self.default, drive) {
                // The person's other drives may be on the server; the
                // search and pairing machinery behind this is the process's.
                tokio::spawn(super::simple::follow_listed_drives(drive));
            }
            super::assistant::follow_conversations_in_background(self);
        }
        Ok(())
    }

    /// Close this handle's session. Writes wait in the outbox for the next
    /// [`AtomicStore::open_ws_sync`].
    pub async fn close_ws_sync(&self) {
        self.sync.close().await;
    }

    /// The server this handle's session was last opened on.
    #[flutter_rust_bridge::frb(sync)]
    pub fn connected_server(&self) -> Option<String> {
        self.sync.origin()
    }

    /// Whether the session is open now.
    #[flutter_rust_bridge::frb(sync)]
    pub fn is_syncing(&self) -> bool {
        self.sync.is_open()
    }

    /// Send what waits in the outbox over this handle's session now. `true`
    /// when nothing is left waiting; without a session nothing is attempted.
    pub async fn push_pending(&self) -> bool {
        self.sync.drain_outbox(&self.db).await
    }

    // ── Watching ──

    /// Wait until `subject` changes or is destroyed, or `timeout_ms` passes.
    /// Call it in a loop (re-reading the resource on `Changed`) to watch a
    /// resource.
    pub async fn wait_for_resource_event(
        &self,
        subject: String,
        timeout_ms: u32,
    ) -> Result<ResourceEvent, AtomicError> {
        Ok(super::simple::resource::wait_resource_event(
            &self.db,
            &subject,
            std::time::Duration::from_millis(timeout_ms as u64),
        )
        .await)
    }
}

impl AtomicStore {
    /// Wait until any resource in the store changes or is destroyed, or
    /// `timeout_ms` passes: the building block of watching a list.
    pub async fn wait_for_store_event(&self, timeout_ms: u32) -> Result<StoreEvent, AtomicError> {
        Ok(super::simple::resource::wait_store_event(
            &self.db,
            std::time::Duration::from_millis(timeout_ms as u64),
        )
        .await)
    }
}

/// What [`AtomicStore::load_agent`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreAgentLoad {
    pub agent_subject: String,
    /// The agent's drive is not in the store yet.
    pub needs_sync: bool,
}

/// What [`AtomicStore::sign_in`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSignIn {
    pub agent_subject: String,
    /// The agent's drive is not in the store yet.
    pub needs_sync: bool,
    /// Drives of the agent that was signed in before that now belong to the
    /// new one too. Empty when there was no such agent or it had no work.
    pub brought_along: Vec<String>,
    /// The secret of the agent signed in before, when it was a different one.
    /// Sensitive; the caller archives it.
    pub previous_secret: Option<String>,
}

/// What [`AtomicStore::setup`] made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSetup {
    /// The agent's secret: keep it to open the store as this agent again.
    pub agent_secret: String,
    pub agent_subject: String,
    /// The agent's private drive.
    pub drive: String,
}

// ── The default store ──────────────────────────────────────────────────────
//
// The same calls on the store `open_db` opened and the agent `load_agent`
// set, for the screens that have not moved to a handle.

/// [`AtomicStore::get_resource_data`] on the default store.
pub async fn get_resource_data(subject: String) -> Result<ResourceData, AtomicError> {
    AtomicStore::global()?.get_resource_data(subject).await
}

/// [`AtomicStore::get_child_subjects`] on the default store.
pub async fn get_child_subjects(parent: String, limit: u32) -> Result<Vec<String>, AtomicError> {
    AtomicStore::global()?.get_child_subjects(parent, limit).await
}

/// [`AtomicStore::search_resources`] on the default store.
pub async fn search_resources(
    query: String,
    drive: Option<String>,
    limit: u32,
    is_a: Option<String>,
) -> Result<Vec<SearchHit>, AtomicError> {
    AtomicStore::global()?
        .search_resources(query, drive, limit, is_a)
        .await
}

/// [`AtomicStore::save_resource_changes`] on the default store.
pub async fn save_resource_changes(
    subject: String,
    changes: Vec<PropValue>,
    remove: Vec<String>,
) -> Result<(), AtomicError> {
    AtomicStore::global()?
        .save_resource_changes(subject, changes, remove)
        .await
}

/// [`AtomicStore::create_resource_with_values`] on the default store.
pub async fn create_resource_with_values(values: Vec<PropValue>) -> Result<String, AtomicError> {
    AtomicStore::global()?.create_resource_with_values(values).await
}

/// [`AtomicStore::new_drive`] on the default store.
pub async fn new_drive(name: String) -> Result<String, AtomicError> {
    AtomicStore::global()?.new_drive(name).await
}

/// [`AtomicStore::wait_for_resource_event`] on the default store.
pub async fn wait_for_resource_event(
    subject: String,
    timeout_ms: u32,
) -> Result<ResourceEvent, AtomicError> {
    AtomicStore::global()?
        .wait_for_resource_event(subject, timeout_ms)
        .await
}

/// [`AtomicStore::destroy_resource`] on the default store.
pub async fn destroy_resource(subject: String) -> Result<(), AtomicError> {
    AtomicStore::global()?.destroy_resource(subject).await
}

/// [`AtomicStore::wait_for_store_event`] on the default store.
pub async fn wait_for_store_event(timeout_ms: u32) -> Result<StoreEvent, AtomicError> {
    AtomicStore::global()?.wait_for_store_event(timeout_ms).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ErrorKind;
    use crate::api::simple::tests::shared_drive;
    use atomic_lib::urls;

    fn roundtrip(value: AtomicValue) {
        let lib = atomic_to_value(&value).unwrap();
        assert_eq!(value_to_atomic(&lib), value);
    }

    fn scalar(datatype: Datatype, text: &str) -> AtomicValue {
        AtomicValue::scalar(datatype, text)
    }

    #[test]
    fn values_survive_a_round_trip_through_the_library_type() {
        roundtrip(scalar(Datatype::String, "a"));
        roundtrip(scalar(Datatype::Markdown, "# a"));
        roundtrip(scalar(Datatype::Link, "https://example.com/x"));
        roundtrip(scalar(Datatype::Integer, "-4"));
        roundtrip(scalar(Datatype::Float, "1.5"));
        roundtrip(scalar(Datatype::Timestamp, "1700000000000"));
        roundtrip(scalar(Datatype::Boolean, "true"));
        roundtrip(scalar(Datatype::Json, "{\"a\":1}"));
        roundtrip(AtomicValue {
            items: vec![
                scalar(Datatype::Link, "https://example.com/a"),
                AtomicValue {
                    props: vec![PropValue {
                        property: "https://example.com/p".into(),
                        value: scalar(Datatype::Integer, "1"),
                    }],
                    ..scalar(Datatype::Nested, "")
                },
            ],
            ..scalar(Datatype::Array, "")
        });
        roundtrip(AtomicValue {
            props: vec![PropValue {
                property: "nl".into(),
                value: scalar(Datatype::String, "hallo"),
            }],
            ..scalar(Datatype::Localized, "")
        });
    }

    #[test]
    fn what_cannot_be_written_is_invalid() {
        let kind = |v: AtomicValue| atomic_to_value(&v).unwrap_err().kind;
        assert_eq!(kind(scalar(Datatype::Unsupported, "y")), ErrorKind::Invalid);
        assert_eq!(kind(scalar(Datatype::Json, "{")), ErrorKind::Invalid);
        assert_eq!(kind(scalar(Datatype::Integer, "four")), ErrorKind::Invalid);
        assert_eq!(kind(scalar(Datatype::Boolean, "yes")), ErrorKind::Invalid);
        let bad_array = AtomicValue {
            items: vec![scalar(Datatype::Integer, "1")],
            ..scalar(Datatype::Array, "")
        };
        assert_eq!(kind(bad_array), ErrorKind::Invalid);
    }

    fn text(property: &str, value: &str) -> PropValue {
        PropValue {
            property: property.into(),
            value: scalar(Datatype::String, value),
        }
    }

    fn prop<'a>(data: &'a ResourceData, property: &str) -> Option<&'a AtomicValue> {
        data.props.iter().find(|p| p.property == property).map(|p| &p.value)
    }

    #[tokio::test]
    async fn a_resource_is_created_read_changed_and_found() {
        let drive = shared_drive().await.to_string();
        let subject = create_resource_with_values(vec![
            PropValue {
                property: urls::IS_A.into(),
                value: AtomicValue {
                    items: vec![scalar(Datatype::Link, urls::FOLDER)],
                    ..scalar(Datatype::Array, "")
                },
            },
            text(urls::NAME, "Typed pelican"),
            PropValue {
                property: urls::PARENT.into(),
                value: scalar(Datatype::Link, &drive),
            },
        ])
        .await
        .unwrap();

        let data = get_resource_data(subject.clone()).await.unwrap();
        assert_eq!(data.subject, subject);
        assert_eq!(prop(&data, urls::NAME), Some(&scalar(Datatype::String, "Typed pelican")));
        assert_eq!(prop(&data, urls::PARENT), Some(&scalar(Datatype::Link, &drive)));

        save_resource_changes(
            subject.clone(),
            vec![text(urls::NAME, "Typed heron"), text(urls::DESCRIPTION, "A bird")],
            vec![],
        )
        .await
        .unwrap();
        let data = get_resource_data(subject.clone()).await.unwrap();
        assert_eq!(prop(&data, urls::NAME), Some(&scalar(Datatype::String, "Typed heron")));
        save_resource_changes(subject.clone(), vec![], vec![urls::DESCRIPTION.into()])
            .await
            .unwrap();
        assert!(prop(&get_resource_data(subject.clone()).await.unwrap(), urls::DESCRIPTION).is_none());

        let children = get_child_subjects(drive.clone(), 100).await.unwrap();
        assert!(children.contains(&subject));

        // Other tests write to this store at the same time. Each
        // `wait_for_store_event` subscribes anew, so looping over it can miss
        // ours between two calls: hold one subscription instead.
        let mut events = AtomicStore::global().unwrap().db.subscribe_events();
        destroy_resource(subject.clone()).await.unwrap();
        let destroyed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match events.recv().await {
                    Ok(atomic_lib::DbEvent::Destroyed { subject: s, .. }) if s.to_string() == subject => {
                        return true;
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return false,
                }
            }
        })
        .await;
        assert_eq!(destroyed, Ok(true));
        assert_eq!(
            get_resource_data(subject.clone()).await.unwrap_err().kind,
            ErrorKind::NotFound
        );
        assert!(!get_child_subjects(drive, 100).await.unwrap().contains(&subject));
        assert_eq!(
            destroy_resource(subject).await.unwrap_err().kind,
            ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn an_unknown_class_and_property_are_stored_and_read_back_typed() {
        let drive = shared_drive().await.to_string();
        let class = "https://example.com/classes/Task";
        let done = "https://example.com/properties/done";
        let subject = create_resource_with_values(vec![
            PropValue {
                property: urls::IS_A.into(),
                value: AtomicValue {
                    items: vec![scalar(Datatype::Link, class)],
                    ..scalar(Datatype::Array, "")
                },
            },
            text(urls::NAME, "Book flights"),
            PropValue {
                property: done.into(),
                value: scalar(Datatype::Boolean, "false"),
            },
            PropValue {
                property: urls::PARENT.into(),
                value: scalar(Datatype::Link, &drive),
            },
        ])
        .await
        .unwrap();
        save_resource_changes(
            subject.clone(),
            vec![PropValue {
                property: done.into(),
                value: scalar(Datatype::Boolean, "true"),
            }],
            vec![],
        )
        .await
        .unwrap();
        let data = get_resource_data(subject).await.unwrap();
        assert_eq!(prop(&data, done), Some(&scalar(Datatype::Boolean, "true")));
        let is_a = prop(&data, urls::IS_A).unwrap();
        assert_eq!(is_a.items, vec![scalar(Datatype::Link, class)]);
    }

    #[tokio::test]
    async fn a_missing_resource_is_not_found_and_a_bad_value_is_invalid() {
        let drive = shared_drive().await.to_string();
        let missing = get_resource_data(format!("{drive}/no-such-resource")).await;
        assert_eq!(missing.unwrap_err().kind, ErrorKind::NotFound);
        let bad = save_resource_changes(
            drive,
            vec![PropValue {
                property: urls::NAME.into(),
                value: scalar(Datatype::Json, "{"),
            }],
            vec![],
        )
        .await;
        assert_eq!(bad.unwrap_err().kind, ErrorKind::Invalid);
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-bridge-handle-{name}-{}-{}",
            std::process::id(),
            super::super::simple::state::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn folder(name: &str, parent: &str) -> Vec<PropValue> {
        vec![
            PropValue {
                property: urls::IS_A.into(),
                value: AtomicValue {
                    items: vec![scalar(Datatype::Link, urls::FOLDER)],
                    ..scalar(Datatype::Array, "")
                },
            },
            text(urls::NAME, name),
            PropValue {
                property: urls::PARENT.into(),
                value: scalar(Datatype::Link, parent),
            },
        ]
    }

    async fn open(dir: &std::path::Path) -> AtomicStore {
        AtomicStore::open(dir.to_string_lossy().into_owned(), None, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn two_handles_on_different_files_have_their_own_agent_and_drive() {
        let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
        let (a, b) = (open(&dir_a).await, open(&dir_b).await);
        assert!(!a.shares_store_with(&b));
        let sa = a.setup("Alice".into()).await.unwrap();
        let sb = b.setup("Bob".into()).await.unwrap();
        assert_ne!(sa.agent_subject, sb.agent_subject);
        assert_ne!(sa.drive, sb.drive);
        assert_eq!(a.agent_subject(), Some(sa.agent_subject.clone()));
        assert_eq!(b.drive(), Some(sb.drive.clone()));

        let in_a = a
            .create_resource_with_values(folder("Alice's", &sa.drive))
            .await
            .unwrap();
        let in_b = b
            .create_resource_with_values(folder("Bob's", &sb.drive))
            .await
            .unwrap();
        assert_eq!(a.get_resource_data(in_a.clone()).await.unwrap().subject, in_a);
        assert_eq!(
            a.get_resource_data(in_b.clone()).await.unwrap_err().kind,
            ErrorKind::NotFound
        );
        assert_eq!(a.get_child_subjects(sa.drive.clone(), 10).await.unwrap(), vec![in_a]);
        assert_eq!(b.get_child_subjects(sb.drive.clone(), 10).await.unwrap(), vec![in_b]);

        // Reopening with the secret signs as the same agent.
        let again = AtomicStore::open(
            dir_a.to_string_lossy().into_owned(),
            Some(sa.agent_secret.clone()),
            Some(sa.drive.clone()),
        )
        .await
        .unwrap();
        assert_eq!(again.agent_subject(), Some(sa.agent_subject));
        assert!(again.shares_store_with(&a));
        std::fs::remove_dir_all(dir_a).ok();
        std::fs::remove_dir_all(dir_b).ok();
    }

    #[tokio::test]
    async fn two_handles_on_one_path_share_the_store_not_the_agent() {
        let dir = temp_dir("same");
        let (a, b) = (open(&dir).await, open(&dir).await);
        assert!(a.shares_store_with(&b), "the file is opened once");
        let sa = a.setup("Alice".into()).await.unwrap();
        assert_eq!(b.agent_subject(), None, "b has no agent of its own yet");
        let sb = b.setup("Bob".into()).await.unwrap();
        assert_eq!(a.agent_subject(), Some(sa.agent_subject.clone()));
        assert_ne!(sa.agent_subject, sb.agent_subject);
        assert_ne!(a.drive(), b.drive());

        // One store: a's write is b's read, signed by a.
        let subject = a
            .create_resource_with_values(folder("Shared", &sa.drive))
            .await
            .unwrap();
        let seen = b.get_resource_data(subject.clone()).await.unwrap();
        assert_eq!(prop(&seen, urls::NAME), Some(&scalar(Datatype::String, "Shared")));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_handle_on_the_default_path_shares_the_default_store() {
        shared_drive().await;
        let dir = super::super::simple::state::store_dir().unwrap();
        let handle = open(&dir).await;
        let default = AtomicStore::global().unwrap();
        assert!(handle.shares_store_with(&default));
        assert!(handle.on_default_store());
        let other = open(&temp_dir("not-default")).await;
        assert!(!other.on_default_store());
    }
    fn link_prop(property: &str, subject: &str) -> PropValue {
        PropValue {
            property: property.into(),
            value: scalar(Datatype::Link, subject),
        }
    }

    #[tokio::test]
    async fn search_matches_by_ancestry_filters_by_class_and_names_the_class() {
        let dir = temp_dir("search");
        let h = open(&dir).await;
        let setup = h.setup("Searcher".into()).await.unwrap();
        let drive = setup.drive.clone();
        let task = "https://example.com/classes/Task";
        let shelf = h
            .create_resource_with_values(folder("Zebra shelf", &drive))
            .await
            .unwrap();
        let note = h
            .create_resource_with_values(vec![
                PropValue {
                    property: urls::IS_A.into(),
                    value: AtomicValue {
                        items: vec![scalar(Datatype::Link, task)],
                        ..scalar(Datatype::Array, "")
                    },
                },
                text(urls::NAME, "Zebra note"),
                text(urls::DESCRIPTION, "stripes"),
                link_prop(urls::PARENT, &shelf),
                // Custom properties are stored and read back, not indexed.
                PropValue {
                    property: "https://example.com/properties/tags".into(),
                    value: scalar(Datatype::Json, "[\"urgent\",\"home office\"]"),
                },
                text("https://example.com/properties/memo", "quokkaonly"),
            ])
            .await
            .unwrap();
        let other_drive = h.new_drive("Elsewhere".into()).await.unwrap();
        let elsewhere = h
            .create_resource_with_values(folder("Zebra elsewhere", &other_drive))
            .await
            .unwrap();

        let subjects = |hits: &[SearchHit]| hits.iter().map(|x| x.subject.clone()).collect::<Vec<_>>();
        let search = |drive: Option<&str>, is_a: Option<&str>| {
            h.search_resources("zebra".into(), drive.map(Into::into), 20, is_a.map(Into::into))
        };

        // A drive scope matches every descendant, not only direct children.
        let in_drive = search(Some(&drive), None).await.unwrap();
        assert!(subjects(&in_drive).contains(&shelf), "{in_drive:?}");
        assert!(subjects(&in_drive).contains(&note), "{in_drive:?}");
        assert!(!subjects(&in_drive).contains(&elsewhere), "{in_drive:?}");
        let hit = in_drive.iter().find(|x| x.subject == note).unwrap();
        assert_eq!(hit.title, "Zebra note");
        assert_eq!(hit.drive, drive, "a hit names its drive, not its parent");
        // The class name is the class's `name`, the class URL when it has none.
        assert_eq!(hit.class_name, task);
        let shelf_hit = in_drive.iter().find(|x| x.subject == shelf).unwrap();
        assert!(!shelf_hit.class_name.is_empty() && shelf_hit.class_name != urls::FOLDER);

        // Any ancestor scopes, and so does the resource itself.
        let in_shelf = search(Some(&shelf), None).await.unwrap();
        assert!(subjects(&in_shelf).contains(&note) && subjects(&in_shelf).contains(&shelf));

        // Without a scope every drive is searched.
        let everywhere = search(None, None).await.unwrap();
        assert!(subjects(&everywhere).contains(&elsewhere) && subjects(&everywhere).contains(&note));
        assert!(!search(Some(&other_drive), None).await.unwrap().iter().any(|x| x.subject == note));

        // The class filter keeps only that class (a URL).
        let tasks = search(Some(&drive), Some(task)).await.unwrap();
        assert_eq!(subjects(&tasks), vec![note.clone()]);
        let folders = search(Some(&drive), Some(urls::FOLDER)).await.unwrap();
        assert_eq!(subjects(&folders), vec![shelf.clone()]);

        // A custom property is not in the index; the description is.
        assert!(h
            .search_resources("quokkaonly".into(), None, 20, None)
            .await
            .unwrap()
            .is_empty());
        let by_description = h.search_resources("stripes".into(), None, 20, None).await.unwrap();
        assert_eq!(subjects(&by_description), vec![note.clone()]);

        // JSON (a list of strings) is stored as JSON and read back as JSON text.
        let data = h.get_resource_data(note).await.unwrap();
        let tags = prop(&data, "https://example.com/properties/tags").unwrap();
        assert_eq!(tags.datatype, Datatype::Json);
        let decoded: Vec<String> = serde_json::from_str(&tags.text).unwrap();
        assert_eq!(decoded, vec!["urgent", "home office"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn loading_the_secret_on_a_fresh_device_works_in_the_secrets_drive() {
        let (dir_a, dir_b) = (temp_dir("secret-a"), temp_dir("secret-b"));
        let a = open(&dir_a).await;
        let made = a.setup("Alice".into()).await.unwrap();

        // What `AtomicFlutter.open(agentSecret:)` does without a `drive:`.
        let b = AtomicStore::open(
            dir_b.to_string_lossy().into_owned(),
            Some(made.agent_secret.clone()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(b.drive(), None, "a fresh device has no drive of its own");
        let loaded = b.load_agent(made.agent_secret).await.unwrap();
        assert_eq!(loaded.agent_subject, made.agent_subject);
        assert!(loaded.needs_sync, "the drive is not on this device yet");
        assert_eq!(b.drive(), Some(made.drive));
        std::fs::remove_dir_all(dir_a).ok();
        std::fs::remove_dir_all(dir_b).ok();
    }

    #[tokio::test]
    async fn signing_in_as_someone_else_brings_the_old_agents_drives_along() {
        let (dir_a, dir_b) = (temp_dir("bring-a"), temp_dir("bring-b"));
        let (a, b) = (open(&dir_a).await, open(&dir_b).await);
        let alice = a.setup("Alice".into()).await.unwrap();
        let bob = b.setup("Bob".into()).await.unwrap();
        let shared = a.new_drive("Shared".into()).await.unwrap();

        let signed = a.sign_in(bob.agent_secret.clone()).await.unwrap();
        assert_eq!(signed.agent_subject, bob.agent_subject);
        assert_eq!(signed.brought_along, vec![shared.clone()]);
        let previous = atomic_lib::agents::Agent::from_secret(
            &signed.previous_secret.expect("the old secret comes back"),
        )
        .unwrap();
        assert_eq!(previous.subject.to_string(), alice.agent_subject);
        assert!(a
            .db
            .list_drives()
            .await
            .unwrap()
            .iter()
            .any(|d| d.subject == shared));

        // Again as the same agent: a plain sign-in.
        let again = a.sign_in(bob.agent_secret).await.unwrap();
        assert!(again.brought_along.is_empty());
        assert_eq!(again.previous_secret, None);
        std::fs::remove_dir_all(dir_a).ok();
        std::fs::remove_dir_all(dir_b).ok();
    }

    #[tokio::test]
    async fn signing_in_with_nothing_to_bring_still_returns_the_old_secret() {
        let (dir_a, dir_b) = (temp_dir("nobring-a"), temp_dir("nobring-b"));
        let (a, b) = (open(&dir_a).await, open(&dir_b).await);
        a.setup("Alice".into()).await.unwrap();
        let bob = b.setup("Bob".into()).await.unwrap();
        let signed = a.sign_in(bob.agent_secret).await.unwrap();
        assert!(signed.brought_along.is_empty());
        assert!(signed.previous_secret.is_some());
        std::fs::remove_dir_all(dir_a).ok();
        std::fs::remove_dir_all(dir_b).ok();
    }
}
