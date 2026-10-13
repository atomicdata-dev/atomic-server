// The bindings here use `Db::init_redb_opfs`, which is only compiled for the
// wasm32 target (see `lib/src/db.rs`). When cargo runs `clippy/fmt/check` on
// the workspace from a host target, this crate's body would otherwise fail to
// compile. Stub the whole module out on non-wasm32 targets so workspace-level
// commands stay green; the cdylib build still happens via `wasm-pack` (see
// `.dagger/src/index.ts:wasmBuild`) which targets wasm32-unknown-unknown.
#![cfg(target_arch = "wasm32")]

use atomic_lib::{
    parse::ParseOpts,
    runtime::{AtomicNode, IngestPolicy},
    storelike::{Query, QueryResult, Storelike},
    vault::dek::DriveVaultKey,
    vault::keys::{argon2id_derive_key, Argon2Params},
    vault::secret_envelope::{NewWrapper, SecretEnvelope, Unlock},
    vault::store::{MemoryVaultStore, VaultObjectStore},
    vault::sync::{
        commit_lane_state, drive_prefix, export_vault_segment, import_vault_batch,
        CheckpointPolicy, HistoryKeep, SegmentKind,
    },
    Db, Resource, Subject, Value,
};
use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Marker spliced into the `ClientDb.open` error message when the existing OPFS
/// file is a well-formed encrypted database that this key cannot decrypt.
///
/// The local database is a pure cache, so JS self-heals that one case by
/// deleting the file and recreating it (`browser/lib/src/client-db-open.ts`).
/// It matches on this token rather than on the prose message, and every other
/// open failure — corrupt file, unsupported version, OPFS unavailable — stays
/// unmarked so it can never trigger a delete.
const WRONG_KEY_MARKER: &str = "ATOMIC_DB_WRONG_KEY";

/// Marks the other explainable open failure: the browser refuses this origin
/// storage at all (private browsing, tracking prevention, site data blocked).
/// Nothing is wrong with the data and retrying cannot help, so JS reports it
/// as a plain degraded-mode sentence rather than a wasm stack trace.
const STORAGE_BLOCKED_MARKER: &str = "ATOMIC_DB_STORAGE_BLOCKED";

/// A client-side Atomic Data database backed by redb (in-memory, future OPFS).
/// Provides indexed queries, resource storage, and commit application.
///
/// A JS binding over [`AtomicNode`]: query and commit application go through
/// the node; the cache-shaped operations (raw get/put, blobs, version
/// vectors, import/export, vault) still reach the store directly until the
/// node names them.
#[wasm_bindgen]
pub struct ClientDb {
    node: AtomicNode,
    peer_sessions:
        std::collections::HashMap<u32, atomic_lib::sync::browser_peer::BrowserPeerSession>,
    next_peer_session: u32,
}

impl ClientDb {
    async fn drive_subject_list(&self, drive: &str) -> Vec<String> {
        let drive_subject =
            atomic_lib::Subject::from_raw(drive, self.db().get_base_domain().as_deref());

        atomic_lib::sync::engine::collect_drive_subjects(self.db(), &drive_subject)
            .await
            .into_iter()
            .collect()
    }

    fn version_vectors_of(&self, subjects: Vec<String>) -> Result<JsValue, JsError> {
        use atomic_lib::db::trees::Tree;
        use atomic_lib::loro::AtomicLoroDoc;
        use std::collections::HashMap;

        let mut result: HashMap<String, HashMap<String, i32>> = HashMap::new();

        for subject in subjects {
            // `collect_drive_subjects` yields `pure_id()` strings, which are
            // exactly the `LoroSnapshots` keys.
            match self.db().kv.get(Tree::LoroSnapshots, subject.as_bytes()) {
                Ok(Some(snapshot_bytes)) => {
                    match AtomicLoroDoc::vv_map_from_snapshot(&snapshot_bytes) {
                        Ok(vv) => {
                            result.insert(subject, vv);
                        }
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!("[ClientDb] Failed to read VV for {}: {e}", subject)
                                    .into(),
                            );
                        }
                    }
                }
                // No snapshot for this subject yet (metadata-only / not
                // materialized) — nothing to diff, skip it.
                Ok(None) => {}
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[ClientDb] VV read error for {}: {e}", subject).into(),
                    );
                }
            }
        }

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
    }

    fn db(&self) -> &Db {
        self.node.db()
    }
}

#[wasm_bindgen]
impl ClientDb {
    /// Create a new ClientDb with OPFS persistence.
    /// `base_url` is the server URL, e.g. "https://myserver.com".
    ///
    /// `db_name` selects the OPFS file (default `atomic_data.redb`); the
    /// browser uses one file per agent. `db_key` (32 bytes) turns on at-rest
    /// encryption of that file — without the right key an encrypted file
    /// fails to open instead of exposing another agent's cache.
    ///
    /// Expected runtime: a DedicatedWorker nested inside a per-origin
    /// SharedWorker. The SharedWorker fans tab ports into this single inner
    /// worker so exactly one OPFS sync access handle exists. If this fails,
    /// OPFS is genuinely broken (corrupt, quota, unsupported browser) — the
    /// error surfaces verbatim, except that an undecryptable file is tagged
    /// with `WRONG_KEY_MARKER` so the caller can drop and recreate the cache.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(
        base_url: Option<String>,
        db_name: Option<String>,
        db_key: Option<Vec<u8>>,
    ) -> Result<ClientDb, JsError> {
        let name = validate_db_name(db_name)?;
        let key = validate_db_key(db_key)?;
        let db = Db::init_redb_opfs(base_url, &name, key.as_ref())
            .await
            .map_err(|e| {
                let msg = e.to_string();
                // Tag the one recoverable failure so JS can tell it apart from
                // a corrupt file or a genuinely unavailable OPFS without
                // pattern-matching on prose. See `WRONG_KEY_MARKER`.
                if atomic_lib::db::encrypted_backend::is_wrong_key_error(&msg) {
                    to_js_err(format!("OPFS unavailable [{WRONG_KEY_MARKER}]: {msg}"))
                } else if atomic_lib::db::opfs_backend::is_storage_blocked_error(&msg) {
                    to_js_err(format!(
                        "OPFS unavailable [{STORAGE_BLOCKED_MARKER}]: {msg}"
                    ))
                } else {
                    to_js_err(format!("OPFS unavailable: {msg}"))
                }
            })?;
        web_sys::console::log_1(
            &format!(
                "[ClientDb] Using OPFS persistent storage ({name}, {})",
                if key.is_some() {
                    "encrypted"
                } else {
                    "plaintext"
                }
            )
            .into(),
        );
        Ok(ClientDb {
            node: AtomicNode::from_db(db),
            peer_sessions: Default::default(),
            next_peer_session: 0,
        })
    }

    /// Create a non-persistent in-memory ClientDb. Used in environments
    /// without OPFS — Node integration tests, headless harnesses. Data is
    /// lost when the process exits.
    #[wasm_bindgen(js_name = "newInMemory")]
    pub async fn new_in_memory(base_url: Option<String>) -> Result<ClientDb, JsError> {
        let db = Db::init_redb(base_url).await.map_err(to_js_err)?;
        Ok(ClientDb {
            node: AtomicNode::from_db(db),
            peer_sessions: Default::default(),
            next_peer_session: 0,
        })
    }

    /// Create a separately authenticated peer ingress, never a cache write.
    #[wasm_bindgen(js_name = "createPeerSession")]
    pub fn create_peer_session(
        &mut self,
        drive: String,
        expected_peer: Option<String>,
        challenge: String,
    ) -> Result<u32, JsError> {
        // Every tab of this origin shares this database, and every drive has
        // its own peer room, so the budget scales with drives, not tabs.
        if self.peer_sessions.len() >= 128 {
            return Err(JsError::new("Too many peer sessions"));
        }
        let session = atomic_lib::sync::browser_peer::BrowserPeerSession::new(
            drive,
            expected_peer,
            challenge,
        )
        .map_err(to_js_err)?;
        self.next_peer_session = self
            .next_peer_session
            .checked_add(1)
            .ok_or_else(|| JsError::new("Peer session IDs exhausted"))?;
        self.peer_sessions.insert(self.next_peer_session, session);
        Ok(self.next_peer_session)
    }

    #[wasm_bindgen(js_name = "handlePeerFrame")]
    pub async fn handle_peer_frame(
        &mut self,
        session_id: u32,
        frame: Vec<u8>,
    ) -> Result<JsValue, JsError> {
        let db = self.db().clone();
        let session = self
            .peer_sessions
            .get_mut(&session_id)
            .ok_or_else(|| JsError::new("Unknown peer session"))?;
        let result = session.handle(&db, &frame).await.map_err(to_js_err)?;
        db.flush().map_err(to_js_err)?;
        serde_wasm_bindgen::to_value(&result).map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = "canSendPeerFrame")]
    pub async fn can_send_peer_frame(&self, session_id: u32, subject: &str) -> bool {
        match self.peer_sessions.get(&session_id) {
            Some(session) => session.can_send(self.db(), subject).await,
            None => false,
        }
    }

    #[wasm_bindgen(js_name = "closePeerSession")]
    pub fn close_peer_session(&mut self, session_id: u32) {
        self.peer_sessions.remove(&session_id);
    }

    /// Persist buffered writes to durable OPFS storage.
    ///
    /// Per-write redb commits use `Durability::None` (no fsync) for throughput;
    /// redb only persists those once a *subsequent* Immediate commit lands, so
    /// this is what actually makes recent writes survive. Without it, redb rolls
    /// recent writes back to the last durable commit on the next open (a page
    /// reload), so the local cache reads empty — invisible while online (the
    /// server re-fetches) but data loss the moment you're disconnected. The
    /// worker calls this on a short periodic tick, mirroring the native server.
    pub fn flush(&self) -> Result<(), JsError> {
        self.db().flush().map_err(to_js_err)
    }

    /// Get a resource by its subject URL. Returns JSON-AD string or null.
    #[wasm_bindgen(js_name = "getResource")]
    pub async fn get_resource(&self, subject: &str) -> Result<JsValue, JsError> {
        // Localized in, localized out: the caller addresses resources by the
        // URL it was served, while the store is keyed by `internal:`.
        // `Subject::from` drops the base domain and would look up an
        // `External` subject that does not exist here.
        let subject = Subject::from_raw(subject, self.db().get_base_domain().as_deref());
        match self.db().get_resource(&subject).await {
            Ok(resource) => {
                let json = resource_to_json_ad(&resource, &self.origin())?;
                Ok(JsValue::from_str(&json))
            }
            Err(_) => Ok(JsValue::NULL),
        }
    }

    /// A resource's stored row as JSON-AD plus its Loro snapshot, as
    /// `{ jsonAd, snapshot }` (either may be null), for hydrating a tab.
    ///
    /// Reads the stored projection instead of `getResource`'s path, which
    /// decodes the whole CRDT history into a doc only to serialize it again,
    /// and embeds the snapshot in the JSON-AD a second time. The tab imports
    /// the snapshot into its own doc anyway, so that work was thrown away.
    /// Falls back to `getResource`'s path for subjects without a stored row
    /// (endpoints, agents resolved just in time).
    #[wasm_bindgen(js_name = "getResourceWithSnapshot")]
    pub async fn get_resource_with_snapshot(&self, subject: &str) -> Result<JsValue, JsError> {
        let db = self.db();
        let subject = Subject::from_raw(subject, db.get_base_domain().as_deref());
        let json = match db.get_resource_shallow(&subject) {
            Ok(resource) => Some(resource_to_json_ad(&resource, &self.origin())?),
            Err(_) => match db.get_resource(&subject).await {
                Ok(resource) => Some(resource_to_json_ad(&resource, &self.origin())?),
                Err(_) => None,
            },
        };
        let snapshot = json.as_ref().and_then(|_| db.get_loro_snapshot(&subject));

        let row = js_sys::Object::new();
        let json_ad = json.map(|j| JsValue::from_str(&j)).unwrap_or(JsValue::NULL);
        let snapshot = snapshot
            .map(|bytes| js_sys::Uint8Array::from(bytes.as_slice()).into())
            .unwrap_or(JsValue::NULL);
        js_sys::Reflect::set(&row, &"jsonAd".into(), &json_ad)
            .map_err(|_| JsError::new("could not build the row"))?;
        js_sys::Reflect::set(&row, &"snapshot".into(), &snapshot)
            .map_err(|_| JsError::new("could not build the row"))?;
        Ok(row.into())
    }

    /// Store a resource from a JSON-AD string during initial bulk sync.
    /// Rebuilds the full index for this resource (all atoms).
    /// For incremental updates, use `applyCommit` instead — it only
    /// touches changed properties via the Loro diff.
    #[wasm_bindgen(js_name = "putResource")]
    pub async fn put_resource(&self, json_ad: &str) -> Result<(), JsError> {
        self.put_resource_inner(json_ad, None).await
    }

    /// [`Self::put_resource`] with the resource's Loro snapshot. The row, the
    /// snapshot and the index entries are written in one transaction, and the
    /// snapshot is stored as given rather than rebuilt from the propvals.
    #[wasm_bindgen(js_name = "putResourceWithSnapshot")]
    pub async fn put_resource_with_snapshot(
        &self,
        json_ad: &str,
        snapshot: Vec<u8>,
    ) -> Result<(), JsError> {
        self.put_resource_inner(json_ad, Some(snapshot)).await
    }

    /// [`Self::put_resource_with_snapshot`] for many resources in one write.
    /// `snapshots[i]` is a `Uint8Array` for `json_ads[i]`, or null/undefined
    /// for a resource without a Loro doc.
    #[wasm_bindgen(js_name = "putResourcesWithSnapshots")]
    pub async fn put_resources_with_snapshots(
        &self,
        json_ads: Vec<String>,
        snapshots: js_sys::Array,
    ) -> Result<(), JsError> {
        let mut entries = Vec::with_capacity(json_ads.len());
        for (i, json_ad) in json_ads.iter().enumerate() {
            let value = snapshots.get(i as u32);
            let snapshot = if value.is_null() || value.is_undefined() {
                None
            } else {
                Some(js_sys::Uint8Array::new(&value).to_vec())
            };
            let resource = self.resource_for_put(json_ad, snapshot.as_ref()).await?;
            entries.push((resource, snapshot));
        }
        self.db()
            .persist_replicated_resources(entries)
            .await
            .map_err(to_js_err)
    }

    /// Parse a stored row back into a resource, filling in what the parser
    /// skipped from the snapshot that travels with it.
    async fn resource_for_put(
        &self,
        json_ad: &str,
        snapshot: Option<&Vec<u8>>,
    ) -> Result<Resource, JsError> {
        // `SaveOpts::DontSave` keeps `parse_json_ad_resource` from calling
        // `store.add_resource()` (which validates required props) during
        // parsing. This is admitted replica state, not a new authored import:
        // preserve duplicate identities so they remain available for review.
        let mut resource = atomic_lib::parse::parse_json_ad_resource(
            json_ad,
            self.db(),
            &ParseOpts {
                skip_unknown_props: true,
                save: atomic_lib::parse::SaveOpts::DontSave,
                ..Default::default()
            },
        )
        .await
        .map_err(to_js_err)?;
        // A property this database has no definition for yet (a drive's own
        // schema term not synced here, say) is skipped by the parser, but the
        // tab's snapshot still holds its value. `getResourceWithSnapshot`
        // serves this row, so take those values from the snapshot rather than
        // store a row with less in it than the document.
        if let Some(snapshot) = snapshot {
            let keys: Vec<String> =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(json_ad)
                    .map(|map| {
                        map.into_iter()
                            .map(|(key, _)| key)
                            .filter(|key| key != "@id")
                            .collect()
                    })
                    .unwrap_or_default();
            resource.restore_props_from_snapshot(&keys, snapshot);
        }
        Ok(resource)
    }

    async fn put_resource_inner(
        &self,
        json_ad: &str,
        snapshot: Option<Vec<u8>>,
    ) -> Result<(), JsError> {
        let resource = self.resource_for_put(json_ad, snapshot.as_ref()).await?;
        match snapshot {
            Some(snapshot) => self
                .db()
                .persist_replicated_resource_with_snapshot(&resource, snapshot)
                .await
                .map_err(to_js_err)?,
            None => self
                .db()
                .persist_replicated_resource(&resource)
                .await
                .map_err(to_js_err)?,
        }
        Ok(())
    }

    /// The browser outbox's rows for `agent` (`Tree::Outbox`), each the JSON
    /// text the tab stored. The tab owns the format; see
    /// `atomic_lib::sync::outbox::raw`.
    #[wasm_bindgen(js_name = "outboxEntries")]
    pub fn outbox_entries(&self, agent: &str) -> Result<Vec<String>, JsError> {
        atomic_lib::sync::outbox::raw::entries(self.db(), agent)
            .map_err(to_js_err)?
            .into_iter()
            .map(|bytes| String::from_utf8(bytes).map_err(to_js_err))
            .collect()
    }

    /// Store and remove browser outbox rows for `agent` in one batch.
    /// `puts_json` is `[{ subject, value }]`, `deletes_json` a subject list.
    /// Like every other write this commits without an fsync; the worker
    /// flushes when the caller needs it durable.
    #[wasm_bindgen(js_name = "outboxWrite")]
    pub fn outbox_write(
        &self,
        agent: &str,
        puts_json: &str,
        deletes_json: &str,
    ) -> Result<(), JsError> {
        #[derive(serde::Deserialize)]
        struct Row {
            subject: String,
            value: String,
        }
        let puts: Vec<Row> = serde_json::from_str(puts_json).map_err(to_js_err)?;
        let deletes: Vec<String> = serde_json::from_str(deletes_json).map_err(to_js_err)?;
        let puts: Vec<(String, Vec<u8>)> = puts
            .into_iter()
            .map(|row| (row.subject, row.value.into_bytes()))
            .collect();
        atomic_lib::sync::outbox::raw::write(self.db(), agent, &puts, &deletes).map_err(to_js_err)
    }

    /// Apply a Commit (JSON-AD) to the local database.
    /// This is the efficient incremental update path: the Loro diff
    /// determines exactly which atoms changed, so only affected index
    /// entries are updated. Use this for real-time updates (COMMIT messages).
    ///
    /// The server already validated the commit, so this is
    /// [`IngestPolicy::LocalCache`]: no signature, rights, timestamp or
    /// schema checks — index update only.
    #[wasm_bindgen(js_name = "applyCommit")]
    pub async fn apply_commit(&self, commit_json_ad: &str) -> Result<(), JsError> {
        self.node
            .apply_commit(commit_json_ad, IngestPolicy::LocalCache)
            .await
            .map_err(to_js_err)?;
        Ok(())
    }

    /// Validate a locally signed mutation (including a durable peer deletion).
    #[wasm_bindgen(js_name = "applyPeerCommit")]
    pub async fn apply_peer_commit(&self, json: &str) -> Result<(), JsError> {
        self.node
            .apply_commit(json, IngestPolicy::Peer)
            .await
            .map_err(to_js_err)?;
        self.db().flush().map_err(to_js_err)
    }

    /// Remove a resource by its subject URL.
    #[wasm_bindgen(js_name = "removeResource")]
    pub async fn remove_resource(&self, subject: &str) -> Result<(), JsError> {
        let subject = Subject::from(subject);
        self.db()
            .remove_resource(&subject)
            .await
            .map_err(to_js_err)?;
        Ok(())
    }

    /// Query the local database.
    /// `property` and `value` are optional filters.
    /// Returns a JSON object: `{ subjects: string[], resources: string[], count: number }`.
    #[allow(clippy::too_many_arguments)]
    pub async fn query(
        &self,
        property: Option<String>,
        value: Option<String>,
        sort_by: Option<String>,
        sort_desc: Option<bool>,
        limit: Option<usize>,
        offset: Option<usize>,
        include_resources: Option<bool>,
        drive: Option<String>,
        filters: JsValue,
        aggregation: JsValue,
        expression_filters: JsValue,
    ) -> Result<JsValue, JsError> {
        // Extra `(property, value)` AND constraints from JS. `null`/`undefined`
        // → none, keeping single-filter callers unchanged.
        #[derive(serde::Deserialize)]
        struct FilterParam {
            property: Option<String>,
            value: Option<String>,
            operator: Option<String>,
        }

        let base_domain = self.db().get_base_domain();

        let mut extra: Vec<atomic_lib::storelike::PropVal> =
            if filters.is_null() || filters.is_undefined() {
                Vec::new()
            } else {
                let parsed: Vec<FilterParam> =
                    serde_wasm_bindgen::from_value(filters).map_err(to_js_err)?;
                parsed
                    .into_iter()
                    .map(|f| atomic_lib::storelike::PropVal {
                        property: f.property,
                        value: f.value.map(Value::String),
                        operator: atomic_lib::storelike::filter_operator_from_str(
                            f.operator.as_deref(),
                        ),
                    })
                    .collect()
            };

        // The caller only ever saw localized subjects, but this database is
        // keyed by the raw `internal:` form — exactly the asymmetry the server
        // handles in `collections::collect_members`. Without it a `parent=`
        // filter matches nothing locally.
        for filter in extra.iter_mut() {
            let (Some(property), Some(Value::String(raw))) =
                (filter.property.as_deref(), filter.value.as_ref())
            else {
                continue;
            };
            let raw = raw.clone();
            filter.value = Some(
                atomic_lib::collections::delocalize_filter_value(self.db(), Some(property), &raw)
                    .await,
            );
        }

        let value = match value {
            Some(raw) => Some(
                atomic_lib::collections::delocalize_filter_value(
                    self.db(),
                    property.as_deref(),
                    &raw,
                )
                .await,
            ),
            None => None,
        };

        // Statistics over every matching row. The same computation the server
        // does — this is the same crate — so an offline table shows the same
        // totals rather than none.
        let aggregation: Option<atomic_lib::aggregate::Aggregation> =
            if aggregation.is_null() || aggregation.is_undefined() {
                None
            } else {
                Some(serde_wasm_bindgen::from_value(aggregation).map_err(to_js_err)?)
            };

        // Constraints on values computed per row (a duration, a days-since).
        // These can't be indexed, so the store evaluates them over the matching
        // set — see `atomic_lib::expression`.
        let expression_filters: Vec<atomic_lib::expression::ExpressionFilter> =
            if expression_filters.is_null() || expression_filters.is_undefined() {
                Vec::new()
            } else {
                serde_wasm_bindgen::from_value(expression_filters).map_err(to_js_err)?
            };

        let q = Query {
            property,
            value,
            filters: extra,
            expression_filters,
            aggregation,
            sort_by,
            sort_desc: sort_desc.unwrap_or(false),
            limit,
            offset: offset.unwrap_or(0),
            start_val: None,
            end_val: None,
            include_external: false,
            include_nested: include_resources.unwrap_or(false),
            for_agent: atomic_lib::agents::ForAgent::Sudo,
            // `Subject::from` drops the base domain, leaving a localized drive
            // as an `External` subject that matches no stored drive prefix.
            drive: drive.map(|d| Subject::from_raw(&d, base_domain.as_deref())),
        };

        let result = self.node.query(&q).await.map_err(to_js_err)?;
        let response = QueryResponse::from_result(&result, &self.origin())?;
        serde_wasm_bindgen::to_value(&response).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Local KV full-text search. `parents` is a string, a string array, or null.
    /// `filters` is a `{ property: string | string[] }` object, or null.
    /// Returns an array of subject URLs, ranked.
    pub fn search(
        &self,
        query: String,
        limit: Option<u32>,
        parents: JsValue,
        filters: JsValue,
    ) -> Result<JsValue, JsError> {
        let parents: Option<Vec<String>> = if parents.is_null() || parents.is_undefined() {
            None
        } else if let Some(s) = parents.as_string() {
            Some(vec![s])
        } else {
            serde_wasm_bindgen::from_value(parents).ok()
        };
        let opts = atomic_lib::client::search::SearchOpts {
            limit,
            parents,
            filter_pairs: Some(js_to_filter_pairs(filters)),
            ..Default::default()
        };
        let hits = self.node.search(&query, &opts).map_err(to_js_err)?;
        let subjects: Vec<String> = hits.into_iter().map(|h| h.subject.to_string()).collect();
        serde_wasm_bindgen::to_value(&subjects).map_err(|e| JsError::new(&e.to_string()))
    }

    /// The absolute origin this database's subjects are addressed by in the
    /// browser. `internal:` is a storage detail: everything handed back across
    /// the wasm boundary must be a URL (or a DID) the client can actually
    /// fetch, matching what the server sends over HTTP.
    fn origin(&self) -> String {
        self.db()
            .get_base_domain()
            .unwrap_or_else(|| "http://localhost".to_string())
    }

    /// Who signed this resource's history, from the envelopes this client
    /// kept (`atomic_lib::envelopes::attribute_history`). JSON string with
    /// `attributions[]` (signer, createdAt, signature, verified, tokens,
    /// destroy, genesis), `retention` and `complete`.
    #[wasm_bindgen(js_name = "historyAttribution")]
    pub async fn history_attribution(&self, subject: &str) -> Result<String, JsError> {
        let report = atomic_lib::envelopes::attribute_history(self.db(), subject)
            .await
            .map_err(to_js_err)?;
        serde_json::to_string(&report).map_err(to_js_err)
    }

    /// Apply the resource states of a `SYNC_PUSH` without building them in
    /// JavaScript: each `(subject, state)` pair is merged into the stored
    /// document and persisted with its indexes (`apply_state_update`, the path
    /// replicas use). `subjects` is an array of strings and `states` an array
    /// of `Uint8Array`s of the same length. Returns how many were applied.
    #[wasm_bindgen(js_name = "applyStateUpdates")]
    pub async fn apply_state_updates(
        &self,
        subjects: Vec<String>,
        states: js_sys::Array,
        defer_search: bool,
    ) -> Result<u32, JsError> {
        let items: Vec<(String, Vec<u8>)> = subjects
            .into_iter()
            .enumerate()
            .map(|(i, subject)| {
                (
                    subject,
                    js_sys::Uint8Array::new(&states.get(i as u32)).to_vec(),
                )
            })
            .collect();

        let applied =
            atomic_lib::sync::ws_apply::apply_state_updates(self.db(), &items, defer_search)
                .await
                .map_err(to_js_err)?;

        Ok(applied as u32)
    }

    /// Add full-text search entries for up to `limit` resources that were
    /// stored without them (`applyStateUpdates` with `deferSearch`). Returns how
    /// many were done; call again until it returns 0.
    #[wasm_bindgen(js_name = "indexPendingSearch")]
    pub async fn index_pending_search(&self, limit: u32) -> Result<u32, JsError> {
        let done = atomic_lib::search::index_pending(self.db(), limit as usize)
            .await
            .map_err(to_js_err)?;

        Ok(done as u32)
    }

    /// Whether the atom indexes still have to be rebuilt for the current key
    /// layout (`Db::index_migration_pending`). The worker runs
    /// `migrateIndexKeysStep` until it is done before it serves anything.
    #[wasm_bindgen(js_name = "indexMigrationPending")]
    pub fn index_migration_pending(&self) -> Result<bool, JsError> {
        self.db().index_migration_pending().map_err(to_js_err)
    }

    /// Rebuild the indexes for up to `limit` more resources. Returns
    /// `{ "done": n, "total": n, "finished": bool }` as JSON.
    #[wasm_bindgen(js_name = "migrateIndexKeysStep")]
    pub fn migrate_index_keys_step(&self, limit: u32) -> Result<String, JsError> {
        let step = self
            .db()
            .migrate_index_keys_step(limit as usize)
            .map_err(to_js_err)?;
        serde_json::to_string(&step).map_err(to_js_err)
    }

    /// Whether old chat `Message` resources may still have to be moved into
    /// chat log pages (`Db::message_migration_pending`).
    #[wasm_bindgen(js_name = "messageMigrationPending")]
    pub fn message_migration_pending(&self) -> Result<bool, JsError> {
        self.db().message_migration_pending().map_err(to_js_err)
    }

    /// Move the old messages of whole chats into pages, until about `limit`
    /// messages are done. Returns `{ "done": n, "total": n, "finished": bool }`
    /// as JSON. `local_only_drives_json` is a JSON array of the drives that
    /// exist only in this store: pages are written for those alone. A drive a
    /// server hosts gets its pages from the server; for those this only drops
    /// cached `Message`s whose entry is already in a page it holds.
    #[wasm_bindgen(js_name = "migrateMessagesStep")]
    pub async fn migrate_messages_step(
        &self,
        limit: u32,
        local_only_drives_json: &str,
    ) -> Result<String, JsError> {
        let drives: Vec<String> =
            serde_json::from_str(local_only_drives_json).map_err(to_js_err)?;
        let create_in = atomic_lib::db::chat_migration_drive_set(drives);
        let step = self
            .db()
            .migrate_messages_step(limit as usize, Some(&create_in))
            .await
            .map_err(to_js_err)?;
        serde_json::to_string(&step).map_err(to_js_err)
    }

    /// Whether old `ai-message` resources may still have to be moved into chat
    /// log pages (`Db::ai_chat_migration_pending`).
    #[wasm_bindgen(js_name = "aiChatMigrationPending")]
    pub fn ai_chat_migration_pending(&self) -> Result<bool, JsError> {
        self.db().ai_chat_migration_pending().map_err(to_js_err)
    }

    /// Like `migrateMessagesStep`, for the messages of AI chats
    /// (`Db::migrate_ai_chats_step`).
    #[wasm_bindgen(js_name = "migrateAiChatsStep")]
    pub async fn migrate_ai_chats_step(
        &self,
        limit: u32,
        local_only_drives_json: &str,
    ) -> Result<String, JsError> {
        let drives: Vec<String> =
            serde_json::from_str(local_only_drives_json).map_err(to_js_err)?;
        let create_in = atomic_lib::db::chat_migration_drive_set(drives);
        let step = self
            .db()
            .migrate_ai_chats_step(limit as usize, Some(&create_in))
            .await
            .map_err(to_js_err)?;
        serde_json::to_string(&step).map_err(to_js_err)
    }

    /// The retained signed envelopes of each subject, as
    /// `{ "<subject>": ["<commit JSON-AD>", ...] }`, to ride along a
    /// `SYNC_PUSH` (`atomic_lib::envelopes::for_subjects`). `subjects_json`
    /// is a JSON array of subjects.
    #[wasm_bindgen(js_name = "envelopesFor")]
    pub fn envelopes_for(&self, subjects_json: &str) -> Result<String, JsError> {
        let subjects: Vec<String> = serde_json::from_str(subjects_json).map_err(to_js_err)?;
        let map =
            atomic_lib::envelopes::for_subjects(self.db(), subjects.iter().map(String::as_str));
        serde_json::to_string(&map).map_err(to_js_err)
    }

    /// Keep envelopes that arrived with a `SYNC_PUSH`: a JSON array of
    /// `{ subject, json }`. Each is verified before it is stored
    /// (`atomic_lib::envelopes::import_envelope`); returns how many were kept.
    #[wasm_bindgen(js_name = "importEnvelopes")]
    pub async fn import_envelopes(&self, envelopes_json: &str) -> Result<u32, JsError> {
        let items: Vec<serde_json::Value> =
            serde_json::from_str(envelopes_json).map_err(to_js_err)?;
        let mut kept = 0u32;
        for item in items {
            let (Some(subject), Some(json)) = (
                item.get("subject").and_then(|v| v.as_str()),
                item.get("json").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            if atomic_lib::envelopes::import_envelope(self.db(), subject, json)
                .await
                .is_ok()
            {
                kept += 1;
            }
        }
        Ok(kept)
    }

    /// The stored Loro snapshot of a resource. Returns null if not found.
    #[wasm_bindgen(js_name = "getLoroSnapshot")]
    pub fn get_loro_snapshot(&self, subject: &str) -> Result<JsValue, JsError> {
        Self::state_snapshot_js(self.db(), subject)
    }

    fn state_snapshot_js(db: &atomic_lib::Db, subject: &str) -> Result<JsValue, JsError> {
        let subject = Subject::from_raw(subject, db.get_base_domain().as_deref());
        Ok(match db.get_loro_snapshot(&subject) {
            Some(data) => js_sys::Uint8Array::from(data.as_slice()).into(),
            None => JsValue::NULL,
        })
    }

    /// Store a binary blob keyed by its BLAKE3 hash.
    #[wasm_bindgen(js_name = "putBlob")]
    pub fn put_blob(&self, hash: &[u8], data: &[u8]) -> Result<(), JsError> {
        use atomic_lib::db::trees::Tree;
        if hash.len() != 32 {
            return Err(to_js_err("Hash must be 32 bytes"));
        }
        self.db()
            .kv
            .insert(Tree::Blobs, hash, data)
            .map_err(to_js_err)
    }

    /// Retrieve a binary blob by its BLAKE3 hash. Returns null if not found.
    #[wasm_bindgen(js_name = "getBlob")]
    pub fn get_blob(&self, hash: &[u8]) -> Result<JsValue, JsError> {
        use atomic_lib::db::trees::Tree;
        if hash.len() != 32 {
            return Err(to_js_err("Hash must be 32 bytes"));
        }
        match self.db().kv.get(Tree::Blobs, hash) {
            Ok(Some(data)) => Ok(js_sys::Uint8Array::from(data.as_slice()).into()),
            Ok(None) => Ok(JsValue::NULL),
            Err(e) => Err(to_js_err(e)),
        }
    }

    /// Compute a BLAKE3 hash of the given data.
    #[wasm_bindgen(js_name = "blake3Hash")]
    pub fn blake3_hash(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    /// Get version vectors for all Loro snapshots in the database.
    /// Returns a JSON object: `{ [subject]: { [peer_id]: counter } }`
    #[wasm_bindgen(js_name = "getAllVersionVectors")]
    pub fn get_all_version_vectors(&self) -> Result<JsValue, JsError> {
        use atomic_lib::db::trees::Tree;
        use atomic_lib::loro::AtomicLoroDoc;
        use std::collections::HashMap;

        let mut result: HashMap<String, HashMap<String, i32>> = HashMap::new();

        for item in self.db().kv.iter_tree(Tree::LoroSnapshots) {
            let (key_bytes, snapshot_bytes) = item.map_err(to_js_err)?;
            let subject = String::from_utf8(key_bytes).map_err(|e| JsError::new(&e.to_string()))?;

            // Fast path: read the version vector straight from the snapshot
            // header instead of rebuilding the whole CRDT doc (`from_snapshot`).
            // For a large drive this turns ~N full imports at sync time into ~N
            // cheap header decodes.
            match AtomicLoroDoc::vv_map_from_snapshot(&snapshot_bytes) {
                Ok(vv) => {
                    result.insert(subject, vv);
                }
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[ClientDb] Failed to read VV for {}: {e}", subject).into(),
                    );
                }
            }
        }

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Version vectors for just ONE drive's resources, instead of every
    /// resource in every drive (`getAllVersionVectors`). Uses the same
    /// parent-index walk (`collect_drive_subjects`) the server uses, so the
    /// cost is O(this drive) rather than O(entire local DB) — and the VV set
    /// sent to the server no longer includes foreign-drive subjects it would
    /// otherwise treat as pull/remove candidates.
    #[wasm_bindgen(js_name = "getVersionVectorsForDrive")]
    pub async fn get_version_vectors_for_drive(&self, drive: String) -> Result<JsValue, JsError> {
        let subjects = self.drive_subject_list(&drive).await;

        self.version_vectors_of(subjects)
    }

    /// The subjects of one drive (the parent-index walk of
    /// `getVersionVectorsForDrive`, without reading any snapshot). Together
    /// with `getVersionVectorsForSubjects` this lets a caller read a big
    /// drive's version vectors in slices, so reads queued behind the work can
    /// run between the slices instead of waiting for all of it.
    #[wasm_bindgen(js_name = "getDriveSubjects")]
    pub async fn get_drive_subjects(&self, drive: String) -> Result<JsValue, JsError> {
        let subjects = self.drive_subject_list(&drive).await;

        serde_wasm_bindgen::to_value(&subjects).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Version vectors of exactly these subjects (`pure_id()` strings, as
    /// returned by `getDriveSubjects`). Subjects without a snapshot are skipped.
    #[wasm_bindgen(js_name = "getVersionVectorsForSubjects")]
    pub fn get_version_vectors_for_subjects(&self, subjects: JsValue) -> Result<JsValue, JsError> {
        let subjects: Vec<String> =
            serde_wasm_bindgen::from_value(subjects).map_err(|e| JsError::new(&e.to_string()))?;

        self.version_vectors_of(subjects)
    }

    /// Get all subjects in the database.
    #[wasm_bindgen(js_name = "allSubjects")]
    pub fn all_subjects(&self) -> Result<JsValue, JsError> {
        let subjects: Vec<String> = self
            .db()
            .all_resources(true)
            .map(|r| r.get_subject().to_string())
            .collect();
        serde_wasm_bindgen::to_value(&subjects).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Populate the database with default Atomic Data vocabulary
    /// (classes, properties, datatypes).
    pub async fn populate(&self) -> Result<(), JsError> {
        self.db().populate().await.map_err(to_js_err)
    }

    /// Export all resources as a JSON array of JSON-AD objects.
    /// Used to snapshot the DB to IndexedDB for persistence across page reloads.
    #[wasm_bindgen(js_name = "exportAllResources")]
    pub fn export_all_resources(&self) -> Result<String, JsError> {
        let mut resources = Vec::new();

        for resource in self.db().all_resources(true) {
            if let Ok(json_ad) = resource.to_json_ad(None) {
                resources.push(json_ad);
            }
        }

        Ok(format!("[{}]", resources.join(",")))
    }

    /// Import resources from a JSON array of JSON-AD objects.
    /// Used to restore a snapshot from IndexedDB on init.
    /// Skips indexing during import and builds the index once at the end.
    #[wasm_bindgen(js_name = "importAllResources")]
    pub async fn import_all_resources(&self, json_array: &str) -> Result<u32, JsError> {
        let items: Vec<serde_json::Value> = serde_json::from_str(json_array).map_err(to_js_err)?;

        let mut count: u32 = 0;

        for item in &items {
            let json_str = item.to_string();

            if let Ok(resource) = atomic_lib::parse::parse_json_ad_resource(
                &json_str,
                self.db(),
                &ParseOpts {
                    skip_unknown_props: true,
                    save: atomic_lib::parse::SaveOpts::DontSave,
                    ..Default::default()
                },
            )
            .await
            {
                // Preserve admitted replicas, including independent import identities.
                // The final rebuild still reconciles parent-dependent indexes.
                if self
                    .db()
                    .persist_replicated_resource(&resource)
                    .await
                    .is_ok()
                {
                    count += 1;
                }
            }
        }

        // Build the full index once
        self.db().build_index(true).map_err(to_js_err)?;

        Ok(count)
    }
}

#[derive(serde::Serialize)]
struct QueryResponse {
    subjects: Vec<String>,
    resources: Vec<String>,
    count: usize,
    /// One per requested aggregate; empty when none were asked for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aggregates: Vec<atomic_lib::aggregate::AggregateOutcome>,
}

impl QueryResponse {
    /// `origin` localizes every subject on the way out, the same way
    /// [atomic_lib::serialize] does for the server's HTTP responses.
    ///
    /// Without it `Subject::Internal` stringifies to its raw storage form and
    /// the client receives `internal:/01k4sg…` as a member subject. The
    /// browser cannot fetch that — there is no host to send a request to — so
    /// the resource never resolves and the row renders with no name.
    fn from_result(result: &QueryResult, origin: &str) -> Result<Self, JsError> {
        let subjects: Vec<String> = result.subjects.iter().map(|s| s.resolve(origin)).collect();

        let resources: Vec<String> = result
            .resources
            .iter()
            .map(|r| resource_to_json_ad(r, origin))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(QueryResponse {
            subjects,
            resources,
            count: result.count,
            aggregates: result.aggregates.clone(),
        })
    }
}

fn resource_to_json_ad(resource: &Resource, origin: &str) -> Result<String, JsError> {
    resource.to_json_ad(Some(origin)).map_err(to_js_err)
}

fn to_js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn js_to_filter_pairs(filters: JsValue) -> Vec<(String, String)> {
    if filters.is_null() || filters.is_undefined() {
        return Vec::new();
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum FilterVal {
        S(String),
        N(serde_json::Number),
        B(bool),
        A(Vec<String>),
    }
    let Ok(map) =
        serde_wasm_bindgen::from_value::<std::collections::HashMap<String, FilterVal>>(filters)
    else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (key, val) in map {
        match val {
            FilterVal::S(s) if !s.is_empty() => pairs.push((key, s)),
            FilterVal::N(n) => pairs.push((key, n.to_string())),
            FilterVal::B(b) => pairs.push((key, b.to_string())),
            FilterVal::A(vals) => {
                for s in vals {
                    if !s.is_empty() {
                        pairs.push((key.clone(), s));
                    }
                }
            }
            FilterVal::S(_) => {}
        }
    }
    pairs
}

const LEGACY_DB_NAME: &str = "atomic_data.redb";

/// OPFS filenames come from our own JS, but reject anything that isn't a
/// plain filename anyway — getFileHandle would take names like `..` verbatim.
fn validate_db_name(db_name: Option<String>) -> Result<String, JsError> {
    let name = db_name.unwrap_or_else(|| LEGACY_DB_NAME.to_string());
    let valid = !name.is_empty()
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(to_js_err(format!("invalid database name: {name}")));
    }
    Ok(name)
}

fn validate_db_key(db_key: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, JsError> {
    db_key
        .map(|key| {
            key.as_slice()
                .try_into()
                .map_err(|_| to_js_err(format!("database key must be 32 bytes, got {}", key.len())))
        })
        .transpose()
}

/// Derive a 32-byte key-encryption-key (KEK) via Argon2id, for wrapping the
/// recovery-blob DEK with a generated recovery code (or a discouraged
/// password wrapper). This is the one primitive missing from WebCrypto —
/// AES-GCM itself is used directly via `SubtleCrypto` in the browser and
/// needs no Rust/WASM support. Never called server-side: the recovery code
/// and the derived key never leave the browser. See
/// `atomic-saas/planning/BACKUP_SECURITY.md`.
#[wasm_bindgen(js_name = "argon2idDeriveKey")]
pub fn argon2id_derive_key_js(
    secret: &str,
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, JsError> {
    let params = Argon2Params {
        mem_kib,
        iterations,
        parallelism,
    };
    let key = argon2id_derive_key(secret.as_bytes(), salt, params).map_err(to_js_err)?;
    Ok(key.to_vec())
}

/// Delete one OPFS database file. Returns whether a file was actually removed.
///
/// Only ever called for the *current* identity's file, after that file failed
/// to open with `WRONG_KEY_MARKER` and only when the JS caller opted in via
/// `discardUndecryptable`. Being unreadable today is not on its own a reason to
/// delete: the key may be recoverable, and a local-only drive has no copy
/// anywhere else. `browser/lib/src/client-db-open.ts` holds that judgement.
/// Other agents' files are untouched: the caller passes the name it was about
/// to open, and `validate_db_name` keeps that a plain filename in the OPFS root.
#[wasm_bindgen(js_name = "deleteClientDb")]
pub async fn delete_client_db(db_name: String) -> Result<bool, JsError> {
    let name = validate_db_name(Some(db_name))?;
    let exists = atomic_lib::db::opfs_backend::file_exists(&name)
        .await
        .map_err(|e| to_js_err(format!("checking {name}: {e:?}")))?;
    if !exists {
        return Ok(false);
    }
    atomic_lib::db::opfs_backend::remove_file(&name)
        .await
        .map_err(|e| to_js_err(format!("deleting {name}: {e:?}")))?;
    web_sys::console::warn_1(&format!("[ClientDb] deleted undecryptable database {name}").into());
    Ok(true)
}

/// One-time migration of the pre-split `atomic_data.redb` into the per-agent
/// database `target`, encrypting when `key` is given. Returns whether a legacy
/// file was migrated; no-ops (false) when there is no legacy file or `target`
/// already exists. Call before constructing the ClientDb for `target`.
#[wasm_bindgen(js_name = "migrateLegacyClientDb")]
pub async fn migrate_legacy_client_db(
    target: String,
    key: Option<Vec<u8>>,
) -> Result<bool, JsError> {
    let target = validate_db_name(Some(target))?;
    if target == LEGACY_DB_NAME {
        return Ok(false);
    }
    let key = validate_db_key(key)?;
    atomic_lib::db::opfs_backend::migrate_legacy_db(LEGACY_DB_NAME, &target, key.as_ref())
        .await
        .map_err(to_js_err)
}

// ── Cloud Vault ─────────────────────────────────────────────────────────────
//
// The split of work here is deliberate: **Rust does crypto and format, JS does
// the network.**
//
// A vault client has to talk to the control plane for presigned URLs and then
// to object storage for the bytes. All of that — session cookies, fetch,
// retries, CORS — already exists in TypeScript and works. Reimplementing it
// behind WASM would mean an async object-store trait, an HTTP client compiled
// to wasm32, and credential plumbing across the boundary, to arrive at what the
// browser already does well.
//
// So these functions take and return *bytes*. `vaultExport` seals a drive into
// an object and hands it over; JS uploads it wherever the control plane said.
// `vaultImport` takes objects JS has downloaded and merges them into the store.
// The encrypted payload never leaves Rust unencrypted, which is the only
// property that actually matters for a blind vault.

use serde::{Deserialize, Serialize};

/// One sealed object, ready for JS to upload.
///
/// `sealed` is deliberately NOT a field here. `serde_wasm_bindgen` renders a
/// `Vec<u8>` as a JS *array of numbers*, not a `Uint8Array` — and `fetch` has
/// no binary meaning for an array, so it stringifies it. Every object uploaded
/// that way lands in the bucket as the ASCII text `"1,1,0,0,..."`, which reads
/// as a successful backup and can never be restored (the first byte decodes as
/// 49, the character '1', instead of the envelope version).
///
/// So the bytes are attached separately, as a real `Uint8Array`. See
/// `attach_sealed` below.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultExportResult {
    /// Where the control plane expects this object. JS should still use the key
    /// the server returns from `upload-urls`; this one is computed from the
    /// same rules and exists so a mismatch is visible rather than silent.
    object_key: String,
    /// `"pack"` or `"checkpoint"`. Decides which object JS asks the control
    /// plane for an upload URL for, and whether it must publish the checkpoint
    /// afterwards.
    kind: &'static str,
    resources: usize,
    /// Resources skipped because their version vector still matched this lane's
    /// cursor — the measure of what the incremental pass saved.
    unchanged: usize,
    tombstones: usize,
    /// Checkpoints only: lanes this object provably subsumes. JS publishes this
    /// verbatim; the control plane prunes against it.
    coverage: std::collections::BTreeMap<String, u32>,
}

/// Add `sealed` to a serialised {@link VaultExportResult} as a `Uint8Array`.
fn attach_sealed(value: JsValue, sealed: &[u8]) -> Result<JsValue, JsError> {
    js_sys::Reflect::set(
        &value,
        &JsValue::from_str("sealed"),
        &js_sys::Uint8Array::from(sealed).into(),
    )
    .map_err(|_| JsError::new("could not attach sealed bytes to the export result"))?;

    Ok(value)
}

/// An object JS downloaded, on its way back into the store.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultObjectInput {
    object_key: String,
    sealed: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultImportResult {
    packs_read: usize,
    resources_restored: usize,
    tombstones_applied: usize,
    /// Objects the newest checkpoint already subsumed, so they were not read.
    objects_skipped: usize,
    /// Objects that would not open. Non-zero means part of the vault is corrupt
    /// or foreign; the rest still restored, and the UI must say so rather than
    /// report a clean restore.
    objects_unreadable: usize,
}

/// The message an agent signs to derive its vault key-encryption key.
///
/// Callers sign these exact bytes and pass the signature to `vaultWrapKey` /
/// `vaultUnwrapKey`. Fixed and versioned: changing it would orphan every
/// envelope already stored.
#[wasm_bindgen(js_name = "vaultProofMessage")]
pub fn vault_proof_message() -> Vec<u8> {
    atomic_lib::vault::secret_envelope::AGENT_VAULT_PROOF_MESSAGE.to_vec()
}

/// Wrap a drive vault key so it survives this device.
///
/// This is what makes "clear site data, sign in again, restore" work. The key
/// is sealed under the account's agent secret — the credential the user already
/// has — so enabling backup adds nothing for them to remember. Whatever
/// restores their identity restores their drive keys.
///
/// The returned JSON is opaque and safe for the control plane to store: it
/// holds the key only in ciphertext, and the server never sees an agent secret.
///
/// Wrapping, not deriving. A derived key would weld data encryption to identity
/// forever — no re-keying a drive without a new identity, no sharing one
/// without sharing the agent secret. Wrapping keeps the drive key independent
/// and costs the user nothing.
#[wasm_bindgen(js_name = "vaultWrapKey")]
pub fn vault_wrap_key(drive_key: &[u8], agent_secret: &[u8]) -> Result<String, JsError> {
    if drive_key.len() != 32 {
        return Err(JsError::new("drive vault key must be exactly 32 bytes"));
    }

    check_agent_proof(agent_secret)?;

    SecretEnvelope::create(drive_key, &[NewWrapper::AgentSecret { agent_secret }])
        .map_err(to_js_err)?
        .to_json()
        .map_err(to_js_err)
}

/// Recover a drive vault key from its wrapped form.
///
/// Fails rather than returning nonsense when the agent secret is wrong: a
/// restore that proceeded with a bad key would produce a drive full of
/// undecryptable objects, which is far harder to diagnose than a refusal here.
#[wasm_bindgen(js_name = "vaultUnwrapKey")]
pub fn vault_unwrap_key(envelope_json: &str, agent_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    check_agent_proof(agent_secret)?;

    let secret = SecretEnvelope::from_json(envelope_json)
        .map_err(to_js_err)?
        .unwrap_secret(&Unlock::AgentSecret(agent_secret))
        .map_err(to_js_err)?;

    // An envelope that opened but does not hold a drive key means the wrong
    // envelope was fetched. Refusing here names the problem; letting it through
    // surfaces later as objects that will not decrypt, which reads like data
    // corruption.
    if secret.len() != 32 {
        return Err(JsError::new(
            "this envelope does not contain a drive vault key",
        ));
    }

    Ok(secret)
}

/// A fresh random drive vault key, as raw bytes.
///
/// Generated in Rust so the browser's key material comes from the same CSPRNG
/// as everything else in the format, rather than depending on which JS crypto
/// the caller reaches for.
#[wasm_bindgen(js_name = "vaultGenerateKey")]
pub fn vault_generate_key() -> Vec<u8> {
    DriveVaultKey::generate(1).expose_secret().to_vec()
}

/// The agent's public encryption key, base64url, derived from its vault proof.
///
/// Published on the Agent resource as `encryptionKey`, so others can start an
/// encrypted conversation with it. See `atomic_lib::conversation`.
#[wasm_bindgen(js_name = "conversationEncryptionKey")]
pub fn conversation_encryption_key(vault_proof: &[u8]) -> Result<String, JsError> {
    check_agent_proof(vault_proof)?;
    Ok(atomic_lib::conversation::encryption_public_key(vault_proof))
}

/// Adds an epoch with a fresh key to a conversation keyring, wrapped to
/// `members_json` (`[{agent, encryptionKey}]`). Pass an empty string to start
/// a new keyring. Returns the updated keyring JSON.
#[wasm_bindgen(js_name = "conversationAddEpoch")]
pub fn conversation_add_epoch(keyring_json: &str, members_json: &str) -> Result<String, JsError> {
    use atomic_lib::conversation::{Keyring, Member};
    let mut keyring = if keyring_json.is_empty() {
        Keyring::default()
    } else {
        Keyring::from_json(keyring_json).map_err(to_js_err)?
    };
    let members: Vec<Member> = serde_json::from_str(members_json)
        .map_err(|e| JsError::new(&format!("invalid members: {e}")))?;
    keyring.add_epoch(&members).map_err(to_js_err)?;
    keyring.to_json().map_err(to_js_err)
}

/// Seals a message payload for `conversation` with the keyring's newest epoch.
#[wasm_bindgen(js_name = "conversationSeal")]
pub fn conversation_seal(
    keyring_json: &str,
    agent: &str,
    vault_proof: &[u8],
    conversation: &str,
    plaintext: &str,
) -> Result<String, JsError> {
    use atomic_lib::conversation::{seal_message, Keyring};
    check_agent_proof(vault_proof)?;
    let key = Keyring::from_json(keyring_json)
        .map_err(to_js_err)?
        .open_current(agent, vault_proof)
        .map_err(to_js_err)?;
    seal_message(&key, conversation, plaintext.as_bytes()).map_err(to_js_err)
}

/// Opens sealed messages of one conversation. Returns one entry per input, in
/// order: the plaintext, or `null` when that message cannot be opened (an
/// epoch before the reader joined, or altered data). One keyring unwrap for a
/// whole page of messages.
#[wasm_bindgen(js_name = "conversationOpen")]
pub fn conversation_open(
    keyring_json: &str,
    agent: &str,
    vault_proof: &[u8],
    conversation: &str,
    sealed: Vec<String>,
) -> Result<Vec<JsValue>, JsError> {
    use atomic_lib::conversation::{open_message, Keyring};
    check_agent_proof(vault_proof)?;
    let keys = Keyring::from_json(keyring_json)
        .map_err(to_js_err)?
        .open(agent, vault_proof)
        .map_err(to_js_err)?;
    Ok(sealed
        .iter()
        .map(|s| {
            open_message(&keys, conversation, s)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map_or(JsValue::NULL, |text| JsValue::from_str(&text))
        })
        .collect())
}

/// Encrypts an attachment for `conversation` under a fresh random key.
/// Returns `{ key, ciphertext }`: the base64url file key (to put inside the
/// sealed message that references the file) and the bytes to upload.
#[wasm_bindgen(js_name = "conversationSealFile")]
pub fn conversation_seal_file(conversation: &str, plaintext: &[u8]) -> Result<JsValue, JsError> {
    let (key, ciphertext) =
        atomic_lib::conversation::seal_file(conversation, plaintext).map_err(to_js_err)?;
    let sealed = js_sys::Object::new();
    js_sys::Reflect::set(&sealed, &"key".into(), &JsValue::from_str(&key))
        .map_err(|_| JsError::new("could not build the sealed file"))?;
    js_sys::Reflect::set(
        &sealed,
        &"ciphertext".into(),
        &js_sys::Uint8Array::from(ciphertext.as_slice()).into(),
    )
    .map_err(|_| JsError::new("could not build the sealed file"))?;
    Ok(sealed.into())
}

/// Decrypts what `conversationSealFile` produced. Throws when the key is wrong,
/// the bytes were altered, or the file belongs to another conversation.
#[wasm_bindgen(js_name = "conversationOpenFile")]
pub fn conversation_open_file(
    conversation: &str,
    key: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsError> {
    atomic_lib::conversation::open_file(conversation, key, ciphertext).map_err(to_js_err)
}

/// The proof must be a 64-byte Ed25519 signature.
///
/// Not the private key: the browser's `CryptoProvider` exposes signing rather
/// than key bytes, deliberately, so that hardware-backed and non-extractable
/// keys remain possible. Requiring the key would have closed that door
/// permanently.
///
/// Enforcing the length also removes an ambiguity that already caused a bug:
/// the "agent secret" has several representations in this codebase, and
/// wrapping under one while unwrapping with another produced an envelope
/// nothing could open. A signature has exactly one representation.
fn check_agent_proof(proof: &[u8]) -> Result<(), JsError> {
    if proof.len() != 64 {
        return Err(JsError::new(
            "agent proof must be the 64-byte signature over the vault derivation message",
        ));
    }

    Ok(())
}

fn drive_key(key_bytes: &[u8], epoch: u32) -> Result<DriveVaultKey, JsError> {
    let bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("drive vault key must be exactly 32 bytes"))?;
    Ok(DriveVaultKey::from_bytes(bytes, epoch))
}

#[wasm_bindgen]
impl ClientDb {
    /// Seal one pass of this drive's history into one vault object.
    ///
    /// Usually a **delta pack** carrying only what changed since this lane's
    /// cursor. Periodically a **checkpoint**: every resource's whole oplog,
    /// self-sufficient, and the thing that lets the control plane delete the
    /// chain before it. The caller does not choose — the cadence lives in Rust
    /// so every host decides identically — but it must read `kind` to know
    /// which object it is uploading.
    ///
    /// Returns `null` when the drive has nothing to back up, which since the
    /// cursors landed is the *normal* outcome for an idle device rather than a
    /// rare one.
    ///
    /// `observed_lanes` is the control plane's `{device: newest segment}` map
    /// from `GET /state`. A checkpoint records it so a restore can tell which
    /// segments predate the anchor; pass an empty object when it is unavailable
    /// and the anchor simply orders every segment after itself.
    ///
    /// `current_state_only` makes a checkpoint carry each resource as a shallow
    /// snapshot (current values, no edit history) and no signed envelopes.
    /// It only matters when this pass is a checkpoint. Omit for the default.
    ///
    /// The returned bytes are already encrypted: the control plane and the
    /// bucket only ever see ciphertext.
    #[wasm_bindgen(js_name = "vaultExport")]
    #[allow(clippy::too_many_arguments)]
    pub async fn vault_export(
        &self,
        drive_subject: &str,
        key_bytes: &[u8],
        key_epoch: u32,
        drive_pseudonym: &str,
        device_pubkey: &str,
        segment: u32,
        checkpoint_n: u64,
        drive_has_checkpoint: bool,
        observed_lanes: JsValue,
        current_state_only: Option<bool>,
    ) -> Result<JsValue, JsError> {
        let key = drive_key(key_bytes, key_epoch)?;
        let subject = Subject::from_raw(drive_subject, self.db().get_base_domain().as_deref());
        let staging = MemoryVaultStore::new();

        let observed: std::collections::BTreeMap<String, u32> =
            if observed_lanes.is_undefined() || observed_lanes.is_null() {
                Default::default()
            } else {
                serde_wasm_bindgen::from_value(observed_lanes).map_err(to_js_err)?
            };

        let summary = export_vault_segment(
            self.db(),
            &subject,
            &key,
            &staging,
            drive_pseudonym,
            device_pubkey,
            segment,
            checkpoint_n,
            drive_has_checkpoint,
            &observed,
            CheckpointPolicy {
                history: if current_state_only.unwrap_or(false) {
                    HistoryKeep::CurrentStateOnly
                } else {
                    HistoryKeep::Full
                },
                ..CheckpointPolicy::default()
            },
        )
        .await
        .map_err(to_js_err)?;

        let Some(summary) = summary else {
            return Ok(JsValue::NULL);
        };

        let sealed = staging.get(&summary.object_key).map_err(to_js_err)?;
        let result = serde_wasm_bindgen::to_value(&VaultExportResult {
            object_key: summary.object_key,
            kind: match summary.kind {
                SegmentKind::Pack => "pack",
                SegmentKind::Checkpoint => "checkpoint",
            },
            resources: summary.resources,
            unchanged: summary.unchanged,
            tombstones: summary.tombstones,
            coverage: summary.coverage,
        })
        .map_err(to_js_err)?;

        attach_sealed(result, &sealed)
    }

    /// Record that a sealed segment is durably in the vault.
    ///
    /// Sealing and storing are separate steps here: `vaultExport` produces
    /// bytes and JS uploads them afterwards. Until this is called the lane's
    /// progress is provisional, so an upload that failed is retried against the
    /// same view of what has been backed up rather than one that assumed
    /// success. Call it after the control plane confirms the object.
    #[wasm_bindgen(js_name = "vaultCommitSegment")]
    pub fn vault_commit_segment(
        &self,
        drive_pseudonym: &str,
        device_pubkey: &str,
        segment: u32,
    ) -> Result<(), JsError> {
        commit_lane_state(self.db(), drive_pseudonym, device_pubkey, segment).map_err(to_js_err)
    }

    /// Merge downloaded vault objects into this store.
    ///
    /// Safe against a populated store as well as an empty one: Loro merges
    /// rather than overwrites, so restoring onto a device that already has
    /// some of the drive converges instead of clobbering local edits.
    ///
    /// Objects are applied in the order given, so JS must pass them sorted by
    /// key — a later segment's deletion has to win over an earlier segment's
    /// copy of the same resource.
    ///
    /// Spans every device lane, not just this device's. Each device appends
    /// only to its own lane, so restoring one lane would silently drop every
    /// other device's history while reporting success.
    #[wasm_bindgen(js_name = "vaultImport")]
    pub async fn vault_import(
        &self,
        key_bytes: &[u8],
        key_epoch: u32,
        drive_pseudonym: &str,
        device_pubkey: &str,
        objects: JsValue,
    ) -> Result<JsValue, JsError> {
        let key = drive_key(key_bytes, key_epoch)?;
        let objects: Vec<VaultObjectInput> =
            serde_wasm_bindgen::from_value(objects).map_err(to_js_err)?;

        let staging = MemoryVaultStore::new();
        for object in &objects {
            staging
                .put(&object.object_key, &object.sealed)
                .map_err(to_js_err)?;
        }

        let summary = import_vault_batch(
            self.db(),
            &key,
            &staging,
            &drive_prefix(drive_pseudonym),
            Some((drive_pseudonym, device_pubkey)),
        )
        .await
        .map_err(to_js_err)?;

        serde_wasm_bindgen::to_value(&VaultImportResult {
            packs_read: summary.packs_read,
            resources_restored: summary.resources_restored,
            tombstones_applied: summary.tombstones_applied,
            objects_skipped: summary.objects_skipped,
            objects_unreadable: summary.objects_unreadable,
        })
        .map_err(to_js_err)
    }
}
