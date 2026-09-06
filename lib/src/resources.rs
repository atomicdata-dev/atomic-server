//! A [Resource] is a set of [Atom]s that share a URL.
//! Has methods for saving resources and getting properties inside them.

use crate::commit::{CommitOpts, CommitResponse};
use crate::storelike::Query;
use crate::urls;
use crate::utils::random_string;
use crate::values::{SubResource, Value};
use crate::{commit::CommitBuilder, errors::AtomicResult};
use crate::{
    mapping::is_url,
    schema::{Class, Property},
    Atom, Storelike, Subject,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::instrument;
use ulid::Ulid;

/// A Resource is a set of Atoms that shares a single Subject.
/// Backed by a Loro CRDT document for conflict-free state management.
/// PropVals is a materialized read cache; mutations go through the Loro doc.
#[derive(Serialize, Deserialize, Debug)]
pub struct Resource {
    /// Materialized property-value pairs (read cache)
    propvals: PropVals,
    subject: Subject,
    /// Legacy commit builder — still used by server-side code that calls set_unsafe().
    /// Will be removed once all server code uses Loro.
    commit: CommitBuilder,
    /// The Loro CRDT document backing this resource. Lazily initialized.
    #[serde(skip)]
    loro: Option<crate::loro::AtomicLoroDoc>,
}

/// Maps Property URLs to their values
pub type PropVals = HashMap<String, Value>;

impl Clone for Resource {
    fn clone(&self) -> Self {
        let loro = self.loro.as_ref().map(|doc| {
            let snapshot = doc.export_snapshot();
            crate::loro::AtomicLoroDoc::from_snapshot(&snapshot).expect("Failed to clone Loro doc")
        });
        Resource {
            propvals: self.propvals.clone(),
            subject: self.subject.clone(),
            commit: self.commit.clone(),
            loro,
        }
    }
}

impl Resource {
    fn clone_loro_state(doc: &crate::loro::AtomicLoroDoc) -> crate::loro::AtomicLoroDoc {
        let snapshot = doc.export_snapshot();
        crate::loro::AtomicLoroDoc::from_snapshot(&snapshot).expect("Failed to clone Loro doc")
    }

    fn adopt_resource_state(&mut self, new: &Resource) -> AtomicResult<()> {
        self.subject = new.subject.clone();
        self.propvals = new.propvals.clone();
        // Bring the in-memory doc onto the SAME causal lineage as the
        // server's post-commit doc. The server's apply path writes its own
        // ops (e.g. `lastCommit`) under a fresh peer id; if we kept our
        // pre-commit branch, the next edit would be causally *concurrent*
        // with the server's state and every later commit would re-merge two
        // divergent branches as LWW — silently dropping writes at random
        // (peer-id tiebreak).
        //
        // Import the server's doc rather than replacing the instance: the
        // shared client ops already match (same op identities), so only the
        // server's extra ops are merged in, the doc converges to the
        // server's state, and the live `UndoManager` survives — a snapshot
        // clone would discard it.
        match (&self.loro, &new.loro) {
            (Some(doc), Some(new_doc)) => {
                doc.import_update(&new_doc.export_snapshot())?;
            }
            (None, Some(new_doc)) => {
                self.loro = Some(Self::clone_loro_state(new_doc));
            }
            _ => {}
        }
        Ok(())
    }

    /// Builds a versioned state doc from propvals. Skips the persisted `loroUpdate`
    /// snapshot; other entries become property ops on a fresh doc.
    pub fn seed_state_doc_from_propvals(
        doc: &crate::loro::AtomicLoroDoc,
        propvals: &PropVals,
    ) -> AtomicResult<()> {
        for (prop, val) in propvals {
            if prop == urls::LORO_UPDATE {
                continue;
            }

            doc.set_property(prop, val)?;
        }

        Ok(())
    }

    fn materialize_propvals_from_loro_doc(doc: &crate::loro::AtomicLoroDoc) -> PropVals {
        let mut propvals = PropVals::new();
        let datatypes = doc.get_all_datatypes();

        for (prop, loro_val) in doc.get_all_properties() {
            let tag = datatypes.get(&prop).map(String::as_str);
            if let Some(atomic_val) = crate::loro::loro_value_to_atomic_value_tagged(&loro_val, tag)
            {
                propvals.insert(prop, atomic_val);
            }
        }

        Self::materialize_genesis_metadata(doc, &mut propvals);
        propvals
    }

    /// Extract the inline `genesis` certificate (base64) from a Loro snapshot,
    /// if the resource carries one. Used by genesis-commit validation to verify
    /// the DID against the self-verifying certificate. Returns `None` for legacy
    /// resources minted before the certificate (DID == commit signature).
    pub fn genesis_cert_b64_from_loro_update(update: &[u8]) -> Option<String> {
        let doc = crate::loro::AtomicLoroDoc::new();
        doc.import_update(update).ok()?;
        let propvals = Self::materialize_propvals_from_loro_doc(&doc);
        propvals.get(urls::GENESIS).map(|v| v.to_string())
    }

    /// The resource's creator, proven by its inline self-verifying genesis
    /// certificate — the forge-resistant authority root (see
    /// `planning/authorization-sync.md` "Node-as-granted-replica" and
    /// `planning/genesis-self-verifying.md`).
    ///
    /// This is NOT the `createdBy` propval, which is client-settable and not
    /// forge-resistant (`commit.rs`: commits carrying it are not rejected).
    /// Returns `None` for a resource with no cert (legacy / still-browser-minted
    /// on the commit-signature DID path, or a plain URL resource) or whose cert
    /// does not verify against the subject DID.
    ///
    /// Sound without relying on `genesis`-propval immutability: the cert is
    /// verified against the subject here, so an overwritten or forged cert —
    /// which cannot produce a signature equal to this DID — is rejected rather
    /// than trusted. Callers that check this per rights-decision should cache
    /// the result per subject (the cert never changes for a resource).
    pub fn genesis_signer(&self) -> Option<String> {
        let subject = self.get_subject().to_string();
        // Agent DIDs are identity-based (`did:ad:agent:<pubkey>`), not
        // cert-based; plain URL resources have no cert-DID binding at all.
        let signature = subject.strip_prefix("did:ad:")?;
        if subject.starts_with("did:ad:agent:") {
            return None;
        }
        let cert_b64 = self.get(urls::GENESIS).ok()?.to_string();
        let cert_bytes = crate::agents::decode_base64(&cert_b64).ok()?;
        let cert = crate::genesis::GenesisCert::decode(&cert_bytes).ok()?;
        // Binds the cert (and thus its signer) to this exact subject.
        cert.verify(signature).ok()?;
        Some(cert.signer_did())
    }

    /// Derive `createdAt` / `createdBy` from the genesis oplog change and write
    /// them into the materialized projection. This is the single chokepoint
    /// feeding both the index (so collections can sort by `createdAt`) and
    /// JSON-AD reads — so every resource exposes its creation metadata without
    /// fetching a commit. The signing agent is written into the genesis
    /// change's message by the client (`signChanges`); the timestamp comes
    /// from the genesis change, normalised to milliseconds.
    fn materialize_genesis_metadata(doc: &crate::loro::AtomicLoroDoc, propvals: &mut PropVals) {
        // Prefer the inline genesis certificate — it's the authoritative,
        // offline-verifiable source of creation facts. `createdBy`/`createdAt`/
        // `parent`/`drive` are materialized from it (never clobbering a value
        // already present). Legacy resources without a cert fall through to the
        // oplog-derived path below.
        if let Some(cert_val) = propvals.get(urls::GENESIS) {
            if let Ok(bytes) = crate::agents::decode_base64(&cert_val.to_string()) {
                if let Ok(cert) = crate::genesis::GenesisCert::decode(&bytes) {
                    use crate::datatype::DataType;
                    if cert.created_at > 0 && !propvals.contains_key(urls::CREATED_AT) {
                        if let Ok(v) =
                            Value::new(&cert.created_at.to_string(), &DataType::Timestamp)
                        {
                            propvals.insert(urls::CREATED_AT.into(), v);
                        }
                    }
                    if !propvals.contains_key(urls::CREATED_BY) {
                        if let Ok(v) = Value::new(&cert.signer_did(), &DataType::AtomicUrl) {
                            propvals.insert(urls::CREATED_BY.into(), v);
                        }
                    }
                    if !cert.parent.is_empty() && !propvals.contains_key(urls::PARENT) {
                        if let Ok(v) = Value::new(&cert.parent, &DataType::AtomicUrl) {
                            propvals.insert(urls::PARENT.into(), v);
                        }
                    }
                    if !cert.drive.is_empty() && !propvals.contains_key(urls::DRIVE_PROP) {
                        if let Ok(v) = Value::new(&cert.drive, &DataType::AtomicUrl) {
                            propvals.insert(urls::DRIVE_PROP.into(), v);
                        }
                    }
                    return;
                }
            }
        }

        let Some(genesis) = doc.genesis_change() else {
            return;
        };

        // Fill in `createdAt` only when the oplog has a real timestamp and no
        // value is already present — never clobber an existing creation time.
        // `genesis.timestamp` is already normalised to milliseconds.
        if genesis.timestamp > 0 && !propvals.contains_key(urls::CREATED_AT) {
            if let Ok(value) = Value::new(
                &genesis.timestamp.to_string(),
                &crate::datatype::DataType::Timestamp,
            ) {
                propvals.insert(urls::CREATED_AT.into(), value);
            }
        }

        if let Some(message) = genesis.message {
            if !message.is_empty() && !propvals.contains_key(urls::CREATED_BY) {
                if let Ok(value) = Value::new(&message, &crate::datatype::DataType::AtomicUrl) {
                    propvals.insert(urls::CREATED_BY.into(), value);
                }
            }
        }
    }

    pub fn build_state_doc(&self) -> AtomicResult<crate::loro::AtomicLoroDoc> {
        if let Some(doc) = &self.loro {
            return crate::loro::AtomicLoroDoc::from_snapshot(&doc.export_snapshot());
        }

        // A Commit resource carries a `loroUpdate` property whose bytes are
        // the COMMITTED resource's snapshot — NOT the commit's own Loro
        // state. Using those bytes here would expose the committed
        // resource's propvals (isA: Message, parent, …) as if they belonged
        // to the commit. For commits, seed from propvals instead so the doc
        // reflects (isA: Commit, signature, signer, …). Gate on `is_native`,
        // not the subject: a genesis commit's subject is a placeholder until
        // it is signed, so a subject-based gate would miss it.
        if !self.is_native() {
            if let Some(Value::LoroDoc(snapshot)) = self.propvals.get(urls::LORO_UPDATE) {
                return crate::loro::AtomicLoroDoc::from_snapshot(snapshot);
            }
        }

        let doc = crate::loro::AtomicLoroDoc::new();
        Self::seed_state_doc_from_propvals(&doc, &self.propvals)?;
        Ok(doc)
    }

    /// Replace property state from a materialized versioned doc (sync / import).
    pub fn apply_state_doc(&mut self, doc: crate::loro::AtomicLoroDoc) -> AtomicResult<()> {
        let snapshot = doc.export_snapshot();
        self.apply_state_doc_with_snapshot(doc, snapshot)
    }

    /// Like [`Self::apply_state_doc`], but for the common case where the
    /// caller already holds the exact snapshot bytes `doc` was imported from
    /// (e.g. a snapshot just read out of `Tree::LoroSnapshots`). Skips the
    /// redundant `doc.export_snapshot()` re-serialization — every plain
    /// resource read (`Db::get_resource`) goes through this path, so on a
    /// collection query touching N resources this avoided one full
    /// CRDT-snapshot export per member.
    ///
    /// Callers must guarantee `snapshot` is exactly the bytes `doc` was
    /// built from (no mutation of `doc` in between), otherwise the stored
    /// `loroUpdate` propval would silently diverge from `doc`'s real state.
    pub(crate) fn apply_state_doc_with_snapshot(
        &mut self,
        doc: crate::loro::AtomicLoroDoc,
        snapshot: Vec<u8>,
    ) -> AtomicResult<()> {
        let mut propvals = Self::materialize_propvals_from_loro_doc(&doc);
        propvals.insert(urls::LORO_UPDATE.into(), Value::LoroDoc(snapshot));
        self.propvals = propvals;
        self.loro = Some(doc);
        Ok(())
    }

    fn set_loro_snapshot_state(&mut self, snapshot: Vec<u8>) -> AtomicResult<()> {
        self.propvals
            .insert(urls::LORO_UPDATE.into(), Value::LoroDoc(snapshot.clone()));
        self.loro = Some(crate::loro::AtomicLoroDoc::from_snapshot(&snapshot)?);
        Ok(())
    }

    /// Merge externally-persisted CRDT state into this editable doc before a
    /// local edit, so the edit builds on top of it instead of overwriting it.
    ///
    /// The sync layer writes a peer's merged changes straight to the store's
    /// snapshot, bypassing any in-memory editing session an app is holding for
    /// the same resource. Appending to that stale session and saving would then
    /// export a snapshot without the peer's change — silently reverting it.
    /// Calling this with the store's current snapshot first catches the session
    /// up. Idempotent: importing already-known state is a Loro no-op.
    pub fn merge_persisted_state(&mut self, state: &[u8]) -> AtomicResult<()> {
        if state.is_empty() {
            return Ok(());
        }
        self.ensure_materialized()?;
        self.loro().import_update(state)?;
        self.sync_propvals_from_loro();
        Ok(())
    }

    /// Fetches all 'required' properties. Returns an error if any are missing in this Resource.
    pub async fn check_required_props(&self, store: &impl Storelike) -> AtomicResult<()> {
        let classvec = self.get_classes(store).await?;
        for class in classvec.iter() {
            tracing::debug!(
                "Checking required props for class {} on resource {}",
                class.subject,
                self.get_subject()
            );
            for required_prop in class.requires.clone() {
                if self.get(&required_prop).is_err() {
                    tracing::error!(
                        "Property {} missing from {}. Resource has properties: {:?}",
                        required_prop,
                        self.get_subject(),
                        self.propvals.keys().collect::<Vec<_>>()
                    );
                    return Err(format!(
                        "Property {} missing. Is required in class {} ",
                        required_prop, class.subject
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Removes / deletes the resource from the store by performing a Commit.
    /// Recursively deletes the resource's children.
    #[tracing::instrument(skip(store))]
    pub async fn destroy(
        &mut self,
        store: &impl Storelike,
    ) -> AtomicResult<crate::commit::CommitResponse> {
        self.commit.destroy(true);
        self.save(store)
            .await
            .map_err(|e| format!("Failed to destroy {} : {}", self.subject, e).into())
    }

    /// Gets the children of this resource.
    #[tracing::instrument(skip(store))]
    pub async fn get_children(&self, store: &impl Storelike) -> AtomicResult<Vec<Resource>> {
        let result = store
            .query(&Query::new_prop_val(
                urls::PARENT,
                self.get_subject().as_str(),
            ))
            .await?;
        Ok(result.resources)
    }

    pub fn from_propvals(propvals: PropVals, subject: Subject) -> Resource {
        Resource {
            propvals,
            commit: CommitBuilder::new(subject.clone()),
            subject,
            loro: None,
        }
    }

    /// Update a property on the live Loro doc and propvals cache only.
    /// Does not touch the legacy commit builder — use before `save_locally` so
    /// `sync_loro_changes_to_commit_builder` can export one coherent `loroUpdate`
    /// (e.g. stroke append + `dateEdited` in a single commit).
    pub fn patch_loro_property(&mut self, property: &str, value: Value) -> AtomicResult<()> {
        self.ensure_materialized()?;
        self.propvals.insert(property.into(), value.clone());
        self.loro().set_property(property, &value)?;
        Ok(())
    }

    /// Like [`Self::patch_loro_property`] but tags the resulting Loro commit
    /// with a system origin so the user's undo button skips it.
    ///
    /// Use for writes that aren't part of the user's edit history — touches
    /// to `dateEdited`, sync bookkeeping like `lastCommit`, etc. Without
    /// this, drawing a stroke and then ticking `dateEdited` produces two
    /// undo steps and the user's first undo tap looks like a no-op.
    pub fn patch_loro_property_sys(&mut self, property: &str, value: Value) -> AtomicResult<()> {
        self.ensure_materialized()?;
        // Flush any pending non-system ops first so they don't get lumped
        // into the sys-tagged commit (which would smuggle a user edit past
        // the undo filter). Their UndoManager group stays intact.
        self.loro().commit();
        self.propvals.insert(property.into(), value.clone());
        self.loro().set_property(property, &value)?;
        // `commit_with` binds the origin to *this* commit directly, so the
        // event reaches the UndoManager with `origin = "sys:<prop>"` and the
        // `add_exclude_origin_prefix("sys:")` filter skips it. Without this
        // the date tick becomes its own undo step and the user's first
        // undo tap looks like a no-op (it reverts the timestamp, not the
        // visible stroke).
        let origin = format!("{}{}", crate::loro::SYS_ORIGIN_PREFIX, property);
        self.loro().commit_with_origin(&origin);
        Ok(())
    }

    /// Ensure the in-memory versioned state is loaded (from propvals or persisted snapshot).
    pub fn ensure_materialized(&mut self) -> AtomicResult<()> {
        if self.loro.is_none() {
            self.loro = Some(self.build_state_doc()?);
        }
        Ok(())
    }

    /// Like [`Self::ensure_materialized`], plus undo/redo tracking for interactive edits.
    pub fn ensure_editable(&mut self) -> AtomicResult<()> {
        self.ensure_materialized()?;
        self.init_undo();
        Ok(())
    }

    /// Initialize undo tracking. Call after [`Self::ensure_materialized`].
    pub fn init_undo(&mut self) {
        if let Some(doc) = &self.loro {
            // UndoManager needs a committed baseline (see loro undo_redo_json_array test).
            doc.commit();
            doc.ensure_undo_manager();
        }
    }

    /// Start a new undo group so the next mutation can be undone independently.
    /// Call after each user-visible edit (e.g. one stroke).
    pub fn record_undo_checkpoint(&mut self) -> AtomicResult<()> {
        self.ensure_materialized()?;
        self.loro().checkpoint()
    }

    fn loro(&self) -> &crate::loro::AtomicLoroDoc {
        self.loro
            .as_ref()
            .expect("versioned state not loaded — call ensure_materialized() first")
    }

    /// Rebuild propvals + commit from the current Loro doc state.
    /// Used after undo/redo to keep everything in sync.
    /// Rebuild propvals from the live Loro doc state.
    /// Does NOT export a snapshot — that happens once at save time.
    fn sync_propvals_from_loro(&mut self) {
        self.propvals = Self::materialize_propvals_from_loro_doc(self.loro());
    }

    /// Insert a propval directly, bypassing the Loro doc entirely.
    ///
    /// For response-shaping only: attaching already-exported raw snapshot
    /// bytes as `loroUpdate`, or marking `incomplete` on a listing member.
    /// Going through `set`/`set_unsafe` would call `ensure_materialized`,
    /// which decodes the CRDT snapshot — the exact cost the shallow query
    /// path exists to avoid. Never use this for state that must be merged
    /// or persisted; the doc will not know about it.
    pub(crate) fn insert_propval_raw(&mut self, property: String, value: Value) {
        self.propvals.insert(property, value);
    }

    /// Persisted or in-memory materialized state bytes (for sync and signing).
    pub fn materialized_state(&self) -> Option<Vec<u8>> {
        if let Some(doc) = &self.loro {
            return Some(doc.export_snapshot());
        }

        // Commits' `loroUpdate` value belongs to the committed resource, not
        // the commit itself — see `build_state_doc` above. Skip the
        // property-as-snapshot shortcut so callers that need the commit's
        // own state build it from propvals (via the build_* path), not from
        // the wrong-resource bytes. Gate on `is_native` so a genesis
        // commit's placeholder subject is covered too.
        if !self.is_native() {
            if let Some(Value::LoroDoc(snapshot)) = self.propvals.get(urls::LORO_UPDATE) {
                return Some(snapshot.clone());
            }
        }

        None
    }

    pub(crate) fn export_open_state(&self) -> Option<Vec<u8>> {
        self.loro.as_ref().map(|doc| doc.export_snapshot())
    }

    /// Load versioned state before history reads (`get_history`, `view_at`).
    pub fn warm_history(&mut self) -> AtomicResult<()> {
        self.ensure_materialized()
    }

    /// Edit history for this resource (newest first).
    pub fn get_history(&self) -> Vec<crate::history::VersionMetadata> {
        match &self.loro {
            Some(doc) => doc.get_history(),
            None => Vec::new(),
        }
    }

    /// Current version marker (for branching / time-travel).
    pub fn get_current_version(&mut self) -> AtomicResult<crate::history::VersionID> {
        self.ensure_materialized()?;
        Ok(self.loro().current_version())
    }

    /// Checkout a specific historical version. The resource enters a detached
    /// read-only state — call `attach()` to return to the latest version.
    pub fn checkout(&mut self, version: &crate::history::VersionID) -> AtomicResult<()> {
        self.ensure_materialized()?;
        self.loro().checkout(version)?;
        self.sync_propvals_from_loro();
        Ok(())
    }

    /// Return to the latest version after a `checkout()`.
    pub fn attach(&mut self) -> AtomicResult<()> {
        self.ensure_materialized()?;
        self.loro().attach()?;
        self.sync_propvals_from_loro();
        Ok(())
    }

    /// Read-only view of this resource at a historical version.
    pub fn view_at(&self, version: &crate::history::VersionID) -> AtomicResult<Resource> {
        let doc = self
            .loro
            .as_ref()
            .ok_or("Versioned state not loaded — call warm_history() first")?;
        let props = doc.get_properties_at(version)?;
        let mut propvals = PropVals::new();
        for (key, loro_val) in &props {
            if let Some(atomic_val) = crate::loro::loro_value_to_atomic_value(loro_val) {
                propvals.insert(key.clone(), atomic_val);
            }
        }
        Ok(Resource {
            propvals,
            subject: self.subject.clone(),
            commit: CommitBuilder::new(self.subject.clone()),
            loro: None,
        })
    }

    /// Returns the subject of the resource as a Subject enum.
    pub fn get_subject_enum(&self) -> &Subject {
        &self.subject
    }

    /// Get a value by property URL
    pub fn get(&self, property_url: &str) -> AtomicResult<&Value> {
        Ok(self.propvals.get(property_url).ok_or(format!(
            "Property {} for resource {} not found",
            property_url, self.subject
        ))?)
    }

    pub fn get_commit_builder(&self) -> &CommitBuilder {
        &self.commit
    }

    /// Checks if the classes are there, if not, fetches them.
    /// Returns an empty vector if there are no classes found.
    ///
    /// A class this store does not hold is SKIPPED, not an error. That is what
    /// the line above always claimed, but the `?` that used to be here made one
    /// unresolvable class abort the lot — and since `check_required_props` calls
    /// this, that turned "I have never seen this class" into a rejected commit.
    ///
    /// Cost of getting it wrong, measured in the field: a table was created on
    /// one node and its row class never reached another, so every row written
    /// against that node was refused, forever, with the rows still rendering
    /// locally as though saved. Two people lost a session to it.
    ///
    /// Skipping weakens required-property validation for classes we cannot see,
    /// which is the right trade: a store cannot enforce a contract it does not
    /// have, the same write is already possible with no class at all, and this
    /// is a data-integrity check rather than an access-control one — rights are
    /// enforced separately and are not affected. In a system where resources
    /// arrive at different times by different routes, an unknown class is a
    /// normal state, not a malformed write.
    pub async fn get_classes(&self, store: &impl Storelike) -> AtomicResult<Vec<Class>> {
        let mut classes: Vec<Class> = Vec::new();
        if let Ok(val) = self.get(crate::urls::IS_A) {
            for class in val.to_subjects(None)? {
                match store.get_class(&class).await {
                    Ok(resolved) => classes.push(resolved),
                    Err(e) => tracing::warn!(
                        "Class {} is not available here, so {} is not validated against it: {}",
                        class,
                        self.get_subject(),
                        e
                    ),
                }
            }
        }
        Ok(classes)
    }

    /// Returns the first item of the is_ array
    pub fn get_main_class(&self) -> AtomicResult<String> {
        match self.get(crate::urls::IS_A) {
            Ok(val) => {
                let subjects = val.to_subjects(None)?;
                subjects
                    .first()
                    .cloned()
                    .ok_or_else(|| format!("Resource {} has no class", self.subject).into())
            }
            Err(_) => Err(format!("Resource {} has no class", self.subject).into()),
        }
    }

    /// Returns the `Parent` of this Resource.
    /// Throws in case of recursion
    pub async fn get_parent(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        match self.get(urls::PARENT) {
            Ok(parent_val) => {
                let subject = Subject::from(parent_val.to_string());
                match store.get_resource(&subject).await {
                    Ok(parent) => {
                        if self.get_subject() == parent.get_subject() {
                            return Err(format!(
                                "There is a circular relationship in {} (parent = same resource).",
                                self.get_subject()
                            )
                            .into());
                        }
                        // Check write right
                        Ok(parent)
                    }
                    Err(_err) => Err(format!(
                        "Parent of {} ({}) not found: {}",
                        self.get_subject(),
                        parent_val,
                        _err
                    )
                    .into()),
                }
            }
            Err(e) => Err(format!("Parent of {} not found: {}", self.get_subject(), e).into()),
        }
    }

    /// Returns the `drive` of this Resource, if set.
    ///
    /// The `drive` propval (stamped at genesis) records which drive a resource
    /// belongs to. Unlike `parent`, it is a direct pointer to the drive root,
    /// so it works even for `did:ad:` subjects that can't be matched to a drive
    /// by URL prefix. Used by the commit fan-out to scope delivery to the
    /// owning drive's subscribers and never leak commits across drives.
    pub fn get_drive(&self) -> Option<Subject> {
        if let Ok(val) = self.get(urls::DRIVE_PROP) {
            return Some(Subject::from(val.to_string()));
        }
        // A Drive is its own drive. A drive's own DID can't reference itself
        // before the genesis signature exists, so a Drive root carries no
        // `drive` propval — its authoritative drive is its own subject. Without
        // this, fan-out and rights resolution for edits to the drive root
        // itself would find no owning drive.
        let is_drive = self
            .propvals
            .get(urls::IS_A)
            .and_then(|is_a| is_a.to_subjects(None).ok())
            .is_some_and(|classes| classes.iter().any(|c| c == urls::DRIVE));

        if is_drive {
            return Some(self.subject.clone());
        }

        None
    }

    /// Walks the parent tree upwards until there is no parent, then returns them as a vector.
    pub async fn get_parent_tree(&self, store: &impl Storelike) -> AtomicResult<Vec<Resource>> {
        let mut parents: Vec<Resource> = Vec::new();
        let mut current = self.clone();

        while let Ok(parent) = current.get_parent(store).await {
            parents.push(parent.clone());
            current = parent;
        }

        Ok(parents)
    }

    /// Returns all PropVals.
    /// Useful if you want to iterate over all Atoms / Properties.
    pub fn get_propvals(&self) -> &PropVals {
        &self.propvals
    }

    /// True for resources whose `loroUpdate` is a *signed payload*, not a CRDT
    /// snapshot of their own state — i.e. commits. Such resources are never
    /// given a live `loro` state doc, and their `loroUpdate` propval is
    /// serialized verbatim, never re-derived from a doc.
    ///
    /// Discriminates on `isA: Commit` rather than the subject: a commit's
    /// subject is a placeholder (`did:ad:genesis`) at client-sign time and
    /// `did:ad:commit:…` only at server-verify time, so a subject-based gate
    /// would make the two sides serialize different bytes. `isA` is present
    /// and stable from the moment the commit resource is built.
    pub(crate) fn is_native(&self) -> bool {
        if self.subject.is_commit_did() {
            return true;
        }
        self.propvals
            .get(urls::IS_A)
            .and_then(|is_a| is_a.to_subjects(None).ok())
            .is_some_and(|classes| classes.iter().any(|c| c == urls::COMMIT))
    }

    fn propvals_for_serialization(&self) -> PropVals {
        let mut propvals = self.propvals.clone();

        // Inject the live doc's snapshot as `loroUpdate` for transport — but
        // ONLY for CRDT resources. A commit's `loroUpdate` is its signed
        // payload; re-deriving it from a doc (whose snapshot embeds a random
        // peer id) would make the serialized bytes non-deterministic and
        // break signature verification. Commits keep their propval verbatim.
        if !self.is_native() {
            if let Some(doc) = &self.loro {
                propvals.insert(
                    urls::LORO_UPDATE.into(),
                    Value::LoroDoc(doc.export_snapshot()),
                );
            }
        }

        propvals
    }

    /// Gets a value by its property shortname or property URL.
    // Todo: should use both the Classes AND the existing props
    pub async fn get_shortname(
        &self,
        shortname: &str,
        store: &impl Storelike,
    ) -> AtomicResult<&Value> {
        let prop = self.resolve_shortname_to_property(shortname, store).await?;
        self.get(&prop.subject)
    }

    pub fn get_subject(&self) -> &Subject {
        &self.subject
    }

    /// checks if a resouce has a specific parent. iterates over all parents.
    pub async fn has_parent(&self, store: &impl Storelike, parent: &str) -> bool {
        let mut mut_res = self.to_owned();
        loop {
            if let Ok(found_parent) = mut_res.get_parent(store).await {
                if found_parent.get_subject().as_str() == parent {
                    return true;
                }
                mut_res = found_parent;
            } else {
                return false;
            }
        }
    }

    /// Returns all PropVals.
    pub fn into_propvals(self) -> PropVals {
        self.propvals
    }

    /// Create a new, empty Resource.
    pub fn new(subject: String) -> Resource {
        let propvals: PropVals = HashMap::new();
        let subj: Subject = subject.into();
        Resource {
            propvals,
            commit: CommitBuilder::new(subj.clone()),
            subject: subj,
            loro: None,
        }
    }

    pub fn random_subject(_store: &impl Storelike) -> AtomicResult<String> {
        Ok(format!("/{}", Ulid::new().to_string()))
    }

    /// Create a new resource with a generated Subject
    pub fn new_generate_subject(store: &impl Storelike) -> AtomicResult<Resource> {
        let subject = Resource::random_subject(store)?;
        Ok(Resource::new(subject))
    }

    /// Create a new instance of some Class.
    /// The subject is generated, but can be changed.
    /// Does not save the resource to the store.
    pub async fn new_instance(class_url: &str, store: &impl Storelike) -> AtomicResult<Resource> {
        let propvals: PropVals = HashMap::new();
        let class = store.get_class(class_url).await?;
        let subject = format!("/{}/{}", &class.shortname, random_string(10));
        let subj: Subject = subject.into();
        let mut resource = Resource {
            propvals,
            commit: CommitBuilder::new(subj.clone()),
            subject: subj,
            loro: None,
        };
        let class_urls = Vec::from([String::from(class_url)]);
        resource
            .set(crate::urls::IS_A.into(), class_urls.into(), store)
            .await?;
        Ok(resource)
    }

    /// Appends a Resource to a specific property through the commitbuilder.
    /// Useful if you want to have compact Commits that add things to existing ResourceArrays.
    pub fn push(
        &mut self,
        property: &str,
        value: SubResource,
        skip_existing: bool,
    ) -> AtomicResult<&mut Self> {
        let mut vec = match self.propvals.get(property) {
            Some(some) => match some {
                Value::ResourceArray(vec) => {
                    if skip_existing {
                        let str_val = value.to_string();
                        for i in vec {
                            if i.to_string() == str_val {
                                // Value already exists
                                return Ok(self);
                            }
                        }
                    }
                    vec.to_owned()
                }
                _other => return Err("Wrong datatype, expected ResourceArray".into()),
            },
            None => Vec::new(),
        };
        vec.push(value.clone());
        let full_array: Value = vec.into();
        self.propvals.insert(property.into(), full_array.clone());
        // Mirror the change into the live Loro doc if it's been initialized.
        // Without this, `sign()` exports a stale snapshot (it prefers the
        // live doc over the commitbuilder's set map), and the appended
        // element is silently dropped from the resulting commit's loroUpdate.
        if let Some(doc) = &self.loro {
            let _ = doc.set_property(property, &full_array);
        }
        // Store the full array value in the commit builder so the Loro update
        // contains the complete state, not just the appended item.
        self.commit.set(property.into(), full_array);
        Ok(self)
    }

    /// Append a JSON item to a Json property. CRDT-friendly — appends to the
    /// LoroList instead of replacing it. Items from different devices merge cleanly.
    pub fn push_list_item(
        &mut self,
        property: &str,
        item: serde_json::Value,
    ) -> crate::errors::AtomicResult<()> {
        match self.propvals.get_mut(property) {
            Some(Value::Json(serde_json::Value::Array(arr))) => arr.push(item.clone()),
            _ => {
                self.propvals.insert(
                    property.into(),
                    Value::Json(serde_json::Value::Array(vec![item.clone()])),
                );
            }
        };
        self.ensure_materialized()?;
        self.loro().push_to_loro_list(property, &item)?;
        self.loro().commit();
        let _ = self.record_undo_checkpoint();
        Ok(())
    }

    /// Alias for `push_list_item` (legacy name).
    pub fn push_json_item(
        &mut self,
        property: &str,
        item: serde_json::Value,
    ) -> crate::errors::AtomicResult<()> {
        self.push_list_item(property, item)
    }

    /// Insert a JSON item at a specific index in a Json property.
    /// CRDT-friendly — records a Loro list insert that merges across devices.
    pub fn insert_list_item(
        &mut self,
        property: &str,
        index: usize,
        item: serde_json::Value,
    ) -> crate::errors::AtomicResult<()> {
        match self.propvals.get_mut(property) {
            Some(Value::Json(serde_json::Value::Array(arr))) => {
                if index > arr.len() {
                    return Err(format!(
                        "Index {index} out of bounds for {property} (len {})",
                        arr.len()
                    )
                    .into());
                }
                arr.insert(index, item.clone());
            }
            _ => {
                if index != 0 {
                    return Err(format!("{property} is not a JSON array").into());
                }
                self.propvals.insert(
                    property.into(),
                    Value::Json(serde_json::Value::Array(vec![item.clone()])),
                );
            }
        };
        self.ensure_materialized()?;
        self.loro().insert_into_loro_list(property, index, &item)?;
        Ok(())
    }

    /// Clear all items from a Json property. Clears the LoroList too.
    pub fn clear_json_array(&mut self, property: &str) -> crate::errors::AtomicResult<()> {
        let new_val = Value::Json(serde_json::Value::Array(vec![]));
        self.propvals.insert(property.into(), new_val);
        self.ensure_materialized()?;
        self.loro().clear_loro_list(property)?;
        Ok(())
    }

    /// Delete a single item from a Json property by index. CRDT-friendly —
    /// records a Loro list delete operation that merges across devices.
    pub fn delete_list_item(
        &mut self,
        property: &str,
        index: usize,
    ) -> crate::errors::AtomicResult<()> {
        // Update propvals cache
        match self.propvals.get_mut(property) {
            Some(Value::Json(serde_json::Value::Array(arr))) => {
                if index >= arr.len() {
                    return Err(format!(
                        "Index {index} out of bounds for {property} (len {})",
                        arr.len()
                    )
                    .into());
                }
                arr.remove(index);
            }
            _ => {
                return Err(format!("{property} is not a JSON array").into());
            }
        }

        self.ensure_materialized()?;
        self.loro().delete_from_loro_list(property, index)?;
        self.loro().commit();
        let _ = self.record_undo_checkpoint();
        Ok(())
    }

    /// Undo the last local Loro operation on this resource.
    /// Returns true if something was undone.
    /// After undo, call `save_locally()` to persist and sync the change.
    pub fn undo(&mut self) -> crate::errors::AtomicResult<bool> {
        self.ensure_materialized()?;
        if !self.loro().undo()? {
            return Ok(false);
        }
        self.loro().commit();
        self.sync_propvals_from_loro();
        Ok(true)
    }

    /// Redo the last undone Loro operation on this resource.
    /// Returns true if something was redone.
    /// After redo, call `save_locally()` to persist and sync the change.
    pub fn redo(&mut self) -> crate::errors::AtomicResult<bool> {
        self.ensure_materialized()?;
        if !self.loro().redo()? {
            return Ok(false);
        }
        self.loro().commit();
        self.sync_propvals_from_loro();
        Ok(true)
    }

    pub fn can_undo(&self) -> bool {
        self.loro.as_ref().is_some_and(|d| d.can_undo())
    }

    pub fn can_redo(&self) -> bool {
        self.loro.as_ref().is_some_and(|d| d.can_redo())
    }

    /// Doc-first, fallible propval removal. For CRDT resources the removal is
    /// applied to the live Loro doc with `?` (no swallowed error); commit
    /// resources ([`Self::is_native`]) are propval-only and never get a state
    /// doc.
    pub fn remove_propval(&mut self, property_url: &str) -> AtomicResult<()> {
        if !self.is_native() {
            self.ensure_materialized()?;
            self.loro().remove_property(property_url)?;
        }
        self.propvals.remove_entry(property_url);
        self.commit.remove(property_url.into());
        Ok(())
    }

    /// Remove a propval from a resource by property URL or shortname.
    /// Returns error if propval does not exist in this resource or its class.
    pub async fn remove_propval_shortname(
        &mut self,
        property_shortname: &str,
        store: &impl Storelike,
    ) -> AtomicResult<()> {
        let property_url = self
            .resolve_shortname_to_property(property_shortname, store)
            .await?;
        self.remove_propval(&property_url.subject)?;
        Ok(())
    }

    /// Tries to resolve the shortname of a Property to a Property.
    /// Currently only tries the shortnames for linked classes - not for other properties.
    // TODO: Not spec compliant - does not use the correct order (required, recommended, other)
    // TODO: Seems more costly then needed. Maybe resources need to keep a hashmap for resolving shortnames?
    pub async fn resolve_shortname_to_property(
        &self,
        shortname: &str,
        store: &impl Storelike,
    ) -> AtomicResult<Property> {
        // If it's a URL, were done quickly!
        if is_url(shortname) {
            return store.get_property(shortname).await;
        }
        // First, iterate over all existing properties, see if any of these work.
        for (url, _val) in self.propvals.iter() {
            if let Ok(prop) = store.get_property(url).await {
                if prop.shortname == shortname {
                    return Ok(prop);
                }
            }
        }
        // If that fails, load the classes for the resource, iterate over these
        let classes = self.get_classes(store).await?;
        // Loop over all Requires and Recommends props
        for class in classes {
            for required_prop_subject in class.requires {
                let required_prop = store.get_property(&required_prop_subject).await?;
                if required_prop.shortname == shortname {
                    return Ok(required_prop);
                }
            }
            for recommended_prop_subject in class.recommends {
                let recommended_prop = store.get_property(&recommended_prop_subject).await?;
                if recommended_prop.shortname == shortname {
                    return Ok(recommended_prop);
                }
            }
        }
        Err(format!("Shortname '{}' for '{}' not found", shortname, self.subject).into())
    }

    pub fn reset_commit_builder(&mut self) {
        self.commit = CommitBuilder::new(self.subject.clone());
    }

    /// When only the in-memory Loro doc changed (`push_list_item`, undo/redo), copy
    /// an incremental update onto the commit builder so sign/apply can run.
    fn sync_loro_changes_to_commit_builder(&mut self) -> AtomicResult<()> {
        let Some(doc) = self.loro.as_ref() else {
            return Ok(());
        };
        // Tag the pending edits as one change with a unique token, exactly as
        // the browser does before signing: history buckets versions by this
        // message, and the signed envelope that carries the change is matched
        // back to it by the same token (`crate::envelopes::attribute_history`).
        // A no-op when nothing is pending.
        doc.commit_with_message(&format!(
            "c-{:x}-{}",
            crate::utils::now(),
            crate::utils::random_string(6)
        ));
        let base = match self.get(urls::LORO_UPDATE) {
            Ok(Value::LoroDoc(snapshot)) => Some(snapshot.clone()),
            _ => None,
        };
        let update = if let Some(ref snapshot) = base {
            let base_doc = crate::loro::AtomicLoroDoc::from_snapshot(snapshot)?;
            doc.export_updates_since(&base_doc.oplog_vv())
        } else {
            doc.export_snapshot()
        };
        if !update.is_empty() {
            self.commit.set_loro_update(update);
        }
        Ok(())
    }

    /// Sign, apply to the store, and adopt the resulting resource state.
    async fn apply_signed_commit(
        &mut self,
        store: &impl Storelike,
        commit: crate::Commit,
    ) -> AtomicResult<CommitResponse> {
        let agent = store.get_default_agent()?;
        let opts = CommitOpts {
            validate_schema: true,
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            validate_for_agent: Some(agent.subject.to_string()),
            validate_loro_causality: false,
            update_index: true,
            source_id: None,
        };
        let commit_response = store.apply_commit(commit, &opts).await?;
        if let Some(new) = &commit_response.resource_new {
            self.adopt_resource_state(new)?;
        }
        self.reset_commit_builder();
        Ok(commit_response)
    }

    /// No-op save response when there is nothing to commit.
    fn empty_commit_response(&self, signer: Subject) -> CommitResponse {
        CommitResponse {
            commit: crate::Commit {
                subject: self.get_subject().clone(),
                signer,
                loro_update: None,
                destroy: Some(false),
                created_at: crate::utils::now(),
                previous_commit: None,
                is_genesis: None,
                signature: None,
                url: None,
            },
            commit_resource: Resource::new(self.get_subject().to_string()),
            resource_new: Some(self.clone()),
            resource_old: None,
            add_atoms: Vec::new(),
            remove_atoms: Vec::new(),
            changed_props: std::collections::HashSet::new(),
            source_id: None,
        }
    }

    /// Saves the resource (with all the changes) to the store by creating a Commit.
    /// Uses default Agent to sign the Commit.
    /// Stores changes on the Subject's Server by sending a Commit.
    /// Returns the generated Commit, the new Resource and the old Resource.
    pub async fn save(
        &mut self,
        store: &impl Storelike,
    ) -> AtomicResult<crate::commit::CommitResponse> {
        let agent = store.get_default_agent()?;
        self.sync_loro_changes_to_commit_builder()?;
        if !self.get_commit_builder().has_changes() {
            self.reset_commit_builder();
            return Ok(self.empty_commit_response(agent.subject.clone()));
        }
        let commit = self
            .get_commit_builder()
            .clone()
            .sign(&agent, store, self)
            .await?;
        let should_post = match self.subject.clone() {
            crate::Subject::Internal { .. } => false,
            crate::Subject::External(_) => true,
            crate::Subject::Did { .. } => false,
        };
        if should_post {
            crate::client::post_commit(&commit, store).await?;
        }
        self.apply_signed_commit(store, commit).await
    }

    /// Saves the resource (with all the changes) to the store by creating a Commit.
    /// Uses default Agent to sign the Commit.
    /// Returns the generated Commit and the new Resource.
    /// Does not validate rights / hierarchy.
    /// Does not store these changes on the server of the Subject - the Commit will be lost, unless you handle it manually.
    pub async fn save_locally(&mut self, store: &impl Storelike) -> AtomicResult<CommitResponse> {
        let agent = store.get_default_agent()?;
        self.sync_loro_changes_to_commit_builder()?;
        if !self.get_commit_builder().has_changes() {
            self.reset_commit_builder();
            return Ok(self.empty_commit_response(agent.subject.clone()));
        }
        let commit = self
            .get_commit_builder()
            .clone()
            .sign(&agent, store, self)
            .await?;
        self.apply_signed_commit(store, commit).await
    }

    /// Saves the resource as a new DID-native resource.
    /// The subject will be set to `did:ad:{genesis_signature}`.
    pub async fn save_as_genesis(
        &mut self,
        store: &impl Storelike,
    ) -> AtomicResult<CommitResponse> {
        let agent = store.get_default_agent()?;
        // Use a placeholder that starts with did:ad: to trigger special genesis serialization logic
        self.subject = Subject::from_raw("did:ad:placeholder", None);
        self.commit.set_subject(self.subject.clone());

        let mut commitbuilder = self.get_commit_builder().clone();
        commitbuilder.is_genesis = true;
        let commit = commitbuilder.sign(&agent, store, self).await?;

        let signature = commit
            .signature
            .as_ref()
            .ok_or("No signature generated for genesis commit")?;
        let did_subject = Subject::from_raw(&format!("did:ad:{}", signature), None);

        // Update both the resource and the commit subject to the real DID
        self.subject = did_subject.clone();
        let mut final_commit = commit;
        final_commit.subject = did_subject.clone();

        let opts = CommitOpts {
            validate_schema: true,
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            validate_for_agent: Some(agent.subject.to_string()),
            validate_loro_causality: false,
            update_index: true,
            source_id: None,
        };

        let commit_response = store.apply_commit(final_commit, &opts).await?;
        if let Some(new) = &commit_response.resource_new {
            self.adopt_resource_state(new)?;
        }
        self.reset_commit_builder();
        Ok(commit_response)
    }

    /// Save the resource to a remote server via HTTP POST.
    /// Signs the commit and sends it to the server's `/commit` endpoint.
    /// Use this for client-side code that talks to an AtomicServer.
    pub async fn save_remote(&mut self, store: &impl Storelike) -> AtomicResult<String> {
        let agent = store.get_default_agent()?;
        let snapshot = self.build_state_doc()?.export_snapshot();

        // If this is a genesis commit (new DID resource), use create_did
        if self.subject.as_str() == "did:ad:placeholder" {
            let mut commitbuilder = self.commit.clone();
            commitbuilder.is_genesis = true;
            commitbuilder.set_loro_update(snapshot.clone());

            let commit = crate::Commit::create_did(commitbuilder, &agent, store).await?;
            let subject = commit.subject.clone();
            let commit_id = commit
                .signature
                .as_ref()
                .map(|sig| format!("did:ad:commit:{}", sig));
            crate::client::post_commit(&commit, store).await?;
            self.subject = subject.clone();
            // Stamp lastCommit so subsequent saves do not mis-detect genesis.
            if let Some(id) = commit_id {
                self.propvals
                    .insert(urls::LAST_COMMIT.into(), Value::AtomicUrl(id.into()));
            }
            self.set_loro_snapshot_state(snapshot)?;
            self.reset_commit_builder();
            Ok(subject.to_string())
        } else {
            let mut commitbuilder = self.commit.clone();
            commitbuilder.set_loro_update(snapshot.clone());

            let commit = commitbuilder.sign(&agent, store, self).await?;
            let commit_id = commit
                .signature
                .as_ref()
                .map(|sig| format!("did:ad:commit:{}", sig));
            crate::client::post_commit(&commit, store).await?;
            if let Some(id) = commit_id {
                self.propvals
                    .insert(urls::LAST_COMMIT.into(), Value::AtomicUrl(id.into()));
            }
            self.set_loro_snapshot_state(snapshot)?;
            self.reset_commit_builder();
            Ok(self.subject.to_string())
        }
    }

    /// Set the name property.
    pub fn set_name(&mut self, name: &str) -> AtomicResult<&mut Self> {
        self.set_unsafe(urls::NAME.into(), Value::String(name.into()))?;
        Ok(self)
    }

    /// Get the name property.
    pub fn get_name(&self) -> Option<String> {
        self.get(urls::NAME).ok().map(|v| v.to_string())
    }

    /// Overwrites the is_a (Class) of the Resource.
    pub fn set_class(&mut self, is_a: &str) -> AtomicResult<()> {
        self.set_unsafe(
            crate::urls::IS_A.into(),
            Value::ResourceArray([is_a.into()].into()),
        )?;
        Ok(())
    }

    /// Insert a Property/Value combination.
    /// Overwrites existing Property/Value.
    /// Validates the datatype.
    pub async fn set_string(
        &mut self,
        property_url: String,
        value: &str,
        store: &impl Storelike,
    ) -> AtomicResult<&mut Self> {
        let fullprop = store.get_property(&property_url).await.map_err(|e| {
            format!(
                "Failed setting propval for '{}' because property '{}' could not be found. {}",
                self.get_subject(),
                property_url,
                e
            )
        })?;
        let val = Value::new(value, &fullprop.data_type)?;
        self.set_unsafe(property_url, val)?;
        Ok(self)
    }

    /// Inserts a Property/Value combination.
    /// Checks datatype.
    /// Overwrites existing.
    /// Adds the change to the commit builder's `set` map.
    pub async fn set(
        &mut self,
        property: String,
        value: Value,
        store: &impl Storelike,
    ) -> AtomicResult<&mut Self> {
        let full_prop = store.get_property(&property).await?;
        if let Some(allowed) = full_prop.allows_only {
            let error = Err(format!(
                "Property '{}' does not allow value '{}'. Allowed: {:?}",
                property, value, allowed
            )
            .into());

            match &value {
                Value::ResourceArray(value_array) => {
                    for item in value_array {
                        if !allowed.contains(&item.to_string()) {
                            return error;
                        }
                    }
                }
                _ => {
                    if !allowed.contains(&value.to_string()) {
                        return error;
                    }
                }
            }
        }
        if full_prop.data_type == value.datatype() {
            self.set_unsafe(property, value)?;
            Ok(self)
        } else {
            Err(format!("Datatype for subject '{}', property '{}', value '{}' did not match. Wanted '{}', got '{}'",
                self.get_subject(),
                property,
                value,
                full_prop.data_type,
                value.datatype()
            ).into())
        }
    }

    /// Does not validate property / datatype combination.
    /// Inserts a Property/Value combination. Overwrites existing.
    ///
    /// Doc-first, fallible mutation. For CRDT resources the live Loro doc is
    /// materialized and the write applied to it with `?`: a failed doc write
    /// surfaces instead of being swallowed, so the doc and the `propvals`
    /// cache cannot silently diverge.
    ///
    /// Commit resources ([`Self::is_native`]) are propval-only — they never
    /// get a state doc. Native-ness is read from `isA`; when `isA` itself is
    /// the property being set, the incoming value is consulted so a commit
    /// resource never acquires a doc, not even transiently while it is built.
    pub fn set_unsafe(&mut self, property: String, value: Value) -> AtomicResult<&mut Self> {
        let is_native = if property == urls::IS_A {
            self.subject.is_commit_did()
                || value
                    .to_subjects(None)
                    .is_ok_and(|classes| classes.iter().any(|c| c == urls::COMMIT))
        } else {
            self.is_native()
        };

        if !is_native {
            self.ensure_materialized()?;
            self.loro().set_property(&property, &value)?;
        }
        self.propvals.insert(property.clone(), value.clone());
        self.commit.set(property, value);
        Ok(self)
    }

    /// Sets a property / value combination.
    /// Property can be a shortname (e.g. 'description' instead of the full URL).
    /// Returns error if propval does not exist in this resource or its class.
    pub async fn set_shortname(
        &mut self,
        property: &str,
        value: &str,
        store: &impl Storelike,
    ) -> AtomicResult<&mut Self> {
        let fullprop = self.resolve_shortname_to_property(property, store).await?;
        let fullval = Value::new(value, &fullprop.data_type)?;
        self.set_unsafe(fullprop.subject, fullval)?;
        Ok(self)
    }

    /// Overwrites all current PropVals. Does not perform validation.
    pub fn set_propvals_unsafe(&mut self, propvals: PropVals) {
        self.propvals = propvals;
        self.loro = None;
    }

    /// Changes the subject of the Resource.
    /// Does not 'move' the Resource
    /// See https://github.com/atomicdata-dev/atomic-server/issues/44
    pub fn set_subject(&mut self, url: String) -> &mut Self {
        let subj: Subject = url.into();
        self.commit.set_subject(subj.clone());
        self.subject = subj;
        self
    }

    /// Converts Resource to JSON-AD string.
    /// If origin is provided, Internal subjects are resolved to it.
    #[instrument(skip_all)]
    pub fn to_json_ad(&self, origin: Option<&str>) -> AtomicResult<String> {
        let origin = origin.unwrap_or("http://localhost");
        let propvals = self.propvals_for_serialization();
        let res = crate::serialize::propvals_to_json_ad_map(
            &propvals,
            Some(self.get_subject().resolve(origin)),
            origin,
            true,
        )?;
        Ok(serde_json::to_string(&res)?)
    }

    /// Serializes the resource to JSON-AD string, using the provided base_url for resolving Local subjects.
    pub fn to_json_ad_with_url(&self, base_url: &str) -> AtomicResult<String> {
        let propvals = self.propvals_for_serialization();
        let mut map = serde_json::Map::new();
        for (prop, val) in propvals.iter() {
            map.insert(
                prop.clone(),
                crate::serialize::val_to_serde(val.clone(), base_url, true)?,
            );
        }
        Ok(serde_json::to_string(&map)?)
    }

    /// Converts Resource to plain JSON string.
    #[instrument(skip_all)]
    pub async fn to_json(
        &self,
        store: &impl Storelike,
        origin: Option<&str>,
    ) -> AtomicResult<String> {
        let propvals = self.propvals_for_serialization();
        let obj = crate::serialize::propvals_to_json_ld(
            &propvals,
            Some(self.get_subject().to_string()),
            store,
            false,
            origin,
        )
        .await?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON".into())
    }

    /// Converts Resource to JSON-LD string, with @context object and RDF compatibility.
    #[instrument(skip_all)]
    pub async fn to_json_ld(
        &self,
        store: &impl Storelike,
        origin: Option<&str>,
    ) -> AtomicResult<String> {
        let propvals = self.propvals_for_serialization();
        let obj = crate::serialize::propvals_to_json_ld(
            &propvals,
            Some(self.get_subject().to_string()),
            store,
            true,
            origin,
        )
        .await?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON-LD".into())
    }

    pub fn to_atoms_iter(&self) -> impl Iterator<Item = Atom> + '_ {
        self.propvals.iter().map(|(property, value)| {
            Atom::new(self.subject.clone(), property.clone(), value.clone())
        })
    }

    #[instrument(skip_all)]
    pub fn to_atoms(&self) -> Vec<Atom> {
        self.to_atoms_iter().collect()
    }

    #[instrument(skip_all)]
    #[cfg(feature = "rdf")]
    /// Serializes the Resource to the RDF N-Triples format.
    pub async fn to_n_triples(&self, store: &impl Storelike) -> AtomicResult<String> {
        crate::serialize::atoms_to_ntriples(self.to_atoms(), store).await
    }

    pub fn vec_to_json_ad(resources: &[Resource], origin: Option<&str>) -> AtomicResult<String> {
        let str = resources
            .iter()
            .map(|r| r.to_json_ad(origin))
            .collect::<AtomicResult<Vec<String>>>()?
            .join(",");

        Ok(format!("[{}]", str))
    }

    pub async fn vec_to_json(
        resources: &Vec<Resource>,
        store: &impl Storelike,
        origin: Option<&str>,
    ) -> AtomicResult<String> {
        let mut strings = Vec::new();
        for r in resources {
            strings.push(r.to_json(store, origin).await?);
        }
        let str = strings.join(",");

        Ok(format!("[{}]", str))
    }

    pub async fn vec_to_json_ld(
        resources: &Vec<Resource>,
        store: &impl Storelike,
        origin: Option<&str>,
    ) -> AtomicResult<String> {
        let mut strings = Vec::new();
        for r in resources {
            strings.push(r.to_json_ld(store, origin).await?);
        }
        let str = strings.join(",");

        Ok(format!("[{}]", str))
    }

    pub fn vec_to_atoms(resources: &Vec<Resource>) -> Vec<Atom> {
        let mut atoms = Vec::new();

        for resource in resources {
            atoms.extend(resource.to_atoms_iter());
        }

        atoms
    }

    #[cfg(feature = "rdf")]
    pub async fn vec_to_n_triples(
        resources: &Vec<Resource>,
        store: &impl Storelike,
    ) -> AtomicResult<String> {
        let atoms = Self::vec_to_atoms(resources);
        crate::serialize::atoms_to_ntriples(atoms, store).await
    }
}

impl From<Resource> for crate::storelike::ResourceResponse {
    fn from(resource: Resource) -> Self {
        crate::storelike::ResourceResponse::Resource(resource)
    }
}

impl From<&Resource> for crate::storelike::ResourceResponse {
    fn from(resource: &Resource) -> Self {
        crate::storelike::ResourceResponse::Resource(resource.clone())
    }
}

#[cfg(all(test, feature = "db"))]
mod test {
    use super::*;
    use crate::{test_utils::init_store, urls};

    mod genesis_signer {
        use super::*;
        use crate::datatype::DataType;

        async fn mint_resource_and_agent() -> (crate::Db, crate::agents::Agent, String) {
            let store = init_store().await;
            let agent = store.create_agent(Some("creator")).await.unwrap();
            store.set_default_agent(agent.clone());
            let drive = crate::test_utils::create_test_drive(&store).await.unwrap();

            let mut cb = crate::commit::CommitBuilder::new("placeholder".into());
            cb.set(urls::PARENT.into(), Value::AtomicUrl(drive.as_str().into()));
            cb.set(
                urls::DESCRIPTION.into(),
                Value::new("x", &DataType::Markdown).unwrap(),
            );
            let commit = crate::commit::Commit::create_did(cb, &agent, &store)
                .await
                .unwrap();
            let subject = commit.subject.to_string();
            let opts = crate::commit::CommitOpts {
                validate_schema: false,
                validate_signature: true,
                validate_timestamp: false,
                validate_rights: false,
                validate_loro_causality: false,
                update_index: true,
                validate_for_agent: None,
                source_id: None,
            };
            store.apply_commit(commit, &opts).await.unwrap();
            (store, agent, subject)
        }

        #[tokio::test]
        async fn a_cert_minted_resource_reports_its_creator() {
            let (store, agent, subject) = mint_resource_and_agent().await;
            let resource = store.get_resource(&subject.as_str().into()).await.unwrap();
            assert_eq!(
                resource.genesis_signer().as_deref(),
                Some(agent.subject.to_string().as_str()),
                "the verified cert signer must be the creating agent"
            );
        }

        #[test]
        fn a_resource_without_a_cert_has_no_signer() {
            // A plain URL resource carries no genesis cert.
            let resource = Resource::new("https://localhost/plain".into());
            assert_eq!(resource.genesis_signer(), None);
        }

        #[tokio::test]
        async fn a_tampered_cert_is_rejected_not_trusted() {
            let (store, _agent, subject) = mint_resource_and_agent().await;
            let mut resource = store.get_resource(&subject.as_str().into()).await.unwrap();
            // Overwrite the cert with bytes that no longer sign to this DID.
            resource
                .set_unsafe(
                    urls::GENESIS.into(),
                    Value::String("not-a-real-cert".into()),
                )
                .unwrap();
            assert_eq!(
                resource.genesis_signer(),
                None,
                "a cert that does not verify against the subject must not be trusted"
            );
        }
    }

    #[tokio::test]
    async fn get_and_set_resource_props() {
        let store: crate::Db = init_store().await;
        let mut resource = store.get_resource(&urls::CLASS.into()).await.unwrap();
        assert!(
            resource
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "class"
        );
        resource
            .set_shortname("shortname", "something-valid", &store)
            .await
            .unwrap();
        assert!(
            resource
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "something-valid"
        );
        resource
            .set_shortname("shortname", "should not contain spaces", &store)
            .await
            .unwrap_err();
    }

    /// A table's row class created on one node may not have reached this one.
    /// Refusing the write in that case cost two people a session: every row was
    /// rejected with "Failed getting class …", the rows rendered locally as
    /// though saved, and nothing surfaced it.
    #[tokio::test]
    async fn a_class_this_store_does_not_have_is_skipped_not_fatal() {
        let store: crate::Db = init_store().await;
        let mut row = Resource::new("did:ad:rowAgainstAnAbsentClass".into());
        row.set_unsafe(
            crate::urls::IS_A.into(),
            crate::Value::ResourceArray(vec![crate::values::SubResource::Subject(
                "did:ad:aClassThisStoreHasNeverSeen".into(),
            )]),
        )
        .unwrap();

        // Unresolvable, so there is nothing to validate against — and nothing
        // to validate against is not the same as invalid.
        let classes = row.get_classes(&store).await.unwrap();
        assert!(classes.is_empty());
        row.check_required_props(&store).await.unwrap();
    }

    #[tokio::test]
    async fn check_required_props() {
        let store: crate::Db = init_store().await;
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        new_resource
            .set_shortname("shortname", "should-fail", &store)
            .await
            .unwrap();
        new_resource.check_required_props(&store).await.unwrap_err();
        new_resource
            .set_shortname("description", "Should succeed!", &store)
            .await
            .unwrap();
        new_resource.check_required_props(&store).await.unwrap();
    }

    #[tokio::test]
    async fn new_instance() {
        let store: crate::Db = init_store().await;
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        new_resource
            .set_shortname("shortname", "person", &store)
            .await
            .unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "person"
        );
        new_resource
            .set_shortname("shortname", "human", &store)
            .await
            .unwrap();
        new_resource
            .set_shortname("description", "A real human being", &store)
            .await
            .unwrap();
        new_resource.save_locally(&store).await.unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "human"
        );
        let resource_from_store = store
            .get_resource(new_resource.get_subject())
            .await
            .unwrap();
        assert!(
            resource_from_store
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "human"
        );
        println!(
            "{}",
            resource_from_store
                .get_shortname("is-a", &store)
                .await
                .unwrap()
        );
        assert_eq!(
            resource_from_store
                .get_shortname("is-a", &store)
                .await
                .unwrap()
                .to_string(),
            "https://atomicdata.dev/classes/Class"
        );
        assert!(resource_from_store.get_classes(&store).await.unwrap()[0].shortname == "class");
    }

    #[tokio::test]
    async fn new_instance_using_commit() {
        let store: crate::Db = init_store().await;
        let agent = store.get_default_agent().unwrap();
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        new_resource
            .set_shortname("shortname", "person", &store)
            .await
            .unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "person"
        );
        new_resource
            .set_shortname("shortname", "human", &store)
            .await
            .unwrap();
        new_resource
            .set_shortname("description", "A real human being", &store)
            .await
            .unwrap();
        let commit = new_resource
            .get_commit_builder()
            .clone()
            .sign(&agent, &store, &new_resource)
            .await
            .unwrap();
        store
            .apply_commit(
                commit,
                &CommitOpts {
                    validate_schema: true,
                    validate_signature: true,
                    validate_timestamp: true,
                    validate_rights: false,
                    validate_loro_causality: false,
                    validate_for_agent: None,
                    update_index: true,
                    source_id: None,
                },
            )
            .await
            .unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "human"
        );
        let resource_from_store = store
            .get_resource(new_resource.get_subject())
            .await
            .unwrap();
        assert!(
            resource_from_store
                .get_shortname("shortname", &store)
                .await
                .unwrap()
                .to_string()
                == "human"
        );
        println!(
            "{}",
            resource_from_store
                .get_shortname("is-a", &store)
                .await
                .unwrap()
        );
        assert_eq!(
            resource_from_store
                .get_shortname("is-a", &store)
                .await
                .unwrap()
                .to_string(),
            "https://atomicdata.dev/classes/Class"
        );
        assert!(resource_from_store.get_classes(&store).await.unwrap()[0].shortname == "class");
    }

    #[tokio::test]
    async fn iterate() {
        let store: crate::Db = init_store().await;
        let new_resource = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        let mut success = false;
        for (prop, val) in new_resource.get_propvals() {
            if prop == urls::IS_A {
                assert!(val.to_subjects(None).unwrap()[0] == urls::CLASS);
                success = true;
            }
        }
        assert!(success);
    }

    #[tokio::test]
    async fn save() {
        let store: crate::Db = init_store().await;
        let property: String = urls::DESCRIPTION.into();
        let value = Value::Markdown("joe".into());
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        new_resource
            .set(property.clone(), value.clone(), &store)
            .await
            .unwrap();
        // Should fail, because a propval is missing
        assert!(new_resource.save_locally(&store).await.is_err());
        new_resource
            .set(urls::SHORTNAME.into(), Value::Slug("joe".into()), &store)
            .await
            .unwrap();
        let subject = new_resource.get_subject().clone();
        println!("subject new {}", new_resource.get_subject());
        new_resource.save_locally(&store).await.unwrap();
        let found_resource = store.get_resource(&subject).await.unwrap();
        println!("subject found {}", found_resource.get_subject());
        println!("subject all {:?}", found_resource.get_propvals());

        let found_prop = found_resource.get(&property).unwrap().clone();
        assert_eq!(found_prop.to_string(), value.to_string());
    }

    #[tokio::test]
    async fn push_propval() {
        let store: crate::Db = init_store().await;
        let property: String = urls::CHILDREN.into();
        let append_value = "https://localhost/someURL";
        let mut resource = Resource::new_generate_subject(&store).unwrap();
        resource
            .push(&property, append_value.into(), false)
            .unwrap();
        let vec = resource.get(&property).unwrap().to_subjects(None).unwrap();
        assert_eq!(
            append_value,
            vec.first().unwrap(),
            "The first element should be the appended value"
        );
        let resp = resource.save_locally(&store).await.unwrap();
        assert!(
            resp.commit_resource.get(urls::LORO_UPDATE).is_ok(),
            "Commit should have a loroUpdate"
        );

        let new_val = resp
            .resource_new
            .unwrap()
            .get(&property)
            .unwrap()
            .to_subjects(None)
            .unwrap();
        // Loro preserves the value as-given (no URL normalization on property values)
        assert_eq!(new_val.first().unwrap(), append_value);
    }

    #[tokio::test]
    async fn json_ad_serialization_includes_current_loro_snapshot() {
        let store: crate::Db = init_store().await;
        let mut resource = Resource::new_generate_subject(&store).unwrap();
        resource.set_name("Loro-backed resource").unwrap();
        resource
            .set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String("Server-side snapshot".into()),
            )
            .unwrap();
        resource.ensure_materialized().unwrap();

        let json = resource.to_json_ad(Some("http://localhost")).unwrap();

        assert!(
            json.contains(urls::LORO_UPDATE),
            "serialized JSON-AD should include the latest loroUpdate"
        );
        assert!(
            json.contains("Server-side snapshot"),
            "serialized JSON-AD should still include materialized properties"
        );
    }

    #[tokio::test]
    async fn commit_loro_update_is_not_re_derived_from_doc() {
        // A commit resource's `loroUpdate` is its signed payload. Even with a
        // live `loro` doc attached, serialization must emit that payload
        // verbatim — re-deriving from a doc snapshot (random peer id) would
        // make the bytes non-deterministic and break signature verification.
        let _store: crate::Db = init_store().await;
        let mut resource = Resource::new("did:ad:commit:test-signature".into());
        resource
            .set_unsafe(urls::IS_A.into(), vec![urls::COMMIT.to_string()].into())
            .unwrap();
        let signed_payload: Vec<u8> = vec![9, 8, 7, 6, 5, 4, 3, 2, 1];
        resource
            .set_unsafe(
                urls::LORO_UPDATE.into(),
                Value::LoroDoc(signed_payload.clone()),
            )
            .unwrap();
        assert!(resource.is_native(), "a Commit-class resource is native");

        // Attach a live doc — its snapshot differs from the signed payload.
        resource.ensure_materialized().unwrap();

        match resource.propvals_for_serialization().get(urls::LORO_UPDATE) {
            Some(Value::LoroDoc(bytes)) => assert_eq!(
                bytes, &signed_payload,
                "commit loroUpdate must stay the signed payload, not a doc snapshot"
            ),
            other => panic!("expected the verbatim LoroDoc payload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_unsafe_is_doc_first_for_crdt_resources() {
        let store: crate::Db = init_store().await;
        let mut resource = Resource::new_generate_subject(&store).unwrap();
        resource
            .set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String("doc-first value".into()),
            )
            .unwrap();

        assert!(
            resource.loro.is_some(),
            "a CRDT resource materializes a live doc on the first fallible set"
        );
        let json = resource.to_json_ad(Some("http://localhost")).unwrap();
        assert!(
            json.contains(urls::LORO_UPDATE),
            "serialized JSON-AD should carry a loroUpdate"
        );
        assert!(json.contains("doc-first value"));
    }

    #[tokio::test]
    async fn set_unsafe_keeps_commit_resources_docless() {
        // `isA: Commit` set first → every subsequent fallible set is
        // propval-only; the commit resource never acquires a state doc.
        let mut resource = Resource::new("did:ad:will-be-a-commit".into());
        resource
            .set_unsafe(urls::IS_A.into(), vec![urls::COMMIT.to_string()].into())
            .unwrap();
        resource
            .set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String("commit field".into()),
            )
            .unwrap();

        assert!(
            resource.loro.is_none(),
            "a commit resource must never get a state doc"
        );
    }

    #[tokio::test]
    async fn set_propvals_unsafe_resets_stale_loro_state() {
        let store: crate::Db = init_store().await;
        let mut resource = Resource::new_generate_subject(&store).unwrap();
        resource
            .set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String("Old materialized value".into()),
            )
            .unwrap();
        resource.ensure_materialized().unwrap();

        let mut propvals = PropVals::new();
        propvals.insert(urls::NAME.into(), Value::String("Fresh propvals".into()));
        resource.set_propvals_unsafe(propvals);

        resource.ensure_materialized().unwrap();
        let doc = resource.loro.as_ref().unwrap();
        let properties = doc.get_all_properties();

        assert!(
            !properties.contains_key(urls::DESCRIPTION),
            "stale loro-only properties should be dropped when propvals are replaced"
        );
        assert_eq!(
            resource.get(urls::NAME).unwrap().to_string(),
            "Fresh propvals"
        );
    }

    const STROKE_DATA: &str = "https://atomicdata.dev/ontology/canvas/strokeData";

    fn stroke_count(resource: &Resource) -> usize {
        match resource.get(STROKE_DATA) {
            Ok(Value::Json(serde_json::Value::Array(arr))) => arr.len(),
            _ => 0,
        }
    }

    /// Reproduce the Flutter canvas flow: after `push_list_item` the caller
    /// updates an unrelated "system" property (e.g. `dateEdited`) before
    /// `save_locally`. The user-visible undo should still revert the stroke
    /// — the date touch must not become its own undo step that swallows
    /// the user's first undo tap.
    #[tokio::test]
    async fn undo_after_touch_date_edited_reverts_user_edit_in_one_step() {
        let store: crate::Db = init_store().await;
        let (_agent, drive) = store.setup("test").await.unwrap();
        let date_edited = "https://atomicdata.dev/ontology/canvas/dateEdited";
        let canvas = store
            .create_resource(
                "https://atomicdata.dev/ontology/canvas/Canvas",
                &drive,
                "Date touch undo",
                Some(vec![(
                    STROKE_DATA,
                    Value::Json(serde_json::Value::Array(vec![])),
                )]),
            )
            .await
            .unwrap();
        let mut resource = store.get_resource(&canvas.as_str().into()).await.unwrap();
        resource.ensure_editable().unwrap();

        // User draws a single stroke.
        resource
            .push_list_item(
                STROKE_DATA,
                serde_json::json!({"color": 1, "width": 2.0, "path": [[0.0, 0.0]]}),
            )
            .unwrap();
        // Caller (flutter `touch_date_edited`) writes a non-undoable
        // system property before saving — mirrors `save_and_push`. Use the
        // `_sys` variant so the UndoManager doesn't record it as its own
        // step (which would otherwise swallow the user's first undo tap).
        resource
            .patch_loro_property_sys(date_edited, Value::Timestamp(1_700_000_000))
            .unwrap();
        resource.save_locally(&store).await.unwrap();
        assert_eq!(stroke_count(&resource), 1, "stroke is in the doc");

        // ONE undo tap from the user → stroke should be gone.
        assert!(resource.can_undo(), "stroke push should be undoable");
        assert!(resource.undo().unwrap(), "first undo must do something");
        assert_eq!(
            stroke_count(&resource),
            0,
            "one undo tap should revert the user-visible stroke, not just the dateEdited tick"
        );
    }

    /// Undo must work after `save_locally` (which clones the in-memory Loro doc).
    #[tokio::test]
    async fn undo_after_save_exports_loro_update_for_sync() {
        let store: crate::Db = init_store().await;
        let (_agent, drive) = store.setup("test").await.unwrap();
        let canvas = store
            .create_resource(
                "https://atomicdata.dev/ontology/canvas/Canvas",
                &drive,
                "Undo export test",
                Some(vec![(
                    STROKE_DATA,
                    Value::Json(serde_json::Value::Array(vec![])),
                )]),
            )
            .await
            .unwrap();

        let mut resource = store.get_resource(&canvas.as_str().into()).await.unwrap();
        resource.ensure_materialized().unwrap();
        resource.init_undo();
        resource
            .push_list_item(
                STROKE_DATA,
                serde_json::json!({"color": 1, "width": 2.0, "path": [[0.0, 0.0]]}),
            )
            .unwrap();
        resource
            .push_list_item(
                STROKE_DATA,
                serde_json::json!({"color": 2, "width": 2.0, "path": [[1.0, 1.0]]}),
            )
            .unwrap();
        resource.save_locally(&store).await.unwrap();
        assert_eq!(stroke_count(&resource), 2);
        assert!(
            resource.can_undo(),
            "undo manager must survive save_locally (snapshot clone)"
        );

        assert!(
            resource.undo().unwrap(),
            "undo should remove the last stroke"
        );
        assert_eq!(stroke_count(&resource), 1);

        let undo_resp = resource.save_locally(&store).await.unwrap();
        assert!(
            undo_resp
                .commit
                .loro_update
                .as_ref()
                .is_some_and(|u| !u.is_empty()),
            "undo must produce a loro update commit so peers can import the change"
        );

        let reloaded = store.get_resource(&canvas.as_str().into()).await.unwrap();
        assert_eq!(
            stroke_count(&reloaded),
            1,
            "store should persist the undone stroke list"
        );
    }

    #[tokio::test]
    async fn push_stroke_with_date_edited_touch_persists_strokes() {
        let store: crate::Db = init_store().await;
        let (_agent, drive) = store.setup("test").await.unwrap();
        let stroke_data = "https://atomicdata.dev/ontology/canvas/strokeData";
        let date_edited = "https://atomicdata.dev/ontology/canvas/dateEdited";
        let canvas = store
            .create_resource(
                "https://atomicdata.dev/ontology/canvas/Canvas",
                &drive,
                "Stroke test",
                Some(vec![(
                    stroke_data,
                    Value::Json(serde_json::Value::Array(vec![])),
                )]),
            )
            .await
            .unwrap();

        let mut resource = store.get_resource(&canvas.as_str().into()).await.unwrap();
        resource.ensure_materialized().unwrap();
        resource
            .push_list_item(
                stroke_data,
                serde_json::json!({"color": 255, "width": 2.0, "path": [[1.0, 2.0]]}),
            )
            .unwrap();
        // Mirrors Flutter `save_and_push` → `touch_date_edited` before `save_locally`.
        resource
            .patch_loro_property(date_edited, Value::Timestamp(crate::utils::now()))
            .unwrap();
        assert!(
            !resource.get_commit_builder().has_changes(),
            "dateEdited touch must not dirty the legacy commit builder"
        );

        let resp = resource.save_locally(&store).await.unwrap();
        assert!(
            resp.commit
                .loro_update
                .as_ref()
                .is_some_and(|u| !u.is_empty()),
            "stroke + dateEdited save should produce a non-empty loro update"
        );

        let reloaded = store.get_resource(&canvas.as_str().into()).await.unwrap();
        match reloaded.get(stroke_data) {
            Ok(Value::Json(serde_json::Value::Array(arr))) => assert_eq!(arr.len(), 1),
            other => panic!("expected 1 stroke after save_locally, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_list_item_save_locally_persists_strokes() {
        let store: crate::Db = init_store().await;
        let (_agent, drive) = store.setup("test").await.unwrap();
        let stroke_data = "https://atomicdata.dev/ontology/canvas/strokeData";
        let canvas = store
            .create_resource(
                "https://atomicdata.dev/ontology/canvas/Canvas",
                &drive,
                "Stroke test",
                Some(vec![(
                    stroke_data,
                    Value::Json(serde_json::Value::Array(vec![])),
                )]),
            )
            .await
            .unwrap();

        let mut resource = store.get_resource(&canvas.as_str().into()).await.unwrap();
        resource.ensure_materialized().unwrap();
        resource
            .push_list_item(
                stroke_data,
                serde_json::json!({"color": 255, "width": 2.0, "path": [[1.0, 2.0]]}),
            )
            .unwrap();
        // Loro-only edits (Flutter `push_stroke`) do not touch CommitBuilder::set/remove.
        assert!(
            !resource.get_commit_builder().has_changes(),
            "test setup: push_list_item alone must not mark the commit builder dirty"
        );
        let resp = resource.save_locally(&store).await.unwrap();
        assert!(
            resp.commit
                .loro_update
                .as_ref()
                .is_some_and(|u| !u.is_empty()),
            "stroke append should produce a loro update commit"
        );

        let reloaded = store.get_resource(&canvas.as_str().into()).await.unwrap();
        match reloaded.get(stroke_data) {
            Ok(Value::Json(serde_json::Value::Array(arr))) => assert_eq!(arr.len(), 1),
            other => panic!("expected 1 stroke after save_locally, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_resource_loads_full_loro_history_after_multiple_saves() {
        let store: crate::Db = init_store().await;
        let stroke_data = "https://atomicdata.dev/ontology/canvas/strokeData";
        let mut resource = Resource::new_generate_subject(&store).unwrap();
        let subject = resource.get_subject().clone();
        resource.ensure_editable().unwrap();
        resource
            .push_list_item(
                stroke_data,
                serde_json::json!({"color": 1, "path": [[0, 0]]}),
            )
            .unwrap();
        resource.save_locally(&store).await.unwrap();
        resource
            .push_list_item(
                stroke_data,
                serde_json::json!({"color": 2, "path": [[1, 1]]}),
            )
            .unwrap();
        resource.save_locally(&store).await.unwrap();

        let mut reloaded = store.get_resource(&subject).await.unwrap();
        reloaded.warm_history().unwrap();
        let history = reloaded.get_history();
        assert!(
            history.len() >= 2,
            "get_resource should expose merged Loro oplog (got {} entries)",
            history.len()
        );
    }

    #[tokio::test]
    async fn get_children() {
        let store: crate::Db = init_store().await;
        let mut resource1 = Resource::new_generate_subject(&store).unwrap();
        let subject1 = resource1.get_subject().to_string();
        resource1.save_locally(&store).await.unwrap();

        let mut resource2 = Resource::new_generate_subject(&store).unwrap();
        resource2
            .set(
                urls::PARENT.into(),
                Value::AtomicUrl(subject1.into()),
                &store,
            )
            .await
            .unwrap();
        let subject2 = resource2.get_subject().to_string();
        resource2.save_locally(&store).await.unwrap();

        let children = resource1.get_children(&store).await.unwrap();

        assert_eq!(children.len(), 1);
        assert_eq!(children[0].get_subject().to_string(), subject2);
    }
}
