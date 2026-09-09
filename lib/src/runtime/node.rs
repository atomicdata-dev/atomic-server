//! [`AtomicNode`]: a thin, named surface over [`Db`].
//!
//! Every method here delegates to a function that already existed before the
//! runtime module did (the doc comment on each one names it). The point is
//! not new behaviour but one place for adapters to bind, so that
//! `wasm/src/lib.rs` and the other bindings stop each re-wrapping `Db` with
//! their own copy of the commit-validation knobs.
//!
//! Slice 1 (2026-09-01) shipped this with a wider aspirational API — `open`
//! with a storage config, `get`, `mutate`, `subscribe`, `sync_with_peer`.
//! Three days later nothing but the WASM binding had bound to it, and the
//! WASM binding used four methods. The surface was cut down to those on
//! 2026-09-04; the seam stays, and grows again when a second adapter binds
//! to it (`planning/atomic-lib-runtime.md`).

use crate::{
    agents::Agent,
    commit::CommitResponse,
    db::Db,
    errors::AtomicResult,
    storelike::{Query, QueryResult},
    sync::engine::{ingest_commit, CommitIngestOpts},
    Storelike,
};

/// The trust role under which a signed commit is ingested. `Hub` and `Peer`
/// are [`CommitIngestOpts::hub`] and [`CommitIngestOpts::peer`];
/// `LocalCache` is the browser's WASM cache applying a commit the server
/// already accepted.
///
/// | policy | signature | rights | timestamp | ownership | loro causality | live echo |
/// | --- | --- | --- | --- | --- | --- | --- |
/// | `Hub` | yes | yes | yes | yes | yes | fan out |
/// | `Peer` | yes | yes | yes | no | no | suppressed |
/// | `LocalCache` | no | no | no | no | no | fan out |
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum IngestPolicy {
    /// This node owns the subject and is the authority: HTTP `/commit` and
    /// hub WS `COMMIT`. `source_id` is the connection the commit came from,
    /// so the commit monitor does not echo it back; `response_origin`
    /// resolves `internal:/` subjects in the response.
    Hub {
        source_id: Option<String>,
        response_origin: Option<String>,
    },
    /// A signed commit from another full node (Iroh / peer `COMMIT` frame).
    /// Fully validated, but this node may host subjects it does not own and
    /// concurrent writes are expected.
    #[default]
    Peer,
    /// A trusted local cache (browser WASM/OPFS) mirroring what its hub
    /// already accepted. Nothing is validated; only the index is updated.
    LocalCache,
}

/// A running Atomic node: durable store plus the local agent that signs for
/// it. Cheap to clone (`Db` is a bundle of `Arc`s); clones share the store,
/// its event channel and its default agent.
#[derive(Clone)]
pub struct AtomicNode {
    db: Db,
}

impl AtomicNode {
    /// Wrap an already-opened store. Adapters construct `Db` themselves
    /// (the WASM `ClientDb`, the server's `AppState`) and bind here.
    pub fn from_db(db: Db) -> Self {
        Self { db }
    }

    /// The underlying store, for operations this surface does not name
    /// (blobs, version vectors, import/export, drive setup, events).
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// The agent that signs local edits (`Storelike::get_default_agent`).
    pub fn agent(&self) -> Option<Agent> {
        self.db.get_default_agent().ok()
    }

    /// Install (or replace) the agent that signs local edits
    /// (`Storelike::set_default_agent`).
    pub fn set_agent(&self, agent: Agent) {
        self.db.set_default_agent(agent);
    }

    /// Run an indexed query (`Storelike::query`). Rights are checked per hit
    /// via `Query::for_agent`.
    pub async fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        self.db.query(q).await
    }

    /// Local KV full-text search (`crate::search::query`).
    pub fn search(
        &self,
        query: &str,
        opts: &crate::client::search::SearchOpts,
    ) -> AtomicResult<Vec<crate::search::SearchHit>> {
        self.db.search_hits(query, opts)
    }

    /// Ingest a signed JSON-AD commit under `policy`.
    ///
    /// - `Hub` / `Peer`: `sync::engine::ingest_commit` with the matching
    ///   `CommitIngestOpts` — the path `server/src/handlers/commit.rs` and
    ///   the peer `COMMIT` frame handler already use.
    /// - `LocalCache`: `Db::apply_commit` with every `validate_*` off — the
    ///   options the WASM `ClientDb.applyCommit` used to carry inline.
    pub async fn apply_commit(
        &self,
        commit_json: &str,
        policy: IngestPolicy,
    ) -> AtomicResult<CommitResponse> {
        match policy {
            IngestPolicy::Hub {
                source_id,
                response_origin,
            } => {
                ingest_commit(
                    &self.db,
                    commit_json,
                    &CommitIngestOpts::hub(source_id, response_origin),
                )
                .await
            }
            IngestPolicy::Peer => {
                ingest_commit(&self.db, commit_json, &CommitIngestOpts::peer()).await
            }
            IngestPolicy::LocalCache => {
                // `DontSave`: the default would persist the parsed Commit
                // resource (validating required props) before `apply_commit`
                // runs; `apply_commit` is the persistence step here.
                let commit_resource = crate::parse::parse_json_ad_resource(
                    commit_json,
                    &self.db,
                    &crate::parse::ParseOpts {
                        save: crate::parse::SaveOpts::DontSave,
                        ..Default::default()
                    },
                )
                .await?;
                let commit = crate::Commit::from_resource(commit_resource)?;
                let opts = crate::commit::CommitOpts {
                    update_index: true,
                    ..crate::commit::CommitOpts::no_validations_no_index()
                };
                self.db.apply_commit(commit, &opts).await
            }
        }
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod tests {
    use super::*;
    use crate::{
        agents::ForAgent, client::commit_to_wire_json, db::DbEvent, urls, Resource, Subject, Value,
    };

    async fn open_test_node(label: &str) -> AtomicNode {
        let db = Db::init_redb(Some("https://localhost".into()))
            .await
            .unwrap_or_else(|e| panic!("{label}: open failed: {e}"));
        db.populate().await.unwrap();
        AtomicNode::from_db(db)
    }

    /// Two nodes in one process, no Actix: a genesis commit minted on one is
    /// ingested on the other via `apply_commit(Peer)`, after which `query`
    /// on the second node reflects it and the store's event channel saw the
    /// change.
    #[tokio::test]
    async fn two_nodes_genesis_then_peer_ingest() {
        let alice_node = open_test_node("alice").await;
        let (alice, drive) = alice_node.db().setup("Alice").await.unwrap();
        let drive = Subject::from(drive);
        assert_eq!(
            alice_node.agent().map(|a| a.subject),
            Some(alice.subject.clone())
        );

        let bob_node = open_test_node("bob").await;
        bob_node.db().setup("Bob").await.unwrap();
        let mut bob_events = bob_node.db().subscribe_events();

        // Alice mints a classless DID document under her drive.
        let mut draft = Resource::new("did:ad:placeholder".into());
        draft
            .set_unsafe(urls::NAME.into(), Value::String("Peer Doc".into()))
            .unwrap();
        draft
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.clone()))
            .unwrap();
        let response = draft.save_as_genesis(alice_node.db()).await.unwrap();
        let subject = response.commit.subject.clone();
        assert!(subject.as_str().starts_with("did:ad:"), "got {subject}");
        assert!(
            bob_node.db().get_resource(&subject).await.is_err(),
            "bob must not see alice's write before ingesting it"
        );

        // Bob already holds Alice's drive, as a replica does after its first
        // sync. A child arriving for a drive this node does not hold is
        // refused: nothing here would say Alice may append to it.
        let alice_drive = alice_node.db().get_resource(&drive).await.unwrap();
        bob_node
            .db()
            .add_resource_opts(&alice_drive, false, true, true)
            .await
            .unwrap();

        // The commit crosses the (in-process) wire as JSON-AD.
        let wire = commit_to_wire_json(&response.commit, alice_node.db())
            .await
            .unwrap();
        let ingested = bob_node
            .apply_commit(&wire, IngestPolicy::Peer)
            .await
            .expect("bob must accept alice's signed genesis commit under Peer policy");
        assert_eq!(ingested.commit.signer, alice.subject);

        // The store sees it (as sudo: bob has no rights on alice's doc).
        let got = bob_node
            .db()
            .get_resource_extended(&subject, false, &ForAgent::Sudo)
            .await
            .unwrap()
            .to_single();
        assert_eq!(got.get(urls::NAME).unwrap().to_string(), "Peer Doc");

        // `query` sees it.
        let result = bob_node
            .query(&Query {
                property: Some(urls::PARENT.into()),
                value: Some(Value::AtomicUrl(drive.clone())),
                for_agent: ForAgent::Sudo,
                ..Query::new()
            })
            .await
            .unwrap();
        assert_eq!(result.subjects, vec![subject.clone()]);

        // The event channel saw the ingest: the ingest stores the commit
        // resource and the document, each emitting a `Changed` event.
        let mut changed = Vec::new();
        while let Ok(event) = bob_events.try_recv() {
            if let DbEvent::Changed { subject, .. } = event {
                changed.push(subject.pure_id());
            }
        }
        assert!(
            changed.contains(&subject.pure_id()),
            "expected a Changed event for {subject}, got {changed:?}"
        );
    }

    /// `LocalCache` is today's WASM `applyCommit`: it applies an unsigned,
    /// unauthorized commit without complaint, because the cache trusts its
    /// hub. `Peer` must reject the very same bytes.
    #[tokio::test]
    async fn local_cache_skips_validation_peer_does_not() {
        let hub = open_test_node("hub").await;
        let (_alice, drive) = hub.db().setup("Alice").await.unwrap();
        let drive = Subject::from(drive);
        let mut draft = Resource::new("did:ad:placeholder".into());
        draft
            .set_unsafe(urls::NAME.into(), Value::String("Cached".into()))
            .unwrap();
        draft
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive))
            .unwrap();
        let response = draft.save_as_genesis(hub.db()).await.unwrap();
        // What the hub pushes to its caches over WS: the stored commit
        // resource, `@id` included (`ingest_commit_json`'s return value).
        let mut wire: serde_json::Value =
            serde_json::from_str(&response.commit_resource.to_json_ad(None).unwrap()).unwrap();
        // Corrupt the signature: a peer must notice, a local cache does not check.
        wire[urls::SIGNATURE] = serde_json::Value::String("AAAA".into());
        let tampered = wire.to_string();

        let cache = open_test_node("cache").await;
        cache
            .apply_commit(&tampered, IngestPolicy::LocalCache)
            .await
            .expect("LocalCache applies without validating the signature");
        cache
            .db()
            .get_resource_extended(&response.commit.subject, false, &ForAgent::Sudo)
            .await
            .expect("cached resource is readable");

        let peer = open_test_node("peer").await;
        peer.apply_commit(&tampered, IngestPolicy::Peer)
            .await
            .expect_err("Peer validates the signature and must reject the tampered commit");
    }
}
