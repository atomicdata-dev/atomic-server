//! Host-owned identity mappings and acknowledged projections, scoped to a plugin instance.
use atomic_lib::{db::trees::Tree, Db, Storelike};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub revision: u64,
    pub records: BTreeMap<String, Binding>,
    pub cursor: Option<serde_json::Value>,
    /// Earlier subjects remain traceable after a reviewed primary-record choice.
    #[serde(default)]
    pub resolved_aliases: BTreeMap<String, String>,
    #[serde(default)]
    pub last_operation: Option<(String, String)>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub local: String,
    /// Null is an acknowledged deletion; absence of a page is never a deletion.
    pub baseline: serde_json::Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub remote: String,
    pub local: String,
    pub local_projection: serde_json::Value,
    pub remote_projection: serde_json::Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub revision: u64,
    pub records: Vec<Acknowledgement>,
    pub cursor: Option<serde_json::Value>,
}

fn key(drive: &str, plugin: &str) -> String {
    format!(
        "plugin-connection-state/v1/{}",
        serde_json::json!([drive, plugin])
    )
}
pub fn read(db: &Db, drive: &str, plugin: &str) -> Result<State, String> {
    db.kv
        .get(Tree::PluginMeta, key(drive, plugin).as_bytes())
        .map_err(|e| e.to_string())?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Ok(State::default()))
}
/// Resolve reviewed source identities before a new sync or revision check. A
/// changed binding advances the revision, invalidating older sync approvals.
pub async fn read_resolved(db: &Db, drive: &str, plugin: &str) -> Result<State, String> {
    let _writer = db.lock_plugin(&key(drive, plugin)).await;
    let mut state = read(db, drive, plugin)?;
    let mut changed = false;
    let mut locals = std::collections::HashSet::new();
    for binding in state.records.values_mut() {
        if !binding.baseline.is_null() {
            // Missing/deleted resources retain the existing deletion protocol.
            if db.has_resource_locally(&binding.local) {
                let resource = db
                    .get_resource(&binding.local.clone().into())
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some((parent, id)) = atomic_lib::import_identity::identity(&resource) {
                    if let Some(primary) =
                        atomic_lib::import_identity::find_existing(db, &parent, &id)
                            .await
                            .map_err(|e| e.to_string())?
                    {
                        if primary != binding.local {
                            state
                                .resolved_aliases
                                .insert(binding.local.clone(), primary.clone());
                            binding.local = primary;
                            changed = true;
                        }
                    }
                }
            }
        }
        if !locals.insert(binding.local.clone()) {
            return Err("Reviewed copies would bind distinct remote records to one local record; review the connection".into());
        }
    }
    if changed {
        state.revision = state.revision.checked_add(1).ok_or("revision exhausted")?;
        db.kv
            .insert(
                Tree::PluginMeta,
                key(drive, plugin).as_bytes(),
                &serde_json::to_vec(&state).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        db.flush().map_err(|e| e.to_string())?;
    }
    Ok(state)
}

pub async fn checkpoint(
    db: &Db,
    drive: &str,
    plugin: &str,
    page: Checkpoint,
) -> Result<State, String> {
    checkpoint_once(db, drive, plugin, page, None).await
}

pub async fn checkpoint_once(
    db: &Db,
    drive: &str,
    plugin: &str,
    page: Checkpoint,
    operation: Option<&str>,
) -> Result<State, String> {
    read_resolved(db, drive, plugin).await?;
    let _writer = db.lock_plugin(&key(drive, plugin)).await;
    let mut state = read(db, drive, plugin)?;
    let fingerprint = blake3::hash(&serde_json::to_vec(&page).map_err(|e| e.to_string())?)
        .to_hex()
        .to_string();
    if let (Some(id), Some((previous, digest))) = (operation, &state.last_operation) {
        if id == previous {
            if &fingerprint != digest {
                return Err("checkpoint identity cannot be reused with different data".into());
            }
            return Ok(state);
        }
    }
    if state.revision != page.revision {
        return Err("connection state changed; reload before checkpointing".into());
    }
    let mut seen = std::collections::HashSet::new();
    for record in page.records {
        if record.remote.is_empty()
            || record.local.is_empty()
            || !seen.insert(record.remote.clone())
        {
            return Err("record identities must be nonempty and unique in a page".into());
        }
        if record.local_projection != record.remote_projection {
            return Err("local and remote projections must agree before checkpointing".into());
        }
        if !record.local_projection.is_object() && !record.local_projection.is_null() {
            return Err("a projection must be an object or an explicit deletion".into());
        }
        if state
            .records
            .get(&record.remote)
            .is_some_and(|old| old.local != record.local)
        {
            return Err("a remote identity cannot be rebound to another local resource".into());
        }
        if state
            .records
            .iter()
            .any(|(remote, old)| remote != &record.remote && old.local == record.local)
        {
            return Err("a local resource is already bound to another remote identity".into());
        }
        state.records.insert(
            record.remote,
            Binding {
                local: record.local,
                baseline: record.local_projection,
            },
        );
    }
    state.revision = state.revision.checked_add(1).ok_or("revision exhausted")?;
    state.cursor = page.cursor;
    state.last_operation = operation.map(|id| (id.to_string(), fingerprint));
    let bytes = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("connection state exceeds eight MiB".into());
    }
    db.kv
        .insert(Tree::PluginMeta, key(drive, plugin).as_bytes(), &bytes)
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reviewed_primary_advances_binding_revision_and_preserves_lineage() {
        use atomic_lib::{urls, Resource, Value};
        let db = Db::init_temp("resolved_connection").await.unwrap();
        let (agent, drive) = db.setup("Resolution test").await.unwrap();
        let other = Db::init_temp("resolved_connection_other").await.unwrap();
        other.set_default_agent(agent);
        other
            .add_resource_opts(
                &db.get_resource(&drive.clone().into()).await.unwrap(),
                false,
                true,
                true,
            )
            .await
            .unwrap();
        let mut copies = Vec::new();
        for (store, name) in [(&db, "Primary"), (&other, "Original")] {
            let mut row = Resource::new("https://localhost/new".into());
            row.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.clone().into()))
                .unwrap();
            row.set_unsafe(
                urls::LOCAL_ID.into(),
                Value::String("github:issue:one".into()),
            )
            .unwrap();
            row.set_unsafe(urls::NAME.into(), Value::String(name.into()))
                .unwrap();
            row.save_as_genesis(store).await.unwrap();
            copies.push(row);
        }
        checkpoint(
            &db,
            &drive,
            "plugin",
            page(
                0,
                "remote",
                copies[1].get_subject().as_str(),
                serde_json::json!({"title":"Original"}),
                serde_json::json!({"title":"Original"}),
            ),
        )
        .await
        .unwrap();
        let push = atomic_lib::sync::protocol::DecodedSyncPush {
            drive: drive.clone(),
            last: true,
            entries: vec![atomic_lib::sync::protocol::SyncPushEntry {
                subject: copies[1].get_subject().to_string(),
                loro_bytes: copies[1].build_state_doc().unwrap().export_snapshot(),
            }],
        };
        atomic_lib::sync::engine::import_sync_push(
            &push,
            &db,
            &atomic_lib::agents::ForAgent::Sudo,
            false,
        )
        .await
        .unwrap();
        assert!(read_resolved(&db, &drive, "plugin").await.is_err());
        let mut primary = db.get_resource(copies[0].get_subject()).await.unwrap();
        let mut members = serde_json::Map::new();
        for row in &copies {
            members.insert(
                row.get_subject().pure_id(),
                atomic_lib::import_identity::review_snapshot(
                    &db.get_resource(row.get_subject()).await.unwrap(),
                )
                .unwrap(),
            );
        }
        primary.set_unsafe(urls::IMPORT_RESOLUTION.into(), Value::Json(serde_json::json!({"version":1,"id":"review","canonical":primary.get_subject().pure_id(),"members":members,"supersedes":[]}))).unwrap();
        primary.save_locally(&db).await.unwrap();
        let resolved = read_resolved(&db, &drive, "plugin").await.unwrap();
        assert_eq!(resolved.revision, 2);
        assert_eq!(
            resolved.records["remote"].local,
            primary.get_subject().to_string()
        );
        assert_eq!(
            resolved.records["remote"].baseline,
            serde_json::json!({"title":"Original"})
        );
        assert_eq!(
            resolved.resolved_aliases[copies[1].get_subject().as_str()],
            primary.get_subject().to_string()
        );
        assert_eq!(
            read_resolved(&db, &drive, "plugin").await.unwrap().revision,
            2
        );
        assert!(checkpoint(
            &db,
            &drive,
            "plugin",
            page(
                1,
                "remote",
                primary.get_subject().as_str(),
                serde_json::json!({}),
                serde_json::json!({})
            )
        )
        .await
        .is_err());
    }
    fn page(
        revision: u64,
        remote: &str,
        local: &str,
        a: serde_json::Value,
        b: serde_json::Value,
    ) -> Checkpoint {
        Checkpoint {
            revision,
            records: vec![Acknowledgement {
                remote: remote.into(),
                local: local.into(),
                local_projection: a,
                remote_projection: b,
            }],
            cursor: Some(serde_json::json!("next")),
        }
    }
    #[tokio::test]
    async fn checkpoint_receipt_survives_retry_and_rejects_changed_payload() {
        let db = Db::init_temp("checkpoint_retry").await.unwrap();
        let original = page(0, "r", "l", serde_json::json!({}), serde_json::json!({}));
        checkpoint_once(&db, "d", "p", original.clone(), Some("run/effect"))
            .await
            .unwrap();
        assert_eq!(
            checkpoint_once(&db, "d", "p", original.clone(), Some("run/effect"))
                .await
                .unwrap()
                .revision,
            1
        );
        let mut changed = original;
        changed.cursor = None;
        assert!(checkpoint_once(&db, "d", "p", changed, Some("run/effect"))
            .await
            .is_err());
    }
    #[tokio::test]
    async fn checkpoint_is_atomic_and_rejects_stale_or_divergent_pages() {
        let db = Db::init_temp("connection_checkpoint").await.unwrap();
        let value = serde_json::json!({"name": "Normalized"});
        checkpoint(
            &db,
            "drive",
            "plugin",
            page(0, "r", "l", value.clone(), value.clone()),
        )
        .await
        .unwrap();
        assert!(checkpoint(
            &db,
            "drive",
            "plugin",
            page(0, "r", "l", value.clone(), value.clone())
        )
        .await
        .is_err());
        assert!(checkpoint(
            &db,
            "drive",
            "plugin",
            page(1, "r", "l", value, serde_json::json!({}))
        )
        .await
        .is_err());
        assert_eq!(read(&db, "drive", "plugin").unwrap().revision, 1);
        assert_eq!(read(&db, "other", "plugin").unwrap().revision, 0);
        let mut invalid = page(
            1,
            "new",
            "new",
            serde_json::json!({}),
            serde_json::json!({}),
        );
        invalid.records.push(Acknowledgement {
            remote: "r".into(),
            local: "changed".into(),
            local_projection: serde_json::Value::Null,
            remote_projection: serde_json::Value::Null,
        });
        assert!(checkpoint(&db, "drive", "plugin", invalid).await.is_err());
        assert!(!read(&db, "drive", "plugin")
            .unwrap()
            .records
            .contains_key("new"));
    }
    #[tokio::test]
    async fn empty_pages_keep_bindings_and_deletions_keep_identity() {
        let db = Db::init_temp("connection_tombstone").await.unwrap();
        checkpoint(
            &db,
            "d",
            "p",
            page(0, "r", "l", serde_json::json!({}), serde_json::json!({})),
        )
        .await
        .unwrap();
        checkpoint(
            &db,
            "d",
            "p",
            Checkpoint {
                revision: 1,
                records: vec![],
                cursor: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(read(&db, "d", "p").unwrap().records.len(), 1);
        checkpoint(
            &db,
            "d",
            "p",
            page(
                2,
                "r",
                "l",
                serde_json::Value::Null,
                serde_json::Value::Null,
            ),
        )
        .await
        .unwrap();
        assert!(checkpoint(
            &db,
            "d",
            "p",
            page(
                3,
                "other",
                "l",
                serde_json::json!({}),
                serde_json::json!({})
            )
        )
        .await
        .is_err());
        assert!(read(&db, "d", "p").unwrap().records["r"].baseline.is_null());
    }
}
