//! Current package activation, stored on the existing connection resource.
//! Jobs retain reviewed snapshots; changing activation never rewrites their receipts.
use atomic_lib::{Db, Storelike};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub release: String,
    pub config: Value,
}

pub async fn read(db: &Db, drive: &str, plugin: &str) -> Result<Option<Binding>, String> {
    let Some(terms) = super::scheduler::drive_terms(db, drive).await else {
        return Ok(None);
    };
    let Some(property) = terms.property("plugin-connection") else {
        return Ok(None);
    };
    let resource = db
        .get_resource(&plugin.into())
        .await
        .map_err(|e| e.to_string())?;
    let Ok(value) = resource.get(property) else {
        return Ok(None);
    };
    let binding: Binding =
        serde_json::from_str(&value.to_string()).map_err(|e| format!("invalid connection: {e}"))?;
    if binding.release.is_empty() {
        return Err("connection release is missing".into());
    }
    Ok(Some(binding))
}

/// Check before starting new work or accepting a new approval. Recovery of
/// already-approved effects keeps its pinned snapshot instead of calling this.
pub async fn require_current(
    db: &Db,
    drive: &str,
    plugin: &str,
    release: &str,
    config: &Value,
    required: bool,
) -> Result<bool, String> {
    match read(db, drive, plugin).await? {
        Some(binding) if binding.release == release && binding.config == *config => Ok(true),
        Some(_) => Err("installation release or settings changed; preview and review the current version first".into()),
        None if required => Err("installation connection was removed; reconnect and review before running".into()),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::{urls, Value as AtomicValue};
    use serde_json::json;

    #[actix_rt::test]
    async fn checks_release_settings_and_removed_activation_without_moving_data() {
        let mut f = super::super::test_fixture::fixture("activation_contract").await;
        super::super::test_fixture::write_plugin(&mut f, "draft").await;
        let db = &f.appstate.store;
        assert!(
            !require_current(db, &f.drive, &f.plugin, "release-a", &json!({}), false)
                .await
                .unwrap()
        );
        assert!(
            require_current(db, &f.drive, &f.plugin, "release-a", &json!({}), true)
                .await
                .is_err()
        );
        let mut r = db.get_resource(&f.plugin.as_str().into()).await.unwrap();
        let parent = r.get(urls::PARENT).unwrap().to_string();
        r.set_unsafe(
            f.terms.property("plugin-connection").unwrap().into(),
            AtomicValue::Json(
                json!({"release":"release-a","config":{"table":"existing"},"events":[]}),
            ),
        )
        .unwrap();
        r.save(db).await.unwrap();
        assert!(require_current(
            db,
            &f.drive,
            &f.plugin,
            "release-a",
            &json!({"table":"existing"}),
            true
        )
        .await
        .unwrap());
        assert!(require_current(
            db,
            &f.drive,
            &f.plugin,
            "release-b",
            &json!({"table":"existing"}),
            true
        )
        .await
        .is_err());
        assert!(require_current(
            db,
            &f.drive,
            &f.plugin,
            "release-a",
            &json!({"table":"other"}),
            true
        )
        .await
        .is_err());
        assert_eq!(
            db.get_resource(&f.plugin.as_str().into())
                .await
                .unwrap()
                .get(urls::PARENT)
                .unwrap()
                .to_string(),
            parent
        );
        r.remove_propval(f.terms.property("plugin-connection").unwrap())
            .unwrap();
        r.save(db).await.unwrap();
        assert!(require_current(
            db,
            &f.drive,
            &f.plugin,
            "release-a",
            &json!({"table":"existing"}),
            true
        )
        .await
        .is_err());
    }
}
