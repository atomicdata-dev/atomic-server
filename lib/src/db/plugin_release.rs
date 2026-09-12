//! Immutable, content-addressed plugin packages, independent of installations.
use super::trees::Tree;
use crate::{errors::AtomicResult, Db};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RUNTIME: &str = "atomic-js/1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginRelease {
    pub source: String,
    pub manifest: serde_json::Value,
    pub runtime: String,
    /// Alias -> exact schema identity. No implicit shortname resolution.
    pub schemas: BTreeMap<String, String>,
}

impl PluginRelease {
    pub fn id(&self) -> AtomicResult<String> {
        let mut value = serde_json::to_value(self)?;
        sort_objects(&mut value);
        Ok(format!(
            "blake3:{}",
            blake3::hash(&serde_json::to_vec(&value)?).to_hex()
        ))
    }
}

fn sort_objects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                sort_objects(value);
            }
            let sorted: BTreeMap<_, _> = std::mem::take(map).into_iter().collect();
            map.extend(sorted);
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(sort_objects),
        _ => {}
    }
}

impl Db {
    pub fn publish_plugin_release(&self, release: &PluginRelease) -> AtomicResult<String> {
        if release.runtime != RUNTIME {
            return Err("unsupported plugin runtime".into());
        }
        if release.source.is_empty() {
            return Err("a release requires source".into());
        }
        let id = release.id()?;
        let key = format!("plugin-release/v1/{id}");
        self.kv.insert(
            Tree::PluginMeta,
            key.as_bytes(),
            &serde_json::to_vec(release)?,
        )?;
        Ok(id)
    }

    pub fn get_plugin_release(&self, id: &str) -> AtomicResult<PluginRelease> {
        let key = format!("plugin-release/v1/{id}");
        let bytes = self
            .kv
            .get(Tree::PluginMeta, key.as_bytes())?
            .ok_or("plugin release is missing")?;
        let release: PluginRelease = serde_json::from_slice(&bytes)?;
        if release.id()? != id {
            return Err("plugin release integrity check failed".into());
        }
        if release.runtime != RUNTIME {
            return Err("unsupported plugin runtime".into());
        }
        Ok(release)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> PluginRelease {
        PluginRelease {
            source: "export function run() { return {}; }".into(),
            manifest: serde_json::json!({"schemaVersion":1}),
            runtime: RUNTIME.into(),
            schemas: BTreeMap::new(),
        }
    }
    #[test]
    fn every_executable_dependency_changes_release_identity() {
        let original = release();
        let id = original.id().unwrap();
        let mut changed = original.clone();
        changed.source.push(' ');
        assert_ne!(changed.id().unwrap(), id);
        changed = original.clone();
        changed.runtime.push('2');
        assert_ne!(changed.id().unwrap(), id);
        changed = original.clone();
        changed
            .schemas
            .insert("task".into(), "https://schema.test/task/v2".into());
        assert_ne!(changed.id().unwrap(), id);
        changed = original.clone();
        changed.manifest["operations"] = serde_json::json!([]);
        assert_ne!(changed.id().unwrap(), id);
    }
    #[tokio::test]
    async fn publication_cannot_mutate_an_existing_release() {
        let db = Db::init_temp("immutable_plugin_release").await.unwrap();
        let mut draft = release();
        let first = db.publish_plugin_release(&draft).unwrap();
        draft.source.push(' ');
        let second = db.publish_plugin_release(&draft).unwrap();
        assert_ne!(first, second);
        assert_eq!(db.get_plugin_release(&first).unwrap(), release());
        assert_eq!(db.get_plugin_release(&second).unwrap(), draft);
        assert!(
            db.plugin_catalog().unwrap().is_empty(),
            "an approval package is not automatically public"
        );
        db.publish_plugin_catalog_entry(&CatalogEntry {
            release: first.clone(),
            name: "Example".into(),
            emoji: None,
            description: String::new(),
            publisher: "publisher".into(),
            domains: vec!["education".into()],
            standards: vec![],
        })
        .unwrap();
        assert_eq!(db.plugin_catalog().unwrap().len(), 1);
        let key = format!("plugin-release/v1/{first}");
        db.kv
            .insert(
                Tree::PluginMeta,
                key.as_bytes(),
                &serde_json::to_vec(&draft).unwrap(),
            )
            .unwrap();
        assert!(
            db.get_plugin_release(&first).is_err(),
            "corrupt package content must not execute"
        );
    }
}

/// Public catalog metadata is written only by explicit publication, never by
/// unattended approval. Publication does not imply provider verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub release: String,
    pub name: String,
    #[serde(default)]
    pub emoji: Option<String>,
    pub description: String,
    pub publisher: String,
    pub domains: Vec<String>,
    pub standards: Vec<String>,
}
impl Db {
    pub fn publish_plugin_catalog_entry(&self, entry: &CatalogEntry) -> AtomicResult<()> {
        self.get_plugin_release(&entry.release)?;
        let key = format!(
            "plugin-catalog/v1/{}",
            serde_json::json!([entry.release, entry.publisher])
        );
        self.kv.insert(
            Tree::PluginMeta,
            key.as_bytes(),
            &serde_json::to_vec(entry)?,
        )?;
        Ok(())
    }
    pub fn plugin_catalog(&self) -> AtomicResult<Vec<CatalogEntry>> {
        self.kv
            .scan_prefix(Tree::PluginMeta, b"plugin-catalog/v1/")
            .map(|entry| {
                let (_, bytes) = entry?;
                serde_json::from_slice(&bytes).map_err(Into::into)
            })
            .collect()
    }
}
