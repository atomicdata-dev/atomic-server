//! Immutable, content-addressed plugin packages, independent of installations.
//!
//! A release is one record for both runtimes: JS source (`atomic-js/1`) or a
//! wasip2 zip (`wasip2/1`, addressed by the blake3 hex of its bytes, which is
//! also how `File` blobs are keyed). The identity covers every field. Fields
//! that are absent or at their default are left out of the hashed form, so a
//! JS release published before `world`, `version` and `previousRelease`
//! existed keeps the id it was published under.
use super::trees::Tree;
use crate::{errors::AtomicResult, urls, Db, Resource, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The JS runtime. Kept under its old name for existing callers.
pub const RUNTIME: &str = "atomic-js/1";
pub const RUNTIME_JS: &str = RUNTIME;
pub const RUNTIME_WASIP2: &str = "wasip2/1";
pub const RUNTIMES: [&str; 2] = [RUNTIME_JS, RUNTIME_WASIP2];

/// Proposal-only world: exports `run`, user-installable.
pub const WORLD_EXTENSION: &str = "extension";
/// Class-extender world: may write, operator-installed, never via an Installation.
pub const WORLD_SERVER_EXTENSION: &str = "server-extension";
pub const WORLDS: [&str; 2] = [WORLD_EXTENSION, WORLD_SERVER_EXTENSION];

fn default_world() -> String {
    WORLD_EXTENSION.to_string()
}

fn is_default_world(world: &str) -> bool {
    world == WORLD_EXTENSION
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginRelease {
    /// JS module source. Required for `atomic-js/1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Blake3 hex of the zip bytes. Required for `wasip2/1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    pub manifest: serde_json::Value,
    pub runtime: String,
    #[serde(default = "default_world", skip_serializing_if = "is_default_world")]
    pub world: String,
    /// Alias -> exact schema identity. No implicit shortname resolution.
    #[serde(default)]
    pub schemas: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Id of the release this one supersedes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_release: Option<String>,
}

impl Default for PluginRelease {
    /// An empty JS release in the `extension` world; fill in `source` and `manifest`.
    fn default() -> Self {
        Self {
            source: None,
            package: None,
            manifest: serde_json::Value::Null,
            runtime: RUNTIME_JS.into(),
            world: default_world(),
            schemas: BTreeMap::new(),
            version: None,
            previous_release: None,
        }
    }
}

impl PluginRelease {
    /// A JS release with the fields that existed before the record was generalized.
    pub fn js(
        source: String,
        manifest: serde_json::Value,
        schemas: BTreeMap<String, String>,
    ) -> Self {
        Self {
            source: Some(source),
            package: None,
            manifest,
            runtime: RUNTIME_JS.into(),
            world: default_world(),
            schemas,
            version: None,
            previous_release: None,
        }
    }

    pub fn id(&self) -> AtomicResult<String> {
        let mut value = serde_json::to_value(self)?;
        sort_objects(&mut value);
        Ok(format!(
            "blake3:{}",
            blake3::hash(&serde_json::to_vec(&value)?).to_hex()
        ))
    }

    pub fn is_js(&self) -> bool {
        self.runtime == RUNTIME_JS
    }

    pub fn is_wasip2(&self) -> bool {
        self.runtime == RUNTIME_WASIP2
    }

    /// Shape checks that hold for every release, whichever store it came from.
    pub fn validate(&self) -> AtomicResult<()> {
        if !RUNTIMES.contains(&self.runtime.as_str()) {
            return Err("unsupported plugin runtime".into());
        }
        if !WORLDS.contains(&self.world.as_str()) {
            return Err("unsupported plugin world".into());
        }
        if self.is_js() {
            if self.source.as_deref().unwrap_or_default().is_empty() {
                return Err("a JS release requires source".into());
            }
            if self.package.is_some() {
                return Err("a JS release has no package".into());
            }
        } else {
            let Some(package) = &self.package else {
                return Err("a wasip2 release requires a package".into());
            };
            if package.len() != 64 || !package.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("a package must be the blake3 hex of the zip bytes".into());
            }
            if self.source.is_some() {
                return Err("a wasip2 release has no source".into());
            }
        }
        if let Some(previous) = &self.previous_release {
            if !previous.starts_with("blake3:") {
                return Err("previousRelease must be a release id".into());
            }
        }
        Ok(())
    }

    /// Reads a `Release` resource back into a release record.
    ///
    /// `package` is the blake3 hex of the zip the resource's `package` File
    /// points at; the caller resolves it, since the File may live on another
    /// server. The stored `releaseId` is not trusted: recompute with [`Self::id`]
    /// and compare.
    pub fn from_resource(resource: &Resource, package: Option<String>) -> AtomicResult<Self> {
        let string = |prop: &str| -> Option<String> {
            match resource.get(prop) {
                Ok(Value::String(s)) | Ok(Value::Markdown(s)) | Ok(Value::Slug(s)) => {
                    Some(s.clone())
                }
                Ok(Value::AtomicUrl(s)) => Some(s.to_string()),
                Ok(other) => Some(other.to_string()),
                Err(_) => None,
            }
        };
        let json = |prop: &str| -> AtomicResult<Option<serde_json::Value>> {
            match resource.get(prop) {
                Ok(Value::Json(v)) => Ok(Some(v.clone())),
                Ok(Value::String(s)) => Ok(Some(serde_json::from_str(s)?)),
                Ok(other) => Ok(Some(serde_json::from_str(&other.to_string())?)),
                Err(_) => Ok(None),
            }
        };
        let manifest = json(urls::MANIFEST)?.ok_or("a Release requires a manifest")?;
        let schemas = match json(urls::SCHEMAS)? {
            Some(value) => serde_json::from_value(value)?,
            None => BTreeMap::new(),
        };
        let release = Self {
            source: string(urls::SOURCE),
            package,
            manifest,
            runtime: string(urls::RUNTIME).ok_or("a Release requires a runtime")?,
            world: string(urls::WORLD).unwrap_or_else(default_world),
            schemas,
            version: string(urls::VERSION),
            previous_release: string(urls::PREVIOUS_RELEASE),
        };
        release.validate()?;
        Ok(release)
    }

    /// Writes this release onto a resource as a `Release`. `package_file` is
    /// the File resource holding the zip for wasip2 releases.
    pub fn write_to_resource(
        &self,
        resource: &mut Resource,
        package_file: Option<&str>,
    ) -> AtomicResult<()> {
        self.validate()?;
        resource.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::RELEASE.into()]),
        )?;
        resource.set_unsafe(urls::RUNTIME.into(), Value::String(self.runtime.clone()))?;
        resource.set_unsafe(urls::WORLD.into(), Value::String(self.world.clone()))?;
        resource.set_unsafe(urls::MANIFEST.into(), Value::Json(self.manifest.clone()))?;
        resource.set_unsafe(
            urls::SCHEMAS.into(),
            Value::Json(serde_json::to_value(&self.schemas)?),
        )?;
        resource.set_unsafe(urls::RELEASE_ID.into(), Value::String(self.id()?))?;
        if let Some(source) = &self.source {
            resource.set_unsafe(urls::SOURCE.into(), Value::String(source.clone()))?;
        }
        if self.package.is_some() {
            let file = package_file.ok_or("a wasip2 Release resource needs its package File")?;
            resource.set_unsafe(urls::PACKAGE.into(), Value::AtomicUrl(file.into()))?;
        }
        if let Some(version) = &self.version {
            resource.set_unsafe(urls::VERSION.into(), Value::String(version.clone()))?;
        }
        if let Some(previous) = &self.previous_release {
            resource.set_unsafe(
                urls::PREVIOUS_RELEASE.into(),
                Value::String(previous.clone()),
            )?;
        }
        Ok(())
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

/// The KV release cache: every release this node published or fetched, under
/// its id. Marketplace visibility is not recorded here; that is a `Listing`
/// resource, created by the server when a release is published publicly.
impl Db {
    pub fn publish_plugin_release(&self, release: &PluginRelease) -> AtomicResult<String> {
        release.validate()?;
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
        release.validate()?;
        Ok(release)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> PluginRelease {
        PluginRelease::js(
            "export function run() { return {}; }".into(),
            serde_json::json!({"schemaVersion":1}),
            BTreeMap::new(),
        )
    }
    fn wasm_release() -> PluginRelease {
        PluginRelease {
            source: None,
            package: Some("ab".repeat(32)),
            manifest: serde_json::json!({"name":"test-plugin","namespace":"ontola","version":"1.0.0"}),
            runtime: RUNTIME_WASIP2.into(),
            world: WORLD_EXTENSION.into(),
            schemas: BTreeMap::new(),
            version: Some("1.0.0".into()),
            previous_release: None,
        }
    }
    #[test]
    fn a_js_release_keeps_its_pre_generalization_identity() {
        // Hashed form before `package`, `world`, `version`, `previousRelease` existed.
        let legacy = serde_json::json!({
            "manifest": {"schemaVersion": 1},
            "runtime": RUNTIME,
            "schemas": {},
            "source": "export function run() { return {}; }",
        });
        let expected = format!(
            "blake3:{}",
            blake3::hash(&serde_json::to_vec(&legacy).unwrap()).to_hex()
        );
        assert_eq!(release().id().unwrap(), expected);
        let stored: PluginRelease = serde_json::from_value(legacy).unwrap();
        assert_eq!(stored, release());
    }
    #[test]
    fn world_and_lineage_are_part_of_the_identity() {
        let original = wasm_release();
        let id = original.id().unwrap();
        let mut changed = original.clone();
        changed.world = WORLD_SERVER_EXTENSION.into();
        assert_ne!(changed.id().unwrap(), id);
        changed = original.clone();
        changed.previous_release = Some(id.clone());
        assert_ne!(changed.id().unwrap(), id);
        changed = original.clone();
        changed.package = Some("cd".repeat(32));
        assert_ne!(changed.id().unwrap(), id);
    }
    #[test]
    fn runtime_shape_is_validated() {
        let mut bad = wasm_release();
        bad.package = None;
        assert!(bad.validate().is_err());
        bad = wasm_release();
        bad.source = Some("x".into());
        assert!(bad.validate().is_err());
        bad = release();
        bad.source = None;
        assert!(bad.validate().is_err());
        bad = release();
        bad.runtime = "python/1".into();
        assert!(bad.validate().is_err());
        bad = release();
        bad.world = "kernel".into();
        assert!(bad.validate().is_err());
    }
    #[test]
    fn release_resource_round_trip_keeps_the_id() {
        for (release, file) in [(release(), None), (wasm_release(), Some("did:ad:file"))] {
            let mut resource = Resource::new("did:ad:release".into());
            release.write_to_resource(&mut resource, file).unwrap();
            assert_eq!(
                resource.get(urls::RELEASE_ID).unwrap().to_string(),
                release.id().unwrap()
            );
            let back = PluginRelease::from_resource(&resource, release.package.clone()).unwrap();
            assert_eq!(back, release);
            assert_eq!(back.id().unwrap(), release.id().unwrap());
        }
    }
    #[tokio::test]
    async fn both_runtimes_are_stored_and_read_back() {
        let db = Db::init_temp("wasm_plugin_release").await.unwrap();
        let id = db.publish_plugin_release(&wasm_release()).unwrap();
        assert_eq!(db.get_plugin_release(&id).unwrap(), wasm_release());
    }
    #[test]
    fn every_executable_dependency_changes_release_identity() {
        let original = release();
        let id = original.id().unwrap();
        let mut changed = original.clone();
        changed.source.as_mut().unwrap().push(' ');
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
        draft.source.as_mut().unwrap().push(' ');
        let second = db.publish_plugin_release(&draft).unwrap();
        assert_ne!(first, second);
        assert_eq!(db.get_plugin_release(&first).unwrap(), release());
        assert_eq!(db.get_plugin_release(&second).unwrap(), draft);
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
