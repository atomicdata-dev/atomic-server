use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

use crate::AtomicError;

/// What the server keeps about one installed plugin on one drive: which
/// resource it is, the agent it acts as, and the manifest it was installed with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginMeta {
    pub subject: String,
    pub agent_secret: String,
    /// The version-two manifest of the installed release.
    ///
    /// A record written before manifests were unified may still hold the
    /// untranslated `plugin.json` (no `schemaVersion`); the server translates
    /// it the first time it loads the plugin and writes the record back.
    pub manifest: serde_json::Value,
    /// The release whose code the server loaded for this plugin, as its
    /// content-addressed id.
    ///
    /// This is what tells an activation that the module already runs. The
    /// manifest cannot answer that: two releases of the same plugin differ in
    /// their package bytes and agree on every manifest field. `None` is a
    /// record written before this field existed, which means "unknown", so
    /// load again and record it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
}

impl PluginMeta {
    /// Whether the manifest is the unified form, or still a legacy `plugin.json`.
    pub fn has_v2_manifest(&self) -> bool {
        self.manifest.get("schemaVersion").is_some()
    }

    /// The origins the manifest allows the plugin to reach. Same path in both
    /// manifest forms.
    pub fn network_origins(&self) -> Vec<String> {
        self.manifest
            .pointer("/network/origins")
            .and_then(|v| v.as_array())
            .map(|origins| {
                origins
                    .iter()
                    .filter_map(|o| o.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The version recorded in the manifest, if any.
    pub fn version(&self) -> Option<&str> {
        self.manifest.get("version").and_then(|v| v.as_str())
    }
}

/// The record shape before the manifest was unified: the `plugin.json` as a
/// struct, plus the version-two manifest an Installation had written beside it.
/// Only read, never written; [`PluginMeta::from_bytes`] upgrades it.
#[derive(Deserialize)]
pub(crate) struct LegacyPluginMeta {
    pub subject: String,
    pub agent_secret: String,
    pub manifest: PluginManifest,
    #[serde(default)]
    pub manifest_v2: Option<serde_json::Value>,
}

impl From<LegacyPluginMeta> for PluginMeta {
    fn from(legacy: LegacyPluginMeta) -> Self {
        let manifest = legacy.manifest_v2.unwrap_or_else(|| {
            serde_json::to_value(&legacy.manifest).unwrap_or(serde_json::Value::Null)
        });
        Self {
            subject: legacy.subject,
            agent_secret: legacy.agent_secret,
            manifest,
            release_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetaKey {
    pub drive: String,
    pub name: String,
    pub namespace: String,
}

impl PluginMetaKey {
    pub fn new(drive: &str, namespace: &str, name: &str) -> Self {
        Self {
            drive: drive.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub name: String,
    pub namespace: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub permissions: Option<Vec<PermissionEntry>>,
    pub default_config: Option<HashMap<String, serde_json::Value>>,
    pub config_schema: Option<HashMap<String, serde_json::Value>>,
    /// Origins this plugin may reach through the host's `fetch`.
    ///
    /// Separate from the `network` permission, which only governs the guest's
    /// own sockets. Shown at install: "this plugin can talk to api.example.com"
    /// is a sentence someone can judge; "this plugin has network access" is not.
    pub network: Option<NetworkPermission>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPermission {
    /// Exact origins, e.g. `https://api.example.com`. No wildcards.
    #[serde(default)]
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub permission: PermissionType,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionType {
    Network,
    Storage,
    FullDriveAccess,
    ExtendedFuel,
    ExtendedMemory,
    CustomView,
}

impl PluginManifest {
    pub fn from_reader(reader: impl Read) -> Result<Self, AtomicError> {
        let manifest: Self = serde_json::from_reader(reader)
            .map_err(|e| AtomicError::from(format!("Failed to parse plugin manifest: {}", e)))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), AtomicError> {
        validate_plugin_identifiers(&self.namespace, &self.name)
    }

    pub fn has_permission(&self, permission: PermissionType) -> bool {
        if let Some(permissions) = &self.permissions {
            return permissions.iter().any(|p| p.permission == permission);
        }
        false
    }
}

/// Checks that a plugin `namespace` and `name` are safe to use as path components.
///
/// Both values end up in filesystem paths (`{namespace}.{name}.wasm`, `{namespace}/assets`),
/// so they must be a single, non-empty path segment: only ASCII alphanumerics, `-` and `_`.
/// This rejects path separators, `.` / `..` traversal, absolute paths and control characters.
///
/// Call this on every code path that turns user-controlled namespace/name values into paths,
/// not only when parsing a manifest.
pub fn validate_plugin_identifiers(namespace: &str, name: &str) -> Result<(), AtomicError> {
    for (field, value) in [("namespace", namespace), ("name", name)] {
        validate_plugin_identifier(field, value)?;
    }
    Ok(())
}

pub fn validate_plugin_identifier(field: &str, value: &str) -> Result<(), AtomicError> {
    const MAX_LEN: usize = 128;

    if value.is_empty() {
        return Err(AtomicError::from(format!("plugin {field} cannot be empty")));
    }
    if value.len() > MAX_LEN {
        return Err(AtomicError::from(format!(
            "plugin {field} cannot be longer than {MAX_LEN} characters"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AtomicError::from(format!(
            "plugin {field} '{value}' is invalid: only ASCII letters, digits, '-' and '_' are allowed"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_identifiers() {
        validate_plugin_identifiers("my-namespace", "my_plugin1").unwrap();
    }

    #[test]
    fn rejects_traversal_and_separators() {
        for bad in [
            "../../tmp",
            "..",
            ".",
            "a/b",
            "a\\b",
            "/tmp",
            "a.b",
            "",
            "with space",
            "nul\0byte",
        ] {
            assert!(
                validate_plugin_identifiers(bad, "ok").is_err(),
                "namespace {bad:?} should be rejected"
            );
            assert!(
                validate_plugin_identifiers("ok", bad).is_err(),
                "name {bad:?} should be rejected"
            );
        }
    }
}
