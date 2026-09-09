use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

use crate::AtomicError;

#[derive(Serialize, Deserialize)]
pub struct PluginMeta {
    pub subject: String,
    pub agent_secret: String,
    pub manifest: PluginManifest,
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
    /// own sockets. Shown at install: "this plugin can talk to api.notion.com"
    /// is a sentence someone can judge; "this plugin has network access" is not.
    pub network: Option<NetworkPermission>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPermission {
    /// Exact origins, e.g. `https://api.notion.com`. No wildcards.
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
    /// Whether this plugin declared the origin it is trying to reach.
    pub fn allows_origin(&self, origin: &str) -> bool {
        self.network
            .as_ref()
            .is_some_and(|n| n.origins.iter().any(|o| o == origin))
    }

    pub fn from_string(string: &str) -> Result<Self, AtomicError> {
        let manifest: Self = serde_json::from_str(string)
            .map_err(|e| AtomicError::from(format!("Failed to parse plugin manifest: {}", e)))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_reader(reader: impl Read) -> Result<Self, AtomicError> {
        let manifest: Self = serde_json::from_reader(reader)
            .map_err(|e| AtomicError::from(format!("Failed to parse plugin manifest: {}", e)))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn option_has_permission(
        manifest: Option<&PluginManifest>,
        permission: PermissionType,
    ) -> bool {
        let Some(manifest) = manifest else {
            return false;
        };

        manifest.has_permission(permission)
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
