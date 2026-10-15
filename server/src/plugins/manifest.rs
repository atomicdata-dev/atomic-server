//! The declaration is evaluated with no host capabilities before execution.
//!
//! Version one makes public reads independent of credential storage.
//! Version two is the single manifest for both runtimes (`atomic-js/1` and
//! `wasip2/1`) and both worlds (`extension`, `server-extension`). A `plugin.json`
//! from a WASM zip is translated into it at the import boundary by
//! [`translate_plugin_json`]; version one upgrades into it with defaults.
//!
//! Serialization of an upgraded version-one manifest is byte-identical to its
//! version-one form: every version-two field is skipped when it holds its
//! default, and `schemaVersion` keeps the value it was parsed with. Releases are
//! content-addressed over the serialized manifest, so this must stay true.
use atomic_lib::db::plugin_meta::{validate_plugin_identifiers, PermissionType, PluginManifest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Runtime::is_default")]
    pub runtime: Runtime,
    #[serde(default, skip_serializing_if = "World::is_default")]
    pub world: World,
    #[serde(default, skip_serializing_if = "Entrypoints::is_default")]
    pub entrypoints: Entrypoints,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub secrets: Vec<Secret>,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<super::actions::Action>,
    /// Coarse egress allowance for packages that call the host `fetch` without
    /// an operation id. It never widens what `operations` grant.
    #[serde(default, skip_serializing_if = "Network::is_default")]
    pub network: Network,
    /// What the plugin's user-editable config looks like. The host validates
    /// the stored config against it before a run; nothing here grants access,
    /// so it is carried rather than interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_config: Option<serde_json::Map<String, serde_json::Value>>,
    /// Files the host may hand this plugin as `input.upload`. See [`Accept`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<Accept>,
    /// Where an importer writes: a schema and the tables (`table`, and/or
    /// keyed `tables`) the browser host creates before the first run and
    /// records as the plugin's config. It grants nothing and the server never
    /// acts on it, so it is carried verbatim (its bytes are part of the
    /// release id); [`validate_destination`] checks its shape the way the
    /// browser's `validateManifest` does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// The shape of a version-one declaration. Parsed strictly, then upgraded.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestV1 {
    schema_version: u32,
    #[serde(default)]
    secrets: Vec<Secret>,
    #[serde(default)]
    operations: Vec<Operation>,
    #[serde(default)]
    actions: Vec<super::actions::Action>,
    #[serde(default)]
    config: Option<serde_json::Value>,
}

impl From<ManifestV1> for Manifest {
    fn from(v1: ManifestV1) -> Self {
        Self {
            schema_version: v1.schema_version,
            runtime: Runtime::default(),
            world: World::default(),
            entrypoints: Entrypoints::default(),
            capabilities: Vec::new(),
            secrets: v1.secrets,
            operations: v1.operations,
            actions: v1.actions,
            network: Network::default(),
            config: v1.config,
            config_schema: None,
            default_config: None,
            accepts: Vec::new(),
            destination: None,
            name: None,
            namespace: None,
            version: None,
            description: None,
            author: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum Runtime {
    #[default]
    #[serde(rename = "atomic-js/1")]
    AtomicJs1,
    #[serde(rename = "wasip2/1")]
    Wasip2v1,
}

impl Runtime {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The trust boundary, independent of the language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum World {
    /// Exports `run`; proposes effects; user-installable.
    #[default]
    Extension,
    /// Exports the class-extender hooks and may write; operator-installed.
    ServerExtension,
}

impl World {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entrypoints {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub run: bool,
    /// Package-relative path of the custom view module. Needs `custom-view`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
    /// Class URLs whose hooks this package exports. Only in `server-extension`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_extender: Option<Vec<String>>,
}

/// When a manifest names no entrypoints it exports `run`, as version one did.
impl Default for Entrypoints {
    fn default() -> Self {
        Self {
            run: true,
            view: None,
            class_extender: None,
        }
    }
}

impl Entrypoints {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn class_urls(&self) -> &[String] {
        self.class_extender.as_deref().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityName {
    Storage,
    FullDriveAccess,
    ExtendedFuel,
    ExtendedMemory,
    CustomView,
    /// A custom view may change the classes and properties of what it shows
    /// (their ontology) without asking each time. Enforced by the view host.
    EditSchema,
}

impl CapabilityName {
    pub const ALL: [CapabilityName; 6] = [
        Self::Storage,
        Self::FullDriveAccess,
        Self::ExtendedFuel,
        Self::ExtendedMemory,
        Self::CustomView,
        Self::EditSchema,
    ];

    /// The kebab-case name, as it appears in manifests and grants.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::FullDriveAccess => "full-drive-access",
            Self::ExtendedFuel => "extended-fuel",
            Self::ExtendedMemory => "extended-memory",
            Self::CustomView => "custom-view",
            Self::EditSchema => "edit-schema",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// The capability a `plugin.json` permission translates to. `network` is not
/// a capability: it becomes `network.origins`.
pub fn permission_capability(permission: PermissionType) -> Option<CapabilityName> {
    Some(match permission {
        PermissionType::Network => return None,
        PermissionType::Storage => CapabilityName::Storage,
        PermissionType::FullDriveAccess => CapabilityName::FullDriveAccess,
        PermissionType::ExtendedFuel => CapabilityName::ExtendedFuel,
        PermissionType::ExtendedMemory => CapabilityName::ExtendedMemory,
        PermissionType::CustomView => CapabilityName::CustomView,
    })
}

/// The capabilities a `plugin.json` declares, with their reasons, without
/// translating the whole manifest. This is what a legacy zip's permissions
/// mean in version-two terms; [`translate_plugin_json`] uses the same mapping.
pub fn plugin_json_capabilities(plugin_json: &PluginManifest) -> Vec<Capability> {
    plugin_json
        .permissions
        .iter()
        .flatten()
        .filter_map(|entry| {
            permission_capability(entry.permission).map(|name| Capability {
                name,
                reason: Some(entry.reason.clone()).filter(|r| !r.is_empty()),
            })
        })
        .collect()
}

/// A capability, written either as `"storage"` or as
/// `{"name": "storage", "reason": "..."}`. The reason is the review text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub name: CapabilityName,
    pub reason: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityObject {
    name: CapabilityName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Name(CapabilityName),
            Object(CapabilityObject),
        }
        Ok(
            match Raw::deserialize(deserializer).map_err(|_| {
                serde::de::Error::custom("capability must be a known name or {name, reason}")
            })? {
                Raw::Name(name) => Self { name, reason: None },
                Raw::Object(CapabilityObject { name, reason }) => Self { name, reason },
            },
        )
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.reason {
            None => self.name.serialize(serializer),
            Some(reason) => CapabilityObject {
                name: self.name,
                reason: Some(reason.clone()),
            }
            .serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    /// Exact origins, e.g. `https://api.example.com`. No wildcards.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Network {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    pub name: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Used when an `accepts` entry declares no `maxBytes`: 5 MiB.
pub const DEFAULT_ACCEPT_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// The largest `maxBytes` a plugin may declare: 20 MiB. The file is held
/// several times over during a run (request body, host string, sandbox string,
/// parse output), so this stays well under the sandbox's 256 MiB default.
pub const ACCEPT_MAX_BYTES_CEILING: u64 = 20 * 1024 * 1024;

/// A file the host may hand the plugin as `input.upload`, instead of the
/// plugin fetching data itself. `extensions` and `mediaTypes` only filter the
/// picker; the plugin still validates what it is given. Only `as: "text"`
/// exists: UTF-8, falling back to Windows-1252, decoded by the host.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Accept {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media_types: Vec<String>,
    #[serde(rename = "as")]
    pub read_as: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

impl Accept {
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.unwrap_or(DEFAULT_ACCEPT_MAX_BYTES)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub method: String,
    /// Exact endpoint; query parameters may vary. No wildcard hosts or paths.
    pub url: String,
    pub effect: String,
}

impl Manifest {
    pub fn parse(raw: serde_json::Value) -> Result<Option<Self>, String> {
        // Legacy drafts have no version and receive only legacy GET/HEAD access.
        let Some(version) = raw.get("schemaVersion") else {
            return Ok(None);
        };
        if raw
            .get("secrets")
            .and_then(|v| v.as_array())
            .is_some_and(|secrets| {
                secrets.iter().any(|secret| {
                    secret
                        .get("description")
                        .is_some_and(|description| !description.is_string())
                })
            })
        {
            return Err("secret description must be text".into());
        }
        let manifest: Self = match version.as_u64() {
            Some(1) => serde_json::from_value::<ManifestV1>(raw)
                .map_err(|e| e.to_string())?
                .into(),
            Some(2) => serde_json::from_value(raw).map_err(|e| e.to_string())?,
            _ => return Err("unsupported manifest schemaVersion".into()),
        };
        manifest.validate()?;
        Ok(Some(manifest))
    }

    fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        for secret in &self.secrets {
            if secret.name.is_empty() || !names.insert(&secret.name) {
                return Err("secret names must be nonempty and unique".into());
            }
            exact_origin(&secret.origin, "secret origin")?;
        }
        names.clear();
        for operation in &self.operations {
            if operation.id.is_empty() || !names.insert(&operation.id) {
                return Err("operation IDs must be nonempty and unique".into());
            }
            endpoint(&operation.url)?;
            if !matches!(
                operation.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
            ) {
                return Err("operation has an unsupported HTTP method".into());
            }
            if !matches!(operation.effect.as_str(), "read" | "write") {
                return Err("operation effect must be read or write".into());
            }
        }
        super::actions::validate_actions(self)?;
        names.clear();
        for origin in &self.network.origins {
            exact_origin(origin, "network origin")?;
            if !names.insert(origin) {
                return Err("network origins must be unique".into());
            }
        }
        let mut capabilities = std::collections::HashSet::new();
        for capability in &self.capabilities {
            if !capabilities.insert(capability.name) {
                return Err("capabilities must be unique".into());
            }
        }
        let class_urls = self.entrypoints.class_urls();
        if self.entrypoints.class_extender.is_some() && class_urls.is_empty() {
            return Err("classExtender must list at least one class URL".into());
        }
        names.clear();
        for class in class_urls {
            let url = url::Url::parse(class).map_err(|e| e.to_string())?;
            if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                return Err("classExtender entries must be class URLs".into());
            }
            if !names.insert(class) {
                return Err("classExtender entries must be unique".into());
            }
        }
        match self.world {
            World::Extension if !class_urls.is_empty() => {
                return Err("world extension may not declare classExtender".into());
            }
            World::ServerExtension
                if self.runtime != Runtime::Wasip2v1 && class_urls.is_empty() =>
            {
                return Err(
                    "world server-extension requires runtime wasip2/1 or entrypoints.classExtender"
                        .into(),
                );
            }
            _ => {}
        }
        if let Some(view) = &self.entrypoints.view {
            if view.is_empty()
                || view.starts_with('/')
                || view.contains('\\')
                || view
                    .split('/')
                    .any(|segment| segment.is_empty() || segment == "..")
            {
                return Err("view entrypoint must be a package-relative path".into());
            }
            if !self.has_capability(CapabilityName::CustomView) {
                return Err("view entrypoint requires the custom-view capability".into());
            }
        }
        // Only a view's host enforces it, so without a view it would be a
        // grant that reads as power and does nothing.
        if self.has_capability(CapabilityName::EditSchema)
            && !self.has_capability(CapabilityName::CustomView)
        {
            return Err("edit-schema requires the custom-view capability".into());
        }
        if self.accepts.len() > 8 {
            return Err("at most 8 accepts entries".into());
        }
        for accept in &self.accepts {
            if accept.read_as != "text" {
                return Err("accepts entries must be read `as` text".into());
            }
            if accept
                .max_bytes
                .is_some_and(|max| !(1..=ACCEPT_MAX_BYTES_CEILING).contains(&max))
            {
                return Err(format!(
                    "accepts maxBytes must be a whole number from 1 to {ACCEPT_MAX_BYTES_CEILING}"
                ));
            }
            let lower_ext = |c: char| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            };
            if accept.extensions.iter().any(|ext| {
                ext.len() < 2
                    || ext.len() > 33
                    || !ext.starts_with('.')
                    || !ext[1..].starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    || !ext.chars().all(lower_ext)
            }) {
                return Err("accepts extensions must be lower-case and start with a dot".into());
            }
            let token = |part: &str| {
                part.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && part.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | '-')
                    })
            };
            if accept.media_types.iter().any(|media| {
                !media
                    .split_once('/')
                    .is_some_and(|(kind, sub)| token(kind) && token(sub))
            }) {
                return Err("accepts mediaTypes must be type/subtype".into());
            }
        }
        if let Some(destination) = &self.destination {
            validate_destination(destination)?;
        }
        if let Some(namespace) = &self.namespace {
            validate_plugin_identifiers(namespace, "name").map_err(|e| e.to_string())?;
        }
        if let Some(name) = &self.name {
            validate_plugin_identifiers("namespace", name).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn has_capability(&self, name: CapabilityName) -> bool {
        self.capabilities.iter().any(|c| c.name == name)
    }

    /// Whether the coarse `network.origins` allowance covers this URL.
    /// Orthogonal to [`Self::allows_effect`]: an operation is never implied by an origin.
    pub fn allows_origin(&self, url: &url::Url) -> bool {
        self.network
            .origins
            .contains(&url.origin().ascii_serialization())
    }

    pub fn allows_read(&self, id: Option<&str>, method: &str, url: &url::Url) -> bool {
        self.allows_effect(id, method, url, "read")
    }

    pub fn allows_effect(
        &self,
        id: Option<&str>,
        method: &str,
        url: &url::Url,
        effect: &str,
    ) -> bool {
        self.operations.iter().any(|operation| {
            let Ok(endpoint) = endpoint(&operation.url) else {
                return false;
            };
            id == Some(operation.id.as_str())
                && operation.method == method
                && operation.effect == effect
                && endpoint.origin() == url.origin()
                && matches_path(endpoint.path(), url.path())
        })
    }
}

/// Translates a WASM zip's `plugin.json` into the version-two manifest.
///
/// `class_urls` is what the component's `class-url` export returns; `plugin.json`
/// alone does not say which classes a package extends. A package that extends
/// classes is a `server-extension` (its hooks run inside reads and commits); a
/// package that extends none is an `extension` exporting `run`.
///
/// `permissions` become `capabilities` with their reasons kept. The `network`
/// permission is not a capability: it becomes `network.origins`, and declaring
/// it without any origin is an error, since an undeclared destination cannot
/// be reviewed.
pub fn translate_plugin_json(
    plugin_json: &PluginManifest,
    class_urls: &[String],
) -> Result<Manifest, String> {
    let permissions = plugin_json.permissions.as_deref().unwrap_or_default();
    let origins = plugin_json
        .network
        .as_ref()
        .map(|n| n.origins.clone())
        .unwrap_or_default();
    let mut capabilities = Vec::new();
    let mut network_reason = None;
    for entry in permissions {
        let reason = Some(entry.reason.clone()).filter(|r| !r.is_empty());
        let Some(name) = permission_capability(entry.permission) else {
            if origins.is_empty() {
                return Err("network permission requires network.origins".into());
            }
            network_reason = reason;
            continue;
        };
        capabilities.push(Capability { name, reason });
    }
    // Sorted so the translated form, and any release id over it, is deterministic.
    let sorted = |map: &std::collections::HashMap<String, serde_json::Value>| {
        let mut entries: Vec<_> = map.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        entries
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<serde_json::Map<_, _>>()
    };
    let manifest = Manifest {
        schema_version: 2,
        runtime: Runtime::Wasip2v1,
        world: if class_urls.is_empty() {
            World::Extension
        } else {
            World::ServerExtension
        },
        entrypoints: Entrypoints {
            run: class_urls.is_empty(),
            view: None,
            class_extender: (!class_urls.is_empty()).then(|| class_urls.to_vec()),
        },
        capabilities,
        secrets: Vec::new(),
        operations: Vec::new(),
        actions: Vec::new(),
        network: Network {
            origins,
            reason: network_reason,
        },
        config: None,
        config_schema: plugin_json.config_schema.as_ref().map(sorted),
        default_config: plugin_json.default_config.as_ref().map(sorted),
        accepts: Vec::new(),
        destination: None,
        name: Some(plugin_json.name.clone()),
        namespace: Some(plugin_json.namespace.clone()),
        version: Some(plugin_json.version.clone()),
        description: plugin_json.description.clone(),
        author: plugin_json.author.clone(),
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Typed parameters admit only positive decimal IDs or hyphenated UUIDs.
/// No globbing, repository substitution, encoded slashes or traversal.
fn matches_path(pattern: &str, actual: &str) -> bool {
    let p: Vec<_> = pattern.split('/').collect();
    let a: Vec<_> = actual.split('/').collect();
    p.len() == a.len()
        && p.iter().zip(a).all(|(p, a)| {
            if *p == "%7Bnumber%7D" || *p == "{number}" {
                !a.is_empty() && !a.starts_with('0') && a.bytes().all(|c| c.is_ascii_digit())
            } else if *p == "%7Buuid%7D" || *p == "{uuid}" {
                a.len() == 36
                    && a.bytes().enumerate().all(|(i, c)| {
                        if matches!(i, 8 | 13 | 18 | 23) {
                            c == b'-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    })
            } else {
                *p == a
            }
        })
}

fn endpoint(value: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(value).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(
            "operation URLs must be HTTP endpoints without credentials, query or fragment".into(),
        );
    }
    Ok(url)
}

/// A class or property shortname: lower-case letters and digits in
/// dash-separated groups.
fn is_shortname(value: &str) -> bool {
    value.split('-').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

/// A `destination.tables` key, read back by the plugin as `config.tables.<key>`:
/// a lower-case letter, then letters and digits, at most 64. Keys that would
/// shadow an `Object.prototype` member in the plugin are refused.
fn is_table_key(value: &str) -> bool {
    const RESERVED: [&str; 7] = [
        "constructor",
        "hasOwnProperty",
        "isPrototypeOf",
        "propertyIsEnumerable",
        "toLocaleString",
        "toString",
        "valueOf",
    ];
    value.len() <= 64
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value.chars().all(|c| c.is_ascii_alphanumeric())
        && !RESERVED.contains(&value)
}

/// Checks a manifest's `destination` with the rules, and the messages, of
/// `validateDestination` in `browser/lib/src/plugin-manifest.ts`. Both are
/// held to `testdata/plugin-manifest/index.json`.
fn validate_destination(entry: &serde_json::Value) -> Result<(), String> {
    use serde_json::{Map, Value};
    use std::collections::HashSet;

    fn fail(message: &str) -> String {
        format!("destination: {message}")
    }
    fn object<'a>(
        value: Option<&'a Value>,
        keys: Option<&[&str]>,
    ) -> Result<&'a Map<String, Value>, String> {
        let Some(Value::Object(map)) = value else {
            return Err(fail("expected a map"));
        };
        if let Some(keys) = keys {
            if let Some(key) = map.keys().find(|key| !keys.contains(&key.as_str())) {
                return Err(fail(&format!("unknown field `{key}`")));
            }
        }
        Ok(map)
    }
    fn text(value: Option<&Value>, what: &str) -> Result<String, String> {
        match value {
            Some(Value::String(text))
                if !text.trim().is_empty() && text.encode_utf16().count() <= 1024 =>
            {
                Ok(text.clone())
            }
            _ => Err(fail(&format!("{what} must be nonempty text"))),
        }
    }
    fn shortnames(value: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
        let Some(value) = value else {
            return Ok(Vec::new());
        };
        let Value::Array(items) = value else {
            return Err(fail(&format!("{what} must be a list")));
        };
        items
            .iter()
            .map(|item| match item {
                Value::String(name) if is_shortname(name) => Ok(name.clone()),
                _ => Err(fail(&format!("{what} must list shortnames"))),
            })
            .collect()
    }

    let entry = object(Some(entry), Some(&["schema", "table", "tables"]))?;
    let schema = object(entry.get("schema"), Some(&["properties", "classes"]))?;
    let (Some(Value::Array(properties)), Some(Value::Array(classes))) =
        (schema.get("properties"), schema.get("classes"))
    else {
        return Err(fail("schema needs properties and classes lists"));
    };

    let mut known = HashSet::new();
    for raw in properties {
        let property = object(
            Some(raw),
            Some(&["shortname", "name", "description", "datatype"]),
        )?;
        let shortname = text(property.get("shortname"), "property shortname")?;
        if !is_shortname(&shortname) {
            return Err(fail(&format!("invalid shortname {shortname}")));
        }
        let datatype = text(property.get("datatype"), "property datatype")?;
        let supported = datatype
            .strip_prefix("https://atomicdata.dev/datatypes/")
            .is_some_and(|name| !name.is_empty() && name.chars().all(|c| c.is_ascii_alphabetic()));
        if !supported {
            return Err(fail(&format!("unsupported datatype {datatype}")));
        }
        text(property.get("name"), "property name")?;
        text(property.get("description"), "property description")?;
        known.insert(shortname);
    }
    if known.len() != properties.len() || known.len() > 64 {
        return Err(fail("property shortnames must be unique, at most 64"));
    }

    let mut class_names = HashSet::new();
    for raw in classes {
        let class = object(
            Some(raw),
            Some(&["shortname", "name", "description", "requires", "recommends"]),
        )?;
        let shortname = text(class.get("shortname"), "class shortname")?;
        if !is_shortname(&shortname) {
            return Err(fail(&format!("invalid shortname {shortname}")));
        }
        let requires = shortnames(class.get("requires"), "requires")?;
        let recommends = shortnames(class.get("recommends"), "recommends")?;
        if requires
            .iter()
            .chain(&recommends)
            .any(|name| !known.contains(name))
        {
            return Err(fail(&format!(
                "class {shortname} names an undeclared property"
            )));
        }
        text(class.get("name"), "class name")?;
        text(class.get("description"), "class description")?;
        class_names.insert(shortname);
    }
    if classes.is_empty() || classes.len() > 8 || class_names.len() != classes.len() {
        return Err(fail("declare one to eight uniquely named classes"));
    }

    // Checks one declared table and returns its row class.
    let table = |raw: &Value| -> Result<String, String> {
        let declared = object(Some(raw), Some(&["name", "rowClass", "columns"]))?;
        let row_class = text(declared.get("rowClass"), "table rowClass")?;
        if !class_names.contains(&row_class) {
            return Err(fail("table rowClass must name a class in schema"));
        }
        let columns = shortnames(declared.get("columns"), "table columns")?;
        if columns.iter().any(|name| !known.contains(name)) {
            return Err(fail("table columns must name properties in schema"));
        }
        text(declared.get("name"), "table name")?;
        Ok(row_class)
    };

    if entry.get("table").is_none() && entry.get("tables").is_none() {
        return Err(fail("declare `table` or `tables`"));
    }
    let mut row_classes = Vec::new();
    if let Some(primary) = entry.get("table") {
        row_classes.push(table(primary)?);
    }
    if let Some(tables) = entry.get("tables") {
        let tables = object(Some(tables), None)?;
        if tables.is_empty() {
            return Err(fail("tables must not be empty"));
        }
        for (key, declared) in tables {
            if !is_table_key(key) {
                return Err(fail(
                    "table keys must be identifiers of letters and digits starting with a lower-case letter, at most 64",
                ));
            }
            row_classes.push(table(declared)?);
        }
    }
    if row_classes.iter().collect::<HashSet<_>>().len() != row_classes.len() {
        return Err(fail("each table needs its own rowClass"));
    }
    Ok(())
}

fn exact_origin(value: &str, what: &str) -> Result<(), String> {
    let parsed = endpoint(value)?;
    if parsed.origin().ascii_serialization() != value {
        return Err(format!("{what} must be an exact HTTP origin"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/plugin-manifest");

    fn fixture(name: &str) -> serde_json::Value {
        let path = format!("{FIXTURES}/{name}");
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{path}: {e}");
        }))
        .unwrap()
    }

    /// Checking `destination` more strictly must not move a release id: the
    /// declaration is carried verbatim. The single-table id is the one
    /// `release-ids.json` pins on the atomic-plugins pin branch.
    #[test]
    fn destination_fixtures_keep_their_release_ids() {
        for (file, pinned) in [
            (
                "v2-accepts-destination.json",
                "blake3:4d41ebf175cb12e05339b85698a8d9b91485523728826485025af20c51ace3ea",
            ),
            (
                "v2-destination-tables.json",
                "blake3:7ac2291a55e8bbe11c26bc0ce413173b3527e85505dbdd7d9f9fd167afeb421d",
            ),
            (
                "v2-destination-tables-only.json",
                "blake3:ed8b010912f877717c191a10dd2975c2bb216f8108dc832a88e79571d3d9ed63",
            ),
        ] {
            let manifest = Manifest::parse(fixture(file)).unwrap().unwrap();
            assert_eq!(
                manifest.destination.as_ref(),
                fixture(file).get("destination"),
                "{file}"
            );
            let id = atomic_lib::db::plugin_release::PluginRelease::js(
                "export function run() {}".into(),
                serde_json::json!(manifest),
                Default::default(),
            )
            .id()
            .unwrap();
            assert_eq!(id, pinned, "{file}");
        }
    }

    #[test]
    fn shared_manifest_conformance() {
        for case in fixture("index.json").as_array().unwrap() {
            let name = &case["name"];
            let result = Manifest::parse(fixture(case["file"].as_str().unwrap()));
            match case["error"].as_str() {
                None => {
                    let manifest = result.unwrap_or_else(|e| panic!("{name}: {e}")).unwrap();
                    if let Some(expected) = case.get("serialized") {
                        assert_eq!(&serde_json::json!(manifest), expected, "{name}");
                    }
                }
                Some(expected) => {
                    let error = result.expect_err(&format!("{name} should be rejected"));
                    assert!(
                        error.contains(expected),
                        "{name}: {error:?} lacks {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn serialization_of_an_upgraded_v1_manifest_is_unchanged() {
        // Releases are content-addressed over this form.
        let raw = fixture("v1-github-issues.json");
        let manifest = Manifest::parse(raw.clone()).unwrap().unwrap();
        assert_eq!(manifest.runtime, Runtime::AtomicJs1);
        assert_eq!(manifest.world, World::Extension);
        assert!(manifest.entrypoints.run);
        assert_eq!(serde_json::json!(manifest), raw);
    }

    #[test]
    fn v2_round_trips_through_serialization() {
        for file in ["v2-js-extension.json", "v2-wasm-server-extension.json"] {
            let raw = fixture(file);
            let manifest = Manifest::parse(raw.clone()).unwrap().unwrap();
            let again = Manifest::parse(serde_json::json!(manifest))
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::json!(again),
                serde_json::json!(manifest),
                "{file}"
            );
        }
    }

    #[test]
    fn plugin_json_translates_to_v2() {
        for case in fixture("translations.json").as_array().unwrap() {
            let name = &case["name"];
            let plugin_json: PluginManifest =
                serde_json::from_value(fixture(case["pluginJson"].as_str().unwrap())).unwrap();
            let classes: Vec<String> =
                serde_json::from_value(case["classUrls"].clone()).unwrap_or_default();
            let result = translate_plugin_json(&plugin_json, &classes);
            match case["error"].as_str() {
                None => {
                    let manifest = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    let expected = fixture(case["expected"].as_str().unwrap());
                    assert_eq!(serde_json::json!(manifest), expected, "{name}");
                    Manifest::parse(expected).unwrap().unwrap();
                }
                Some(expected) => {
                    let error = result.expect_err(&format!("{name} should be rejected"));
                    assert!(
                        error.contains(expected),
                        "{name}: {error:?} lacks {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn network_origins_never_widen_operations() {
        let manifest = Manifest::parse(serde_json::json!({
            "schemaVersion": 2,
            "network": {"origins": ["https://api.test"]},
            "operations": [
                {"id":"list","method":"GET","url":"https://other.test/items","effect":"read"}
            ]
        }))
        .unwrap()
        .unwrap();
        let api = url::Url::parse("https://api.test/anything").unwrap();
        assert!(manifest.allows_origin(&api));
        assert!(!manifest.allows_read(Some("list"), "GET", &api));
        assert!(!manifest.allows_origin(&url::Url::parse("https://other.test/items").unwrap()));
    }

    #[test]
    fn public_read_is_declared_without_a_secret_and_write_cannot_run_in_preview() {
        let manifest = Manifest::parse(serde_json::json!({"schemaVersion":1,"operations":[
            {"id":"list","method":"POST","url":"https://api.test/query","effect":"read"},
            {"id":"delete","method":"DELETE","url":"https://api.test/records","effect":"write"}
        ]}))
        .unwrap()
        .unwrap();
        assert!(manifest.allows_read(
            Some("list"),
            "POST",
            &url::Url::parse("https://api.test/query?page=2").unwrap()
        ));
        assert!(!manifest.allows_read(
            Some("list"),
            "POST",
            &url::Url::parse("https://api.test/admin").unwrap()
        ));
        assert!(!manifest.allows_read(
            Some("delete"),
            "DELETE",
            &url::Url::parse("https://api.test/records").unwrap()
        ));
    }
}

#[cfg(test)]
mod path_tests {
    use super::matches_path;
    #[test]
    fn uuid_paths_are_single_canonical_segments() {
        let pattern = "/v1/pages/%7Buuid%7D";
        assert!(matches_path(
            pattern,
            "/v1/pages/3d3236d2-7bda-80a2-a77a-000b0adec99f"
        ));
        for path in [
            "/v1/pages/3d3236d27bda80a2a77a000b0adec99f",
            "/v1/pages/3d3236d2-7bda-80a2-a77a-000b0adec99g",
            "/v1/pages/3d3236d2-7bda-80a2-a77a-000b0adec99f/comments",
            "/v1/pages/%2e%2e",
            "/v1/pages/..",
            "/v1/users/3d3236d2-7bda-80a2-a77a-000b0adec99f",
        ] {
            assert!(!matches_path(pattern, path), "{path}");
        }
    }
    #[test]
    fn numeric_paths_cannot_escape_the_declared_repository() {
        let pattern = "/repos/owner/repo/issues/%7Bnumber%7D";
        assert!(matches_path(pattern, "/repos/owner/repo/issues/123"));
        for path in [
            "/repos/owner/other/issues/123",
            "/repos/owner/repo/issues/0",
            "/repos/owner/repo/issues/-1",
            "/repos/owner/repo/issues/1/comments",
            "/repos/owner/repo/issues/%31",
            "/repos/owner/repo/issues/..",
        ] {
            assert!(!matches_path(pattern, path));
        }
    }
}
