//! The one host behind every sandboxed plugin.
//!
//! Two guest contracts run on the server — the class extender (a wasip2
//! component that participates in reads and commits) and the JS `run` plugin
//! (QuickJS inside a wasip2 component, which only proposes) — but they share a
//! sandbox and, since this module, a host. Everything security-relevant that
//! both need lives here exactly once: which agent a read is authorized for,
//! which origins a fetch may reach, where a secret may be substituted, how
//! large a response may grow, and who may commit.
//!
//! `wasm.rs` and `js_runtime.rs` keep only what differs: the WIT bindings and
//! the component lifecycle. They translate their guest's types into the calls
//! below and back, and nothing else.

use std::sync::{Arc, OnceLock};

use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::ClassExtenderScope,
    commit::{CommitBuilder, CommitOpts},
    hierarchy,
    storelike::{Query, ResourceResponse},
    urls, Commit, Db, Resource, Storelike, Subject, Value,
};
use futures::{Stream, StreamExt};
use wasmtime::{Engine, Store, StoreLimits, StoreLimitsBuilder};

use super::{
    egress,
    manifest::{CapabilityName, Manifest},
};

// ---------------------------------------------------------------------------
// Engine and resource limits
// ---------------------------------------------------------------------------

/// The one wasmtime engine, shared by every runtime in the process.
///
/// A component can only be instantiated by the engine that compiled it, so
/// the class-extender loader, the zip installer and the JS runtime all have to
/// agree on one. Building it once also means one place for its configuration.
pub fn engine() -> Result<Arc<Engine>, String> {
    static ENGINE: OnceLock<Result<Arc<Engine>, String>> = OnceLock::new();

    ENGINE
        .get_or_init(|| {
            let mut config = wasmtime::Config::new();
            config.wasm_component_model(true);
            config.consume_fuel(true);

            Engine::new(&config)
                .map(Arc::new)
                .map_err(|e| format!("could not create a wasm engine: {e}"))
        })
        .clone()
}

/// Which guest is being metered. The two have different baselines: a class
/// extender runs inside every read of its class and must be cheap; a JS run
/// is one job with an interpreter to feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    ClassExtender,
    Js,
}

/// The capabilities that widen a plugin's resource budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceGrants {
    pub extended_fuel: bool,
    pub extended_memory: bool,
}

impl ResourceGrants {
    /// The one derivation: which of the version-two capabilities are present.
    /// Every other constructor maps its input onto capability names first.
    pub fn from_capabilities(names: impl IntoIterator<Item = CapabilityName>) -> Self {
        let mut grants = Self::default();
        for name in names {
            match name {
                CapabilityName::ExtendedFuel => grants.extended_fuel = true,
                CapabilityName::ExtendedMemory => grants.extended_memory = true,
                _ => {}
            }
        }
        grants
    }

    /// A manifest's declared capabilities, for a plugin that has no
    /// Installation to read approved grants from (a global extension, or a
    /// class extender whose grants equal its declaration by construction).
    pub fn from_v2(manifest: Option<&Manifest>) -> Self {
        Self::from_capabilities(
            manifest
                .into_iter()
                .flat_map(|m| m.capabilities.iter())
                .map(|c| c.name),
        )
    }

    /// The `grants` an Installation stores: a JSON array of capability names
    /// (or an object keyed by them). Names that are not capabilities grant
    /// nothing; `check_grants` already refused them at install time.
    pub fn from_grants(grants: &serde_json::Value) -> Self {
        let names: Vec<&str> = match grants {
            serde_json::Value::Array(items) => items.iter().filter_map(|v| v.as_str()).collect(),
            serde_json::Value::Object(map) => map.keys().map(String::as_str).collect(),
            _ => Vec::new(),
        };
        Self::from_capabilities(names.into_iter().filter_map(CapabilityName::parse))
    }
}

/// One run's worth of resources. Nothing survives to the next run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub fuel: u64,
    pub memory_bytes: usize,
    /// How often a fuel-consuming guest yields to the async executor, so a
    /// hook inside a read cannot monopolize a worker. `None` runs to completion.
    pub yield_interval: Option<u64>,
}

const MIB: usize = 1024 * 1024;

/// The fuel and memory policy, keyed by runtime and capability.
///
/// Class extenders: 100M instructions and 50 MiB, or 1G and 2000 MiB with the
/// `extended-fuel` / `extended-memory` capabilities. JS runs: 20G instructions
/// and 256 MiB, or 200G and 2000 MiB with the same capabilities, which reach a
/// JS run through its Installation's grants ([`PluginHost::resource_grants`]).
pub fn limits(runtime: Runtime, grants: ResourceGrants) -> Limits {
    match runtime {
        Runtime::ClassExtender => Limits {
            fuel: if grants.extended_fuel {
                1_000_000_000
            } else {
                100_000_000
            },
            memory_bytes: if grants.extended_memory {
                2000 * MIB
            } else {
                50 * MIB
            },
            yield_interval: Some(10_000),
        },
        Runtime::Js => Limits {
            fuel: if grants.extended_fuel {
                200_000_000_000
            } else {
                20_000_000_000
            },
            memory_bytes: if grants.extended_memory {
                2000 * MIB
            } else {
                256 * MIB
            },
            yield_interval: None,
        },
    }
}

impl Limits {
    pub fn store_limits(&self) -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(self.memory_bytes)
            .build()
    }

    /// Applies the fuel side of the policy to a store. Memory goes through
    /// [`Limits::store_limits`] and the store's limiter.
    pub fn meter<T>(&self, store: &mut Store<T>) -> Result<(), String> {
        store
            .set_fuel(self.fuel)
            .map_err(|e| format!("could not meter the plugin: {e}"))?;
        store
            .fuel_async_yield_interval(self.yield_interval)
            .map_err(|e| format!("could not meter the plugin: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The JS-facing trait
// ---------------------------------------------------------------------------

/// What the host will do on a JS plugin's behalf.
///
/// A trait rather than a concrete type so the guards can be tested without a
/// store, and so a future placement (a CLI, a test harness) can supply its own.
/// The production implementation is `js_runtime::StoreHost`, a thin delegate
/// to [`HostCore`].
#[async_trait::async_trait]
pub trait PluginHost: Send + 'static {
    async fn invoke_action(
        &mut self,
        _: String,
        _: &str,
        _: bool,
        _: Option<&str>,
    ) -> Result<String, String> {
        Err("integration actions are not available in this context".into())
    }
    async fn fetch(&mut self, request: String) -> Result<String, String>;
    async fn get_resource(&mut self, subject: String) -> Result<String, String>;
    async fn query(&mut self, property: String, value: String) -> Result<String, String>;
    /// The capabilities that widen this run's fuel and memory. Read before the
    /// store is built, so they can come from the Installation the plugin runs
    /// under. A host without one gets the baseline.
    async fn resource_grants(&mut self) -> ResourceGrants {
        ResourceGrants::default()
    }
}

/// The resource grants of a JS plugin: the approved `grants` of the
/// Installation it runs under, or, for a legacy draft that has no Installation
/// at all, what its own manifest declares.
///
/// Those are the only two answers. Once a run is known to belong to an
/// Installation, every way of failing to read its grants yields nothing
/// granted, never the declared set: the declared set is what the plugin asked
/// for, and handing it over because a lookup went wrong would be the one case
/// where asking for more than was approved pays off. `check_grants` makes the
/// two sets equal at install time, so a healthy installation loses nothing by
/// this; an unreadable or half-written one runs with no resource grants and
/// says so in the log. The run's reads are guarded separately by [`Grant`].
pub async fn installation_grants(
    db: &Db,
    drive: &str,
    plugin: &str,
    manifest: Option<&Manifest>,
) -> ResourceGrants {
    // No Installation: a legacy draft, which never had grants of its own.
    let Ok(installation) = super::installation::resolve(db, drive, plugin).await else {
        return ResourceGrants::from_v2(manifest);
    };
    let Some(key) = installation.signing_as else {
        return ResourceGrants::from_v2(manifest);
    };
    let Ok(resource) = db.get_resource(&key.app.as_str().into()).await else {
        tracing::warn!(
            "installation {} of {drive} cannot be read; running {plugin} with no resource grants",
            key.app
        );
        return ResourceGrants::default();
    };
    if !resource.has_class(urls::INSTALLATION) {
        return ResourceGrants::from_v2(manifest);
    }
    match resource.get(urls::GRANTS) {
        Ok(Value::Json(grants)) => ResourceGrants::from_grants(grants),
        // A client that pinned no datatype writes the JSON as a string.
        Ok(Value::String(s)) => match serde_json::from_str(s) {
            Ok(grants) => ResourceGrants::from_grants(&grants),
            Err(e) => {
                tracing::warn!(
                    "installation {} has grants that are not JSON ({e}); running {plugin} with no resource grants",
                    resource.get_subject()
                );
                ResourceGrants::default()
            }
        },
        Ok(other) => {
            tracing::warn!(
                "installation {} has grants of an unexpected shape ({other}); running {plugin} with no resource grants",
                resource.get_subject()
            );
            ResourceGrants::default()
        }
        // Nothing was approved, so nothing is granted. Not a surprise for a
        // release that declares no capabilities.
        Err(_) => ResourceGrants::default(),
    }
}

// ---------------------------------------------------------------------------
// Grant, world and fetch policy
// ---------------------------------------------------------------------------

/// The trust boundary an installation lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum World {
    /// User-installable, proposal-only: `run` returns a verdict that the host
    /// plans, reviews and applies. Never commits on its own.
    Extension,
    /// Operator-installed class extender: participates in reads and commits
    /// and may write, signed by its own agent.
    ServerExtension,
}

/// Whom a read is authorized for.
///
/// The caller is the identity the run happens under: the plugin's own agent
/// for a class extender, the account (or grant agent) that triggered a JS run.
/// The installation identity, when the installation has one, bounds it
/// further: a run may read only what both may read. Neither is ever `Sudo`;
/// a plugin host has no business reading as the server.
#[derive(Clone, Debug)]
pub struct Grant {
    caller: ForAgent,
    installation: Option<ForAgent>,
}

impl Grant {
    pub fn new(caller: ForAgent, installation: Option<ForAgent>) -> Result<Self, String> {
        if caller == ForAgent::Sudo || installation == Some(ForAgent::Sudo) {
            return Err("a plugin host never reads as sudo".into());
        }
        Ok(Self {
            caller,
            installation,
        })
    }

    pub fn caller(&self) -> &ForAgent {
        &self.caller
    }

    /// Refuses unless every identity in the grant may read `resource`.
    pub async fn check_read(&self, db: &Db, resource: &Resource) -> Result<(), String> {
        hierarchy::check_read(db, resource, &self.caller)
            .await
            .map_err(|e| e.to_string())?;
        self.check_installation_read(db, resource).await
    }

    /// The installation half of [`Grant::check_read`], for reads the store has
    /// already authorized for the caller.
    async fn check_installation_read(&self, db: &Db, resource: &Resource) -> Result<(), String> {
        if let Some(installation) = &self.installation {
            hierarchy::check_read(db, resource, installation)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Which destinations a fetch may reach. Three declaration styles exist today;
/// they all end in the same checks.
#[derive(Clone, Debug)]
pub enum FetchPolicy {
    /// Exact origins from a class extender's `plugin.json`, any method.
    Origins(Vec<String>),
    /// Declared operations from a versioned JS manifest: id, method, endpoint
    /// and effect must all match.
    Operations(Box<Manifest>),
    /// A JS draft without a manifest: `GET`/`HEAD` only, to the origins its
    /// secrets are scoped to. "Can reach" and "has a credential for" are the
    /// same thing here, which is wrong for a public API and why versioned
    /// manifests exist.
    SecretOrigins,
}

/// An outgoing request, as both guests describe one.
#[derive(Clone, Debug)]
pub struct FetchRequest {
    /// The declared operation this request claims to be, for
    /// [`FetchPolicy::Operations`].
    pub operation: Option<String>,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// A request that passed every policy check and is ready to resolve and send.
struct Authorized {
    url: url::Url,
    origin: String,
    method: reqwest::Method,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

// ---------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------

/// The host capabilities of one installation, under one grant.
///
/// Cheap to clone: a class extender builds one at load time and clones it per
/// instantiation; a JS run builds one per call so a revocation between calls
/// takes effect immediately.
#[derive(Clone)]
pub struct HostCore {
    db: Arc<Db>,
    /// The drive the installation belongs to; secrets are keyed by it.
    drive: Option<String>,
    /// The installation's resource, which owns its secrets and config.
    plugin: Option<String>,
    /// The key the installation signs with, when it may commit.
    agent: Option<Agent>,
    grant: Grant,
    world: World,
    fetch_policy: FetchPolicy,
    /// Whether `get_resource` may fetch a subject from another server.
    remote_reads: bool,
    /// The drive queries are scoped to, and the most rows a query may return.
    query_scope: Option<String>,
    query_limit: Option<usize>,
}

impl HostCore {
    /// A class extender, in the server-extension world.
    ///
    /// Reads are authorized for the plugin's own agent, or as the public agent
    /// for a global extension that has none. It may commit, signed by that
    /// agent, and may reach the origins its manifest declares.
    pub fn for_class_extender(
        db: Arc<Db>,
        scope: &ClassExtenderScope,
        plugin: Option<String>,
        agent: Option<Agent>,
        manifest: Option<&Manifest>,
    ) -> Result<Self, String> {
        let caller = agent
            .as_ref()
            .map(ForAgent::from)
            .unwrap_or(ForAgent::Public);
        let drive = match scope {
            ClassExtenderScope::Drive(drive) => Some(drive.clone()),
            ClassExtenderScope::Global => None,
        };
        // A class extender declares origins, not operations. Declaring at
        // least one is what network access means for it: the legacy `network`
        // permission translated into `network.origins` and nothing else.
        let origins = manifest
            .map(|m| m.network.origins.clone())
            .unwrap_or_default();

        Ok(Self {
            db,
            drive,
            plugin,
            agent,
            grant: Grant::new(caller, None)?,
            world: World::ServerExtension,
            remote_reads: !origins.is_empty(),
            fetch_policy: FetchPolicy::Origins(origins),
            query_scope: None,
            query_limit: None,
        })
    }

    /// A JS `run` host, in the extension world.
    ///
    /// Resolves the installation now: the plugin must belong to `drive`, its
    /// identity must not be revoked, and when it has one, reads are bounded by
    /// it as well as by `caller`. This host never commits.
    pub async fn for_run(
        db: Arc<Db>,
        drive: &str,
        plugin: &str,
        caller: ForAgent,
        manifest: Option<Manifest>,
    ) -> Result<Self, String> {
        let installation = match super::installation::resolve(&db, drive, plugin)
            .await?
            .signing_as
        {
            Some(key) => {
                let info = db
                    .get_app_agent_info(&key)
                    .map_err(|e| e.to_string())?
                    .ok_or("app identity is missing")?;
                Some(ForAgent::AgentSubject(info.agent.into()))
            }
            None => None,
        };

        Ok(Self {
            db,
            drive: Some(drive.to_string()),
            plugin: Some(plugin.to_string()),
            agent: None,
            grant: Grant::new(caller, installation)?,
            world: World::Extension,
            fetch_policy: match manifest {
                Some(manifest) => FetchPolicy::Operations(Box::new(manifest)),
                None => FetchPolicy::SecretOrigins,
            },
            remote_reads: false,
            query_scope: Some(drive.to_string()),
            query_limit: Some(10_000),
        })
    }

    pub fn world(&self) -> World {
        self.world
    }

    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    /// The subject of the agent this installation signs as, if it has one.
    pub fn plugin_agent(&self) -> Option<String> {
        self.agent.as_ref().map(|a| a.subject.to_string())
    }

    // -- reads --------------------------------------------------------------

    /// A resource, as the grant may see it.
    ///
    /// Local subjects go through the store's extended read, which applies the
    /// caller's rights and any class extender, and then through the
    /// installation's rights. A subject on another server is fetched only when
    /// the installation has network access, and only after the same egress
    /// checks a fetch gets — the store's own fallback would otherwise reach
    /// the network as the server's agent.
    pub async fn get_resource(&self, subject: &str) -> Result<Resource, String> {
        let parsed = Subject::from_raw(subject, self.db.get_base_domain().as_deref());

        if !parsed.is_local() && !self.db.has_resource_locally(&parsed.pure_id()) {
            return self.fetch_remote(subject).await;
        }

        let resource = match self
            .db
            .get_resource_extended(&parsed, false, &self.grant.caller)
            .await
            .map_err(|e| e.to_string())?
        {
            ResourceResponse::Resource(resource)
            | ResourceResponse::ResourceWithReferenced(resource, _) => resource,
            ResourceResponse::Redirect(target) => {
                return Err(format!("{subject} redirects to {target}"));
            }
        };

        self.grant
            .check_installation_read(&self.db, &resource)
            .await?;

        Ok(resource)
    }

    async fn fetch_remote(&self, subject: &str) -> Result<Resource, String> {
        if !self.remote_reads {
            return Err(
                "this plugin has no network permission, so it cannot read resources on other servers"
                    .into(),
            );
        }

        // The host fetches this one, so no guest socket check sees it. Same
        // rules, applied here.
        if let Some(refusal) = egress::refuse_url(subject).await {
            tracing::warn!(%subject, %refusal, "plugin refused a foreign subject fetch");
            return Err(format!("cannot fetch {subject}: {refusal}"));
        }

        self.db
            .fetch_resource(subject, self.agent.as_ref())
            .await
            .map_err(|e| e.to_string())
    }

    /// Resources matching `property = value`, each one authorized for the
    /// grant. The store filters for the caller; the installation's rights are
    /// applied on top.
    pub async fn query(&self, property: &str, value: &str) -> Result<Vec<Resource>, String> {
        let query = Query {
            property: Some(property.to_string()),
            value: Some(Value::String(value.to_string())),
            limit: self.query_limit.map(|limit| limit + 1),
            drive: self.query_scope.as_deref().map(Subject::from),
            for_agent: self.grant.caller.clone(),
            ..Default::default()
        };

        let result = self.db.query(&query).await.map_err(|e| e.to_string())?;

        if let Some(limit) = self.query_limit {
            if result.subjects.len() > limit || result.count != result.subjects.len() {
                return Err(format!(
                    "sandbox query is incomplete or exceeds {limit} records"
                ));
            }
        }

        let mut resources = Vec::with_capacity(result.resources.len());
        for resource in result.resources {
            self.grant
                .check_installation_read(&self.db, &resource)
                .await?;
            resources.push(resource);
        }

        Ok(resources)
    }

    /// The installation's config as a JSON object, `{}` when it has none.
    pub async fn get_config(&self) -> String {
        let Some(subject) = &self.plugin else {
            return "{}".to_string();
        };

        let Ok(plugin_resource) = self
            .db
            .get_resource(&Subject::from_raw(subject, None))
            .await
        else {
            return "{}".to_string();
        };

        let Ok(val) = plugin_resource.get(urls::CONFIG) else {
            return "{}".to_string();
        };

        // Loro stores Value::Json as a JSON string, and the loader heuristic
        // in `loro_value_to_atomic_value` reinflates `{...}` strings as
        // `Value::NestedResource`. So accept any shape that can be coerced
        // back to a JSON object.
        match val {
            Value::Json(json_val) => json_val.to_string(),
            Value::String(s) => match serde_json::from_str::<serde_json::Value>(s) {
                Ok(parsed) if parsed.is_object() => s.clone(),
                _ => "{}".to_string(),
            },
            Value::NestedResource(atomic_lib::values::SubResource::Nested(propvals)) => {
                let map: serde_json::Map<String, serde_json::Value> = propvals
                    .iter()
                    .map(|(k, v)| {
                        let s = v.to_string();
                        let parsed = serde_json::from_str::<serde_json::Value>(&s)
                            .unwrap_or(serde_json::Value::String(s));
                        (k.clone(), parsed)
                    })
                    .collect();
                serde_json::Value::Object(map).to_string()
            }
            _ => "{}".to_string(),
        }
    }

    // -- writes -------------------------------------------------------------

    /// Applies a commit signed by the installation's agent.
    ///
    /// Only a server extension may do this. An extension-world installation
    /// proposes; the host applies after review, and this call tells it so.
    /// `commit` is the plugin SDK's wire shape: `subject`, full `set` and
    /// `remove` payloads, `destroy`.
    pub async fn commit(&self, commit: &str) -> Result<(), String> {
        if self.world != World::ServerExtension {
            return Err(
                "this installation is proposal-only: return intents from `run` instead of committing"
                    .into(),
            );
        }

        let Some(agent) = &self.agent else {
            return Err("Plugin does not have an agent".to_string());
        };

        // The plugin SDK's `CommitBuilder` serializes with full set / remove
        // payloads (HashMap<String, JsonValue> / HashSet<String>). The
        // canonical `CommitBuilderJSON` only carries `loro_update`, so plugins
        // that build a commit by accumulating `set` calls would otherwise
        // arrive with no Loro update and get rejected. Parse the wire shape
        // directly here and convert each JsonValue → typed `Value` via the
        // property's datatype, then `sign` materializes the Loro update.
        #[derive(serde::Deserialize)]
        struct PluginCommitWire {
            subject: String,
            #[serde(default)]
            set: std::collections::HashMap<String, serde_json::Value>,
            #[serde(default)]
            remove: std::collections::HashSet<String>,
            #[serde(default)]
            destroy: bool,
            #[serde(default)]
            previous_commit: Option<String>,
        }

        let wire: PluginCommitWire =
            serde_json::from_str(commit).map_err(|e| format!("Invalid commit JSON: {e}"))?;

        let mut commit_builder = CommitBuilder::new(wire.subject.into());
        commit_builder.destroy(wire.destroy);
        // `previous_commit` is intentionally ignored: `sign()` overrides it
        // from the resource's `lastCommit` propval, so any value the plugin
        // supplies would be discarded anyway.
        let _ = wire.previous_commit;
        for prop in wire.remove {
            commit_builder.remove(prop);
        }
        let parse_opts = atomic_lib::parse::ParseOpts::default();
        for (prop, json_val) in wire.set {
            let (key, value) =
                atomic_lib::parse::parse_propval(&prop, &json_val, None, &*self.db, &parse_opts)
                    .await
                    .map_err(|e| format!("Failed to convert plugin set value for {prop}: {e}"))?;
            commit_builder.set(key.to_string(), value);
        }

        let resource = self
            .db
            .get_resource_extended(&commit_builder.subject, false, &agent.into())
            .await
            .map_err(|e| e.to_string())?
            .to_single();

        let commit = commit_builder
            .sign(agent, &*self.db, &resource)
            .await
            .map_err(|e| e.to_string())?;

        // A plugin editing plugin resources could install or update code
        // without the user's consent.
        if commit_changes_plugin(&commit, &resource)? {
            return Err("Plugin cannot edit plugin resources".to_string());
        }

        let opts = CommitOpts {
            validate_schema: true,
            validate_constraints: true,
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: true,
            validate_loro_causality: false,
            update_index: true,
            validate_for_agent: None,
            source_id: None,
        };

        self.db
            .apply_commit(commit, &opts)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    // -- egress -------------------------------------------------------------

    /// The only way out of a plugin.
    ///
    /// Before a byte leaves: no secret handle appears anywhere it would be
    /// logged, the policy admits this destination (and, for declared
    /// operations, this `effect`), every resolved address is on the public
    /// internet and is the address actually connected to, and every handle in
    /// a header resolves to a secret this installation owns for this origin.
    /// The response is capped while it streams, not after it was buffered.
    pub async fn fetch(
        &self,
        request: FetchRequest,
        effect: &str,
    ) -> Result<FetchResponse, String> {
        let authorized = self.authorize(request, effect)?;
        let addresses = egress::checked_addresses(&authorized.url).await?;
        let headers = self.substitute_secrets(&authorized.origin, authorized.headers)?;

        let client = reqwest::Client::builder()
            // Only the checked addresses, and never through a proxy that would
            // resolve again.
            .no_proxy()
            .resolve_to_addrs(
                authorized.url.host_str().ok_or("URL has no host")?,
                &addresses,
            )
            .timeout(std::time::Duration::from_secs(egress::FETCH_TIMEOUT_SECS))
            // Every redirect would need re-checking against the allowlist and
            // the address rules, and credential headers would have to be
            // dropped crossing origins. Refusing to follow them is the honest
            // version until that exists: the plugin sees the 3xx and can decide.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("could not build an HTTP client: {e}"))?;

        let mut outgoing = client.request(authorized.method, authorized.url);
        for (name, value) in headers {
            outgoing = outgoing.header(name, value);
        }
        if let Some(body) = authorized.body {
            outgoing = outgoing.body(body);
        }

        let origin = authorized.origin;
        let response = outgoing
            .send()
            .await
            .map_err(|e| format!("request to {origin} failed: {e}"))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();

        let bytes = read_capped(
            response.bytes_stream(),
            egress::FETCH_MAX_RESPONSE_BYTES,
            &origin,
        )
        .await?;

        Ok(FetchResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }

    /// Every check that needs no network: handles, policy, method.
    fn authorize(&self, request: FetchRequest, effect: &str) -> Result<Authorized, String> {
        if self.plugin.is_none() {
            return Err("this plugin has no subject, so it has no secrets".to_string());
        }

        if let Some(refusal) =
            egress::refuse_misplaced_handles(&request.url, request.body.as_deref())
        {
            return Err(refusal);
        }

        let url = url::Url::parse(&request.url).map_err(|e| format!("not a URL: {e}"))?;
        let origin = egress::origin_of(&url)?;

        match &self.fetch_policy {
            FetchPolicy::Origins(origins) => {
                if !origins.iter().any(|o| o == &origin) {
                    return Err(format!(
                        "this plugin does not declare {origin} in its manifest, so it cannot reach it",
                    ));
                }
            }
            FetchPolicy::Operations(manifest) => {
                if !manifest.allows_effect(
                    request.operation.as_deref(),
                    &request.method,
                    &url,
                    effect,
                ) {
                    return Err("preview fetch requires a declared read operation; external writes need an approved intent".into());
                }
            }
            FetchPolicy::SecretOrigins => {
                if effect != "read" || !matches!(request.method.as_str(), "GET" | "HEAD") {
                    return Err("legacy preview fetch permits only GET and HEAD; declare read operations in a versioned manifest".into());
                }
                if !self.secret_origins().iter().any(|o| o == &origin) {
                    return Err(format!(
                        "this plugin has no secret scoped to {origin}, so it cannot reach it",
                    ));
                }
            }
        }

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| format!("not an HTTP method: {e}"))?;

        Ok(Authorized {
            url,
            origin,
            method,
            headers: request.headers,
            body: request.body,
        })
    }

    /// Origins the installation's secrets are scoped to.
    fn secret_origins(&self) -> Vec<String> {
        let (Some(drive), Some(plugin)) = (&self.drive, &self.plugin) else {
            return Vec::new();
        };
        self.db
            .list_plugin_secrets(drive, plugin)
            .map(|secrets| {
                secrets
                    .into_iter()
                    .flat_map(|secret| secret.origins)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Replaces `secret:<name>` in header values with the installation's
    /// secret of that name, if it is scoped to `origin` (and, under a
    /// versioned manifest, declared for it). Spending a secret records its use,
    /// so this runs after the address check: a refused request spends nothing.
    fn substitute_secrets(
        &self,
        origin: &str,
        headers: Vec<(String, String)>,
    ) -> Result<Vec<(String, String)>, String> {
        let now = atomic_lib::utils::now();

        egress::substitute_headers(headers, |name| {
            let plugin = self.plugin.as_deref()?;

            if let FetchPolicy::Operations(manifest) = &self.fetch_policy {
                if !manifest
                    .secrets
                    .iter()
                    .any(|secret| secret.name == name && secret.origin == origin)
                {
                    return None;
                }
            }

            let key = atomic_lib::db::plugin_secret::PluginSecretKey::new(
                self.drive.as_deref().unwrap_or_default(),
                plugin,
                name,
            );

            self.db
                .use_plugin_secret(&key, origin, now, |value| value.to_string())
                .ok()
                .flatten()
        })
    }
}

/// Reads a body up to `cap` bytes, refusing the moment a chunk would cross it.
///
/// A response that streams past the cap is abandoned there rather than
/// buffered to completion and measured afterwards: the cap bounds memory,
/// so it has to be enforced while memory is being used.
pub async fn read_capped<S, B, E>(stream: S, cap: usize, origin: &str) -> Result<Vec<u8>, String>
where
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
    E: std::fmt::Display,
{
    let mut stream = std::pin::pin!(stream);
    let mut bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("could not read the response from {origin}: {e}"))?;
        let chunk = chunk.as_ref();

        if chunk.len() > cap.saturating_sub(bytes.len()) {
            return Err(format!(
                "{origin} response exceeds the byte limit of {cap} bytes"
            ));
        }

        bytes.extend_from_slice(chunk);
    }

    Ok(bytes)
}

/// Whether this commit touches a plugin resource, either because the target
/// already is one or because the commit makes it one.
fn commit_changes_plugin(commit: &Commit, resource: &Resource) -> Result<bool, String> {
    if let Ok(is_a) = resource.get(urls::IS_A) {
        let resource_classes = is_a.to_subjects(None).map_err(|e| e.to_string())?;

        if resource_classes
            .iter()
            .any(|class| class == urls::INSTALLATION || class == urls::PLUGIN)
        {
            return Ok(true);
        }
    }

    if let Some(loro_bytes) = &commit.loro_update {
        let doc = atomic_lib::loro::AtomicLoroDoc::new();
        let _ = doc.import_update(loro_bytes);
        if let Some(is_a_str) = doc.get_string_property(urls::IS_A) {
            if is_a_str.contains(urls::INSTALLATION) || is_a_str.contains(urls::PLUGIN) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::db::plugin_secret::{PluginSecret, PluginSecretKey};

    fn class_extender_manifest(origins: &[&str]) -> Manifest {
        Manifest::parse(serde_json::json!({
            "schemaVersion": 2,
            "runtime": "wasip2/1",
            "world": "server-extension",
            "name": "probe",
            "namespace": "test",
            "version": "0.0.1",
            "network": {"origins": origins},
        }))
        .unwrap()
        .unwrap()
    }

    fn js_manifest(origin: &str) -> Manifest {
        Manifest::parse(serde_json::json!({
            "schemaVersion": 1,
            "secrets": [{"name": "token", "origin": origin}],
            "operations": [{"id": "get", "method": "GET", "url": format!("{origin}/x"), "effect": "read"}],
        }))
        .unwrap()
        .unwrap()
    }

    fn request(url: &str, headers: &[(&str, &str)]) -> FetchRequest {
        FetchRequest {
            operation: Some("get".into()),
            method: "GET".into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: None,
        }
    }

    /// One class-extender host and one JS host over the same store, plugin
    /// and drive, each allowed to reach `origin`. The fixture comes along so
    /// the store outlives the hosts.
    async fn both_hosts(
        name: &str,
        origin: &str,
    ) -> (crate::plugins::test_fixture::Fixture, HostCore, HostCore) {
        let mut fixture = crate::plugins::test_fixture::fixture(name).await;
        crate::plugins::test_fixture::write_plugin(&mut fixture, "probe").await;
        let db = Arc::new(fixture.appstate.store.clone());
        let agent = db.get_default_agent().unwrap();

        let wasm = HostCore::for_class_extender(
            db.clone(),
            &ClassExtenderScope::Drive(fixture.drive.clone()),
            Some(fixture.plugin.clone()),
            Some(agent.clone()),
            Some(&class_extender_manifest(&[origin])),
        )
        .unwrap();

        let js = HostCore::for_run(
            db.clone(),
            &fixture.drive,
            &fixture.plugin,
            ForAgent::AgentSubject(agent.subject.clone()),
            Some(js_manifest(origin)),
        )
        .await
        .unwrap();

        (fixture, wasm, js)
    }

    #[test]
    fn a_grant_is_never_sudo() {
        assert!(Grant::new(ForAgent::Sudo, None).is_err());
        assert!(Grant::new(ForAgent::Public, Some(ForAgent::Sudo)).is_err());
        assert!(Grant::new(ForAgent::Public, None).is_ok());
    }

    #[test]
    fn limits_are_keyed_by_runtime_and_capability() {
        let base = limits(Runtime::ClassExtender, ResourceGrants::default());
        assert_eq!(base.fuel, 100_000_000);
        assert_eq!(base.memory_bytes, 50 * MIB);
        let wide = limits(
            Runtime::ClassExtender,
            ResourceGrants {
                extended_fuel: true,
                extended_memory: true,
            },
        );
        assert_eq!(wide.fuel, 1_000_000_000);
        assert_eq!(wide.memory_bytes, 2000 * MIB);
        // The JS runtime's budget is unchanged by the move.
        let js = limits(Runtime::Js, ResourceGrants::default());
        assert_eq!(js.fuel, 20_000_000_000);
        assert_eq!(js.memory_bytes, 256 * MIB);
        assert_eq!(js.yield_interval, None);
    }

    #[actix_rt::test]
    async fn a_js_host_cannot_read_what_its_agent_may_not() {
        let mut fixture = crate::plugins::test_fixture::fixture("host_core_js_read").await;
        crate::plugins::test_fixture::write_plugin(&mut fixture, "probe").await;
        let db = Arc::new(fixture.appstate.store.clone());
        let hidden = crate::plugins::test_fixture::genesis(
            &db,
            vec![
                (urls::NAME, Value::String("host-core-hidden".into())),
                (
                    urls::READ,
                    Value::ResourceArray(vec!["did:ad:agent:unrelated".into()]),
                ),
            ],
        )
        .await;

        // The stranger may read the plugin itself, and nothing else.
        let mut plugin = db
            .get_resource(&fixture.plugin.as_str().into())
            .await
            .unwrap();
        plugin
            .set_unsafe(
                urls::READ.into(),
                Value::ResourceArray(vec!["did:ad:agent:stranger".into()]),
            )
            .unwrap();
        plugin.save(db.as_ref()).await.unwrap();

        let stranger = HostCore::for_run(
            db.clone(),
            &fixture.drive,
            &fixture.plugin,
            ForAgent::AgentSubject("did:ad:agent:stranger".into()),
            None,
        )
        .await
        .unwrap();
        assert!(stranger.get_resource(&hidden).await.is_err());
        let found = stranger
            .query(urls::NAME, "host-core-hidden")
            .await
            .unwrap();
        assert!(found.iter().all(|r| r.get_subject().as_str() != hidden));
        // The stranger may still read its own plugin: the refusal above is
        // about rights, not about the host being broken.
        assert!(stranger.get_resource(&fixture.plugin).await.is_ok());

        // Never as the server, whatever the caller claims to be.
        assert!(HostCore::for_run(
            db.clone(),
            &fixture.drive,
            &fixture.plugin,
            ForAgent::Sudo,
            None
        )
        .await
        .is_err());
    }

    #[actix_rt::test]
    async fn a_js_host_does_not_fetch_foreign_subjects_through_the_store() {
        let mut fixture = crate::plugins::test_fixture::fixture("host_core_remote").await;
        crate::plugins::test_fixture::write_plugin(&mut fixture, "probe").await;
        let db = Arc::new(fixture.appstate.store.clone());
        let host = HostCore::for_run(
            db.clone(),
            &fixture.drive,
            &fixture.plugin,
            ForAgent::AgentSubject(db.get_default_agent().unwrap().subject),
            None,
        )
        .await
        .unwrap();
        let err = host
            .get_resource("http://127.0.0.1:1/resource")
            .await
            .unwrap_err();
        assert!(err.contains("network permission"), "{err}");
    }

    #[actix_rt::test]
    async fn both_hosts_refuse_a_loopback_address_the_same_way() {
        let (_fixture, wasm, js) = both_hosts("host_core_loopback", "http://127.0.0.1:9").await;
        let req = request("http://127.0.0.1:9/x", &[]);
        let from_wasm = wasm.fetch(req.clone(), "write").await.unwrap_err();
        let from_js = js.fetch(req, "read").await.unwrap_err();
        assert!(from_wasm.contains("Loopback"), "{from_wasm}");
        assert_eq!(from_wasm, from_js);
    }

    #[actix_rt::test]
    async fn secrets_are_substituted_identically_and_never_in_a_url() {
        let (fixture, wasm, js) = both_hosts("host_core_secrets", "https://api.test").await;
        let db = &fixture.appstate.store;
        let key = PluginSecretKey::new(
            wasm.drive.as_deref().unwrap(),
            wasm.plugin.as_deref().unwrap(),
            "token",
        );
        db.set_plugin_secret(
            &key,
            &PluginSecret::new("tok-abc".into(), vec!["https://api.test".into()], 0),
        )
        .unwrap();

        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer secret:token".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let from_wasm = wasm
            .substitute_secrets("https://api.test", headers.clone())
            .unwrap();
        let from_js = js.substitute_secrets("https://api.test", headers).unwrap();
        assert_eq!(from_wasm, from_js);
        assert_eq!(from_wasm[0].1, "Bearer tok-abc");
        assert_eq!(from_wasm[1].1, "application/json");

        // Scoped to its origin, on both.
        assert!(wasm
            .substitute_secrets(
                "https://other.test",
                vec![("X".into(), "secret:token".into())]
            )
            .is_err());
        assert!(js
            .substitute_secrets(
                "https://other.test",
                vec![("X".into(), "secret:token".into())]
            )
            .is_err());

        // A handle in the URL is refused before anything resolves or sends.
        let in_url = request("https://api.test/x?t=secret:token", &[]);
        let from_wasm = wasm.fetch(in_url.clone(), "write").await.unwrap_err();
        let from_js = js.fetch(in_url, "read").await.unwrap_err();
        assert!(
            from_wasm.contains("secret handle in the URL"),
            "{from_wasm}"
        );
        assert_eq!(from_wasm, from_js);
    }

    #[actix_rt::test]
    async fn only_a_server_extension_may_commit() {
        let (_fixture, wasm, js) = both_hosts("host_core_commit", "https://api.test").await;
        let err = js.commit("{}").await.unwrap_err();
        assert!(err.contains("proposal-only"), "{err}");
        // The class extender gets past the world check and fails on the payload.
        let err = wasm.commit("{}").await.unwrap_err();
        assert!(!err.contains("proposal-only"), "{err}");
    }

    #[tokio::test]
    async fn the_response_cap_stops_the_stream_where_it_is_crossed() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let polled = Arc::new(AtomicUsize::new(0));
        let seen = polled.clone();
        let chunks: Vec<Result<Vec<u8>, String>> = (0..10).map(|_| Ok(vec![0u8; 100])).collect();
        let stream = futures::stream::iter(chunks).inspect(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });

        let err = read_capped(stream, 250, "https://api.test")
            .await
            .unwrap_err();
        assert!(err.contains("byte limit"), "{err}");
        // Two chunks fit, the third crosses the cap, and the remaining seven
        // are never read.
        assert_eq!(polled.load(Ordering::SeqCst), 3);

        let chunks: Vec<Result<Vec<u8>, String>> = (0..2).map(|_| Ok(vec![1u8; 100])).collect();
        let body = read_capped(futures::stream::iter(chunks), 250, "https://api.test")
            .await
            .unwrap();
        assert_eq!(body.len(), 200);
    }
}
