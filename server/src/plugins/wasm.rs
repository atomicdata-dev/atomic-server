use std::future::Future;
use std::pin::Pin;

use futures::future::join_all;
use zip::ZipArchive;

use std::{
    collections::HashSet,
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
};

use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::ClassExtender,
    commit::{CommitBuilder, CommitOpts},
    db::plugin_meta::{validate_plugin_identifiers, PermissionType, PluginManifest, PluginMeta},
    errors::{AtomicError, AtomicResult},
    parse::{parse_json_ad_resource, ParseOpts, SaveOpts},
    storelike::{Query, ResourceResponse},
    urls, Commit, Db, Resource, Storelike, Value,
};
use atomic_lib::{
    class_extender::{self, ClassExtenderScope},
    AtomicErrorType,
};
use base64::{engine::general_purpose, Engine as _};
use ring::digest::{digest, SHA256};
use tracing::{error, info, warn};
use wasmtime::{
    component::{Component, Linker, ResourceTable},
    Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Trap,
};
use wasmtime_wasi::{p2, DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi_http::{
    p2::{add_only_http_to_linker_async, WasiHttpCtxView, WasiHttpView},
    WasiHttpCtx,
};

use atomic_lib::db::plugin_meta::PluginMetaKey;

mod bindings {
    wasmtime::component::bindgen!({
    path: "wit/class-extender.wit",
    world: "class-extender",
    imports: { default: async },
    exports: { default: async },
    });
}

use bindings::atomic::class_extender::types::{
    CommitContext as WasmCommitContext, GetContext as WasmGetContext,
    ResourceJson as WasmResourceJson, ResourceResponse as WasmResourceResponse,
};

const CLASS_EXTENDER_DIR_NAME: &str = "class-extenders"; // Relative to the store path.
const FUEL_LIMIT: u64 = 100_000_000;
const FUEL_LIMIT_EXTENDED: u64 = 1_000_000_000;
const FUEL_YIELD_INTERVAL: u64 = 10_000;
const MEMORY_LIMIT_BYTES: usize = 50 * 1024 * 1024; // 50MB
const MEMORY_LIMIT_BYTES_EXTENDED: usize = 2000 * 1024 * 1024; // 2GB

struct WasmtimeErrorWrapper(wasmtime::Error);

impl From<wasmtime::Error> for WasmtimeErrorWrapper {
    fn from(error: wasmtime::Error) -> Self {
        WasmtimeErrorWrapper(error)
    }
}

impl From<WasmtimeErrorWrapper> for AtomicError {
    fn from(wrapper: WasmtimeErrorWrapper) -> Self {
        let error = wrapper.0;
        if let Some(trap) = error.downcast_ref::<Trap>() {
            if *trap == Trap::OutOfFuel {
                return AtomicError {
                    message: format!(
                        "Wasm plugin exceeded fuel limit of {} instructions",
                        FUEL_LIMIT
                    ),
                    error_type: AtomicErrorType::OtherError,
                    subject: None,
                };
            }
        }

        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

fn to_atomic_error(error: wasmtime::Error) -> AtomicError {
    WasmtimeErrorWrapper(error).into()
}

pub async fn load_wasm_class_extenders(
    plugin_path: &Path,
    plugin_cache_path: &Path,
    db: &Db,
) -> AtomicResult<Vec<ClassExtender>> {
    // Create the plugin directory if it doesn't exist
    let plugin_dir = plugin_path.join(CLASS_EXTENDER_DIR_NAME);
    let global_dir = plugin_dir.join("global");
    let scoped_dir = plugin_dir.join("scoped");

    if !plugin_dir.exists() {
        if let Err(err) = std::fs::create_dir_all(&plugin_dir) {
            warn!(
                error = %err,
                path = %plugin_dir.display(),
                "Failed to create Wasm extender directory"
            );
        } else {
            // Create global and scoped directories
            std::fs::create_dir_all(&global_dir).ok();
            std::fs::create_dir_all(&scoped_dir).ok();
            info!(
                path = %plugin_dir.display(),
                "Created empty Wasm extender directory (drop .wasm files in 'global' or 'scoped/<base64_drive_url>' folders)"
            );
        }
        return Ok(Vec::new());
    }

    // Ensure subdirectories exist
    if !global_dir.exists() {
        std::fs::create_dir_all(&global_dir).ok();
    }
    if !scoped_dir.exists() {
        std::fs::create_dir_all(&scoped_dir).ok();
    }

    // Setup cache directories
    if !plugin_cache_path.exists() {
        if let Err(err) = std::fs::create_dir_all(plugin_cache_path) {
            warn!(
                error = %err,
                path = %plugin_cache_path.display(),
                "Failed to create Wasm cache directory"
            );
        }
    }
    let global_cache = plugin_cache_path.join("global");
    if !global_cache.exists() {
        std::fs::create_dir_all(&global_cache).ok();
    }
    let scoped_cache = plugin_cache_path.join("scoped");
    if !scoped_cache.exists() {
        std::fs::create_dir_all(&scoped_cache).ok();
    }

    let engine = match build_engine() {
        Ok(engine) => Arc::new(engine),
        Err(err) => {
            error!(error = %err, "Failed to initialize Wasm engine. Skipping dynamic class extenders");
            return Ok(Vec::new());
        }
    };

    let mut extenders = Vec::new();
    let mut used_cwasm_files = HashSet::new();
    let mut cache_dirs = vec![global_cache.clone()];

    info!("Loading plugins...");

    let mut tasks = Vec::new();

    // Global Plugins
    let global_wasm_files = find_wasm_files(&global_dir);
    for path in global_wasm_files {
        tasks.push((
            path,
            global_dir.clone(),
            global_cache.clone(),
            ClassExtenderScope::Global,
        ));
    }

    // Scoped Plugins
    if let Ok(entries) = std::fs::read_dir(&scoped_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = entry.file_name();
                let dir_name_str = dir_name.to_string_lossy();

                // Get the scope subject from the directory name
                let Ok(sope_subject) = decode_subject(&dir_name_str) else {
                    warn!(
                        "Skipping invalid base64 scoped plugin directory: {}",
                        dir_name_str
                    );
                    continue;
                };

                let scope = ClassExtenderScope::Drive(sope_subject);
                let drive_wasm_files = find_wasm_files(&path);
                let drive_cache = scoped_cache.join(&dir_name);
                if !drive_cache.exists() {
                    std::fs::create_dir_all(&drive_cache).ok();
                }
                cache_dirs.push(drive_cache.clone());

                for wasm_path in drive_wasm_files {
                    tasks.push((wasm_path, path.clone(), drive_cache.clone(), scope.clone()));
                }
            }
        }
    }

    let futures = tasks
        .into_iter()
        .map(|(path, plugin_dir, plugin_cache_path, scope)| {
            let engine = engine.clone();
            let db = db.clone();

            async move {
                load_plugin_from_disk(&path, &plugin_dir, &plugin_cache_path, scope, engine, &db)
                    .await
                    .unwrap_or((None, PathBuf::new()))
            }
        });

    let results = join_all(futures).await;

    for res in results {
        let (extender_opt, cwasm_path) = res;
        used_cwasm_files.insert(cwasm_path);
        if let Some(extender) = extender_opt {
            extenders.push(extender);
        }
    }

    for cache_dir in cache_dirs {
        cleanup_cache(&cache_dir, &used_cwasm_files);
    }

    Ok(extenders)
}

fn build_engine() -> AtomicResult<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);

    Engine::new(&config).map_err(to_atomic_error)
}

#[derive(Clone)]
struct WasmPlugin {
    inner: Arc<WasmPluginInner>,
}

struct WasmPluginInner {
    engine: Arc<Engine>,
    component: Component,
    path: PathBuf,
    owned_folder_path: Option<PathBuf>,
    scope: ClassExtenderScope,
    class_url: Vec<String>,
    db: Arc<Db>,
    plugin_subject: Option<String>,
    agent: Option<Agent>,
    manifest: Option<PluginManifest>,
}

impl WasmPlugin {
    #[allow(clippy::too_many_arguments)]
    async fn load(
        engine: Arc<Engine>,
        wasm_bytes: &[u8],
        path: &Path,
        cwasm_path: &Path,
        owned_folder_path: Option<PathBuf>,
        db: &Db,
        scope: ClassExtenderScope,
        plugin_subject: Option<String>,
        agent: Option<Agent>,
        manifest: Option<PluginManifest>,
    ) -> AtomicResult<Self> {
        let db = Arc::new(db.clone());

        let component = if cwasm_path.exists() {
            match std::fs::read(cwasm_path) {
                Ok(bytes) => {
                    // Safety: We trust the pre-compiled component on disk as it is generated by us or the admin
                    match unsafe { Component::deserialize(&engine, &bytes) } {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(
                                "Failed to deserialize cwasm at {}, recompiling. Error: {}",
                                cwasm_path.display(),
                                e
                            );
                            compile_and_save_component(&engine, wasm_bytes, path, cwasm_path)?
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read cwasm file: {}", e);
                    compile_and_save_component(&engine, wasm_bytes, path, cwasm_path)?
                }
            }
        } else {
            compile_and_save_component(&engine, wasm_bytes, path, cwasm_path)?
        };

        let runtime = WasmPlugin {
            inner: Arc::new(WasmPluginInner {
                engine: engine.clone(),
                component,
                path: path.to_path_buf(),
                owned_folder_path,
                class_url: Vec::new(),
                scope: scope.clone(),
                db: Arc::clone(&db),
                plugin_subject: plugin_subject.clone(),
                agent: agent.clone(),
                manifest: manifest.clone(),
            }),
        };

        let class_url = runtime.call_class_url().await?;
        Ok(WasmPlugin {
            inner: Arc::new(WasmPluginInner {
                engine,
                component: runtime.inner.component.clone(),
                path: runtime.inner.path.clone(),
                owned_folder_path: runtime.inner.owned_folder_path.clone(),
                class_url,
                scope,
                db,
                plugin_subject,
                agent,
                manifest,
            }),
        })
    }

    fn into_class_extender(self) -> ClassExtender {
        let get_plugin = self.clone();
        let before_plugin = self.clone();
        let after_plugin = self.clone();

        let id = if let ClassExtenderScope::Drive(drive) = &self.inner.scope {
            let filename = self
                .inner
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            format!("{}:{}", drive, filename)
        } else {
            let filename = self
                .inner
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            format!("global:{}", filename)
        };

        let mut builder = ClassExtender::builder()
            .id(id)
            .classes(self.inner.class_url.clone())
            .on_resource_get(ClassExtender::wrap_get_handler(move |context| {
                let get_plugin = get_plugin.clone();
                Box::pin(async move { get_plugin.call_on_resource_get(context).await })
            }))
            .before_commit(ClassExtender::wrap_commit_handler(move |context| {
                let before_plugin = before_plugin.clone();
                Box::pin(async move { before_plugin.call_before_commit(context).await })
            }))
            .after_commit(ClassExtender::wrap_commit_handler(move |context| {
                let after_plugin = after_plugin.clone();
                Box::pin(async move { after_plugin.call_after_commit(context).await })
            }))
            .scope(self.inner.scope.clone());

        if let Some(subject) = self.inner.plugin_subject.clone() {
            builder = builder.subject(subject);
        }

        builder.build()
    }

    async fn call_class_url(&self) -> AtomicResult<Vec<String>> {
        let (instance, mut store) = self.instantiate().await?;
        instance
            .call_class_url(&mut store)
            .await
            .map_err(to_atomic_error)
    }

    async fn call_on_resource_get<'a>(
        &'a self,
        context: class_extender::GetExtenderContext<'a>,
    ) -> AtomicResult<ResourceResponse> {
        let payload = self.build_get_context(&context)?;
        let (instance, mut store) = self.instantiate().await?;
        let response = instance
            .call_on_resource_get(&mut store, &payload)
            .await
            .map_err(to_atomic_error)??;

        let Some(payload) = response else {
            return Ok(ResourceResponse::Resource(context.db_resource.clone()));
        };

        self.inflate_resource_response(payload, context.store).await
    }

    async fn call_before_commit<'a>(
        &'a self,
        context: class_extender::CommitExtenderContext<'a>,
    ) -> AtomicResult<()> {
        if let Some(agent) = &self.inner.agent {
            // If the commit was signed by the plugin's agent, we skip the handler to prevent infinite loops.
            if agent.subject == context.commit.signer {
                return Ok(());
            }
        }

        let payload = self.build_commit_context(&context).await?;
        let (instance, mut store) = self.instantiate().await?;
        instance
            .call_before_commit(&mut store, &payload)
            .await
            .map_err(to_atomic_error)?
            .map_err(AtomicError::other_error)
    }

    async fn call_after_commit<'a>(
        &'a self,
        context: class_extender::CommitExtenderContext<'a>,
    ) -> AtomicResult<()> {
        if let Some(agent) = &self.inner.agent {
            // If the commit was signed by the plugin's agent, we skip the handler to prevent infinite loops.
            if agent.subject == context.commit.signer {
                return Ok(());
            }
        }

        let payload = self.build_commit_context(&context).await?;
        let (instance, mut store) = self.instantiate().await?;
        instance
            .call_after_commit(&mut store, &payload)
            .await
            .map_err(to_atomic_error)?
            .map_err(AtomicError::other_error)
    }

    async fn instantiate(&self) -> AtomicResult<(bindings::ClassExtender, Store<PluginHostState>)> {
        let mut store = Store::new(
            &self.inner.engine,
            PluginHostState::new(
                Arc::clone(&self.inner.db),
                &self.inner.owned_folder_path,
                self.inner.plugin_subject.clone(),
                self.inner.agent.clone(),
                self.inner.manifest.clone(),
            )?,
        );

        let fuel_limit = if PluginManifest::option_has_permission(
            self.inner.manifest.as_ref(),
            PermissionType::ExtendedFuel,
        ) {
            FUEL_LIMIT_EXTENDED
        } else {
            FUEL_LIMIT
        };

        store.set_fuel(fuel_limit).map_err(to_atomic_error)?;

        store
            .fuel_async_yield_interval(Some(FUEL_YIELD_INTERVAL))
            .map_err(to_atomic_error)?;

        store.limiter(|state| state);

        let mut linker = Linker::new(&self.inner.engine);
        p2::add_to_linker_async(&mut linker).map_err(|err| AtomicError::from(err.to_string()))?;

        if PluginManifest::option_has_permission(
            self.inner.manifest.as_ref(),
            PermissionType::Network,
        ) {
            add_only_http_to_linker_async(&mut linker)
                .map_err(|err| AtomicError::from(err.to_string()))?;
        }

        // Add our host implementations to the linker.
        bindings::atomic::class_extender::host::add_to_linker::<
            PluginHostState,
            wasmtime::component::HasSelf<PluginHostState>,
        >(&mut linker, |state: &mut PluginHostState| state)
        .map_err(|err| AtomicError::from(err.to_string()))?;

        let instance =
            bindings::ClassExtender::instantiate_async(&mut store, &self.inner.component, &linker)
                .await
                .map_err(to_atomic_error)?;
        Ok((instance, store))
    }

    fn build_get_context(
        &self,
        context: &class_extender::GetExtenderContext,
    ) -> AtomicResult<WasmGetContext> {
        Ok(WasmGetContext {
            request_url: context.url.as_str().to_string(),
            requested_subject: context.db_resource.get_subject().to_string(),
            agent_subject: context.for_agent.to_string(),
            snapshot: self.encode_resource(context.db_resource)?,
        })
    }

    async fn build_commit_context<'a>(
        &self,
        context: &'a class_extender::CommitExtenderContext<'a>,
    ) -> AtomicResult<WasmCommitContext> {
        // Plugins parse `commit_json` into `atomic_plugin::Commit`, which
        // requires the `subject` field. The deterministic serializer
        // strips `subject` for genesis commits (because the signature
        // derivation can't include it — circular dep), so using it here
        // makes every genesis commit fail with "missing field subject"
        // inside the plugin's WASM before user logic runs. The plugin
        // doesn't care about signing-deterministic output; it just needs
        // to inspect the commit. Use a regular `to_json_ad` of the commit
        // resource — that always includes `subject`.
        let commit_resource = context.commit.into_resource(context.store).await?;
        let origin = context
            .store
            .get_base_domain()
            .unwrap_or_else(|| "http://localhost".to_string());
        Ok(WasmCommitContext {
            subject: context.resource.get_subject().to_string(),
            commit_json: commit_resource.to_json_ad(Some(&origin))?,
            snapshot: self.encode_resource(context.resource)?,
            is_new: context.is_new,
        })
    }

    fn encode_resource(&self, resource: &Resource) -> AtomicResult<WasmResourceJson> {
        Ok(WasmResourceJson {
            subject: resource.get_subject().to_string(),
            json_ad: resource.to_json_ad(None)?,
        })
    }

    fn inflate_resource_response<'a>(
        &self,
        payload: WasmResourceResponse,
        store: &'a atomic_lib::Db,
    ) -> Pin<Box<dyn Future<Output = AtomicResult<ResourceResponse>> + Send + 'a>> {
        Box::pin(async move {
            let parse_opts = ParseOpts {
                save: SaveOpts::DontSave,
                for_agent: ForAgent::Sudo,
                ..Default::default()
            };

            let mut base =
                parse_json_ad_resource(&payload.primary.json_ad, store, &parse_opts).await?;
            base.set_subject(payload.primary.subject);

            let mut referenced = Vec::new();
            for item in payload.referenced {
                let mut resource =
                    parse_json_ad_resource(&item.json_ad, store, &parse_opts).await?;
                resource.set_subject(item.subject);
                referenced.push(resource);
            }

            if referenced.is_empty() {
                Ok(ResourceResponse::Resource(base))
            } else {
                Ok(ResourceResponse::ResourceWithReferenced(base, referenced))
            }
        })
    }
}

struct PluginHostState {
    table: ResourceTable,
    ctx: WasiCtx,
    http: WasiHttpCtx,
    db: Arc<Db>,
    plugin_subject: Option<String>,
    agent: Option<Agent>,
    limits: StoreLimits,
    manifest: Option<PluginManifest>,
}

impl PluginHostState {
    fn new(
        db: Arc<Db>,
        owned_folder_path: &Option<PathBuf>,
        plugin_subject: Option<String>,
        agent: Option<Agent>,
        manifest: Option<PluginManifest>,
    ) -> AtomicResult<Self> {
        let mut builder = WasiCtxBuilder::new();
        // Plugins should not have access to the host's stdin, stdout and stderr.
        // But it could be useful during development.
        // builder
        //     .inherit_stdout()
        //     .inherit_stderr()
        //     .inherit_stdin()

        if PluginManifest::option_has_permission(manifest.as_ref(), PermissionType::Network) {
            builder.inherit_network();
        }

        if let Some(owned_folder_path) = owned_folder_path {
            let has_storage =
                PluginManifest::option_has_permission(manifest.as_ref(), PermissionType::Storage);

            let dir_perms = if has_storage {
                DirPerms::READ | DirPerms::MUTATE
            } else {
                DirPerms::READ
            };

            let file_perms = if has_storage {
                FilePerms::READ | FilePerms::WRITE
            } else {
                FilePerms::READ
            };

            builder
                .preopened_dir(owned_folder_path.clone(), "/", dir_perms, file_perms)
                .map_err(|e| AtomicError::from(format!("Failed to preopen directory: {}", e)))?;
        }

        let ctx = builder.build();

        let memory_limit_bytes = if PluginManifest::option_has_permission(
            manifest.as_ref(),
            PermissionType::ExtendedMemory,
        ) {
            MEMORY_LIMIT_BYTES_EXTENDED
        } else {
            MEMORY_LIMIT_BYTES
        };

        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_limit_bytes)
            .build();

        Ok(Self {
            table: ResourceTable::new(),
            ctx,
            http: WasiHttpCtx::new(),
            db,
            plugin_subject,
            agent,
            limits,
            manifest,
        })
    }
}

impl ResourceLimiter for PluginHostState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.limits.table_growing(current, desired, maximum)
    }
}

impl WasiView for PluginHostState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for PluginHostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: Default::default(),
        }
    }
}

impl bindings::atomic::class_extender::host::Host for PluginHostState {
    async fn get_resource(
        &mut self,
        subject: String,
        _agent: Option<String>,
    ) -> Result<WasmResourceJson, String> {
        let for_agent = self
            .agent
            .as_ref()
            .map(ForAgent::from)
            .unwrap_or(ForAgent::Public);

        if !subject.starts_with(&self.db.get_server_url()) {
            // If the plugin does not have network permissions we block the request since the plugin could send data to remote servers via these requests.
            if !PluginManifest::option_has_permission(
                self.manifest.as_ref(),
                PermissionType::Network,
            ) {
                return Err("Plugin does not have network access".to_string());
            }

            let resource = self
                .db
                .fetch_resource(&subject, self.agent.as_ref())
                .await
                .map_err(|e| e.to_string())?;

            return Ok(WasmResourceJson {
                subject: resource.get_subject().to_string(),
                json_ad: resource.to_json_ad(None).map_err(|e| e.to_string())?,
            });
        }

        let resource = self
            .db
            .get_resource_extended(&subject.into(), false, &for_agent)
            .await
            .map_err(|e| e.to_string())?
            .to_single();

        Ok(WasmResourceJson {
            subject: resource.get_subject().to_string(),
            json_ad: resource.to_json_ad(None).map_err(|e| e.to_string())?,
        })
    }

    async fn query(
        &mut self,
        property: String,
        value: String,
        _agent: Option<String>,
    ) -> Result<Vec<WasmResourceJson>, String> {
        let for_agent = self
            .agent
            .as_ref()
            .map(ForAgent::from)
            .unwrap_or(ForAgent::Public);

        let mut query = Query::new_prop_val(&property, &value);
        query.for_agent = for_agent;

        let result = self.db.query(&query).await.map_err(|e| e.to_string())?;

        let mut resources = Vec::new();

        for resource in result.resources {
            resources.push(WasmResourceJson {
                subject: resource.get_subject().to_string(),
                json_ad: resource.to_json_ad(None).map_err(|e| e.to_string())?,
            });
        }

        Ok(resources)
    }

    async fn commit(&mut self, commit: String) -> Result<(), String> {
        let Some(agent) = &self.agent else {
            return Err("Plugin does not have an agent".to_string());
        };

        // The plugin SDK's `CommitBuilder` serializes with full set / remove
        // payloads (HashMap<String, JsonValue> / HashSet<String>). The
        // canonical `CommitBuilderJSON` only carries `loro_update`, so plugins
        // that build a commit by accumulating `set` calls would otherwise
        // arrive with no Loro update and get rejected. Parse the wire shape
        // directly here and convert each JsonValue → typed `Value` via the
        // property's datatype, then `sign_at` materializes the Loro update.
        #[derive(serde::Deserialize)]
        struct PluginCommitWire {
            subject: String,
            #[serde(default)]
            set: std::collections::HashMap<String, serde_json::Value>,
            #[serde(default)]
            remove: HashSet<String>,
            #[serde(default)]
            destroy: bool,
            #[serde(default)]
            previous_commit: Option<String>,
        }

        let wire: PluginCommitWire =
            serde_json::from_str(&commit).map_err(|e| format!("Invalid commit JSON: {e}"))?;

        let mut commit_builder = CommitBuilder::new(wire.subject.into());
        commit_builder.destroy(wire.destroy);
        // `previous_commit` is intentionally ignored: `sign()` overrides it
        // from the resource's `lastCommit` propval, so any value the plugin
        // supplies would be discarded anyway.
        let _ = wire.previous_commit;
        for prop in wire.remove {
            commit_builder.remove(prop);
        }
        let parse_opts = ParseOpts::default();
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

        // We do not allow plugins to edit plugin resources as that would allow them to install or update code without the user's consent.
        if check_if_commit_changes_plugin(&commit, &resource).map_err(|e| e.to_string())? {
            return Err("Plugin cannot edit plugin resources".to_string());
        }

        let opts = CommitOpts {
            validate_schema: true,
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

    async fn get_config(&mut self) -> String {
        let Some(subject) = &self.plugin_subject else {
            return "{}".to_string();
        };

        let Ok(plugin_resource) = self
            .db
            .get_resource(&atomic_lib::Subject::from_raw(subject, None))
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
            atomic_lib::Value::Json(json_val) => json_val.to_string(),
            atomic_lib::Value::String(s) => match serde_json::from_str::<serde_json::Value>(s) {
                Ok(parsed) if parsed.is_object() => s.clone(),
                _ => "{}".to_string(),
            },
            atomic_lib::Value::NestedResource(atomic_lib::values::SubResource::Nested(
                propvals,
            )) => {
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
}

fn validate_plugin_zip(
    zip: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
) -> AtomicResult<PluginManifest> {
    // Check for plugin.wasm
    if zip.by_name("plugin.wasm").is_err() {
        return Err(AtomicError::from("Missing plugin.wasm"));
    }

    // Check for plugin.json and read it
    let file = zip
        .by_name("plugin.json")
        .map_err(|_| AtomicError::from("Missing plugin.json"))?;

    let manifest = PluginManifest::from_reader(file)?;

    let mut has_ui_js = false;

    for i in 0..zip.len() {
        let file = zip
            .by_index(i)
            .map_err(|e| AtomicError::from(e.to_string()))?;
        let name = file.name();
        if name == "plugin.wasm"
            || name == "plugin.json"
            || name == "ui.js"
            || name == "ui.css"
            || name.starts_with("assets/")
        {
            if name == "ui.js" {
                has_ui_js = true;
            }
            continue;
        }
        // If it's a directory "assets/", that's fine too.
        if name == "assets/" {
            continue;
        }
        return Err(AtomicError::from(format!(
            "Illegal file found in zip: {}. Only plugin.wasm, plugin.json, ui.js, ui.css and assets/ are allowed.",
            name
        )));
    }

    if has_ui_js && !manifest.has_permission(PermissionType::CustomView) {
        return Err(AtomicError::from(
            "Plugin contains ui.js but does not have the 'custom-view' permission.",
        ));
    }

    Ok(manifest)
}

fn extract_plugin_to_disk(
    zip: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
    plugins_dir: &Path,
    encoded_subject: &str,
    namespace: &str,
    name: &str,
) -> AtomicResult<PathBuf> {
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(encoded_subject);

    // We do not clear the directory, as multiple plugins might share this scope.
    // Existing files (wasm, json) will be overwritten by zip extraction.
    // The assets directory will be merged (existing files kept, new files written/overwritten).
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| AtomicError::from(format!("Failed to create plugin directory: {}", e)))?;

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| AtomicError::from(e.to_string()))?;
        let file_name = file.name().to_string();

        let target_path = if file_name == "plugin.wasm" {
            target_dir.join(format!("{}.{}.wasm", namespace, name))
        } else if file_name == "plugin.json" {
            target_dir.join(format!("{}.{}.json", namespace, name))
        } else if file_name == "ui.js" {
            target_dir.join(format!("{}.{}.ui.js", namespace, name))
        } else if file_name == "ui.css" {
            target_dir.join(format!("{}.{}.ui.css", namespace, name))
        } else if file_name.starts_with("assets/") {
            // Replace "assets/" with "{namespace}/"
            let stripped = file_name.strip_prefix("assets/").unwrap();
            let assets_dir = target_dir.join(namespace);
            if stripped.is_empty() {
                // It is the "assets/" directory itself
                assets_dir
            } else {
                // Zip entry names are attacker-controlled: reject anything that is not a
                // plain relative path made of normal components (no `..`, no absolute paths).
                let relative = safe_relative_path(stripped).ok_or_else(|| {
                    AtomicError::from(format!(
                        "Plugin zip contains an unsafe asset path: {}",
                        file_name
                    ))
                })?;
                assets_dir.join(relative)
            }
        } else {
            continue;
        };

        if file.is_dir() {
            std::fs::create_dir_all(&target_path).map_err(|e| {
                AtomicError::from(format!(
                    "Failed to create directory {}: {}",
                    target_path.display(),
                    e
                ))
            })?;
        } else {
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AtomicError::from(format!(
                        "Failed to create directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            let mut outfile = std::fs::File::create(&target_path).map_err(|e| {
                AtomicError::from(format!(
                    "Failed to create file {}: {}",
                    target_path.display(),
                    e
                ))
            })?;
            std::io::copy(&mut file, &mut outfile).map_err(|e| {
                AtomicError::from(format!(
                    "Failed to write file {}: {}",
                    target_path.display(),
                    e
                ))
            })?;
        }
    }

    Ok(target_dir)
}

fn find_wasm_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension() == Some(OsStr::new("wasm")) {
                files.push(path);
            }
        }
    }
    files
}

fn setup_plugin_data_dir(wasm_file_path: &Path, plugin_dir: &Path) -> Option<PathBuf> {
    let filename = wasm_file_path.file_name().and_then(|s| s.to_str())?;

    // Remove .wasm extension
    let stem = wasm_file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);

    let stem_path = Path::new(stem);

    // If there is no second extension (e.g. just my-plugin.wasm), we don't grant access to a folder.
    // This is to prevent plugins from accessing arbitrary folders.
    // Only namespaced plugins (e.g. google.calendar.wasm or my-plugin.plugin.wasm) get a folder.
    stem_path.extension()?;

    // Remove the second extension (e.g. .plugin in my_script.plugin.wasm), if present.
    // This allows for any suffix without dots.
    let plugin_name = stem_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(stem);

    let data_dir = plugin_dir.join(plugin_name);

    if !data_dir.exists() {
        if let Err(err) = std::fs::create_dir_all(&data_dir) {
            warn!(
                error = %err,
                path = %data_dir.display(),
                "Failed to create data directory for plugin"
            );
            return None;
        }
    }

    if data_dir.exists() {
        Some(data_dir)
    } else {
        None
    }
}

/// Returns `Some(path)` if `raw` is a relative path consisting only of normal components
/// (no `..`, no root/prefix, no `.`), otherwise `None`.
fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    use std::path::Component;

    // Zip archives always use `/`, but be strict about backslashes too so a Windows-style
    // traversal cannot slip through on any platform.
    if raw.contains('\\') || raw.contains('\0') {
        return None;
    }
    let path = Path::new(raw);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    Some(out)
}

/// Errors unless `child` is exactly one path component below `parent`.
fn ensure_direct_child(parent: &Path, child: &Path) -> AtomicResult<()> {
    let is_direct_child = child.parent() == Some(parent)
        && matches!(
            child.components().next_back(),
            Some(std::path::Component::Normal(_))
        );
    if !is_direct_child {
        return Err(AtomicError::from(format!(
            "Refusing to touch path outside plugin directory: {}",
            child.display()
        )));
    }
    Ok(())
}

pub async fn uninstall_plugin(
    name: &str,
    namespace: &str,
    drive_subject: &str,
    store: &Db,
    plugins_dir: &Path,
) -> AtomicResult<()> {
    // `namespace` and `name` may come straight from a user-controlled Plugin resource
    // (see `plugin.rs`), not only from a validated manifest. They are used to build
    // filesystem paths below, so they must be plain path segments (GHSA-vr56-vwrw-w2vg).
    validate_plugin_identifiers(namespace, name)?;

    let encoded_subject = general_purpose::URL_SAFE.encode(drive_subject);
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(&encoded_subject);

    if !target_dir.exists() {
        return Err(AtomicError::not_found(format!(
            "Plugin directory not found for drive: {}",
            drive_subject
        )));
    }

    let wasm_filename = format!("{}.{}.wasm", namespace, name);
    let wasm_path = target_dir.join(&wasm_filename);
    let json_path = target_dir.join(format!("{}.{}.json", namespace, name));
    let ui_js_path = target_dir.join(format!("{}.{}.ui.js", namespace, name));
    let ui_css_path = target_dir.join(format!("{}.{}.ui.css", namespace, name));
    let assets_dir = target_dir.join(namespace);

    // Defense in depth: every path we are about to delete must be a direct child of `target_dir`.
    for path in [
        &wasm_path,
        &json_path,
        &ui_js_path,
        &ui_css_path,
        &assets_dir,
    ] {
        ensure_direct_child(&target_dir, path)?;
    }

    if !wasm_path.exists() {
        return Err(AtomicError::not_found(format!(
            "Plugin {}.{} not found",
            namespace, name
        )));
    }

    // 1. Remove from DB
    let id = format!("{}:{}", drive_subject, wasm_filename);
    store.remove_class_extender(&id)?;

    // 2. Remove from disk
    std::fs::remove_file(&wasm_path).map_err(|e| {
        AtomicError::from(format!(
            "Failed to remove wasm file {}: {}",
            wasm_path.display(),
            e
        ))
    })?;

    if json_path.exists() {
        std::fs::remove_file(&json_path).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove json file {}: {}",
                json_path.display(),
                e
            ))
        })?;
    }

    if ui_js_path.exists() {
        std::fs::remove_file(&ui_js_path).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove ui.js file {}: {}",
                ui_js_path.display(),
                e
            ))
        })?;
    }

    if ui_css_path.exists() {
        std::fs::remove_file(&ui_css_path).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove ui.css file {}: {}",
                ui_css_path.display(),
                e
            ))
        })?;
    }

    // 3. Handle assets folder
    // Check if other plugins are using the same namespace in this drive
    let mut namespace_still_used = false;
    if let Ok(entries) = std::fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    // Check for other plugins in the same namespace
                    if file_name.starts_with(&format!("{}.", namespace))
                        && (file_name.ends_with(".wasm") || file_name.ends_with(".json"))
                    {
                        namespace_still_used = true;
                        break;
                    }
                }
            }
        }
    }

    if !namespace_still_used && assets_dir.is_dir() {
        info!("Removing unused assets directory: {}", assets_dir.display());
        std::fs::remove_dir_all(&assets_dir).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove assets directory {}: {}",
                assets_dir.display(),
                e
            ))
        })?;
    }

    delete_plugin_meta(store, drive_subject, namespace, name).await?;

    info!("Uninstalled plugin {}.{}", namespace, name);

    Ok(())
}

pub async fn install_or_update_plugin(
    zip_file: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
    drive_subject: &str,
    plugin_subject: &str,
    store: &Db,
    plugins_dir: &Path,
    plugin_cache_dir: &Path,
) -> AtomicResult<()> {
    // 1. Validation
    let manifest = validate_plugin_zip(zip_file)?;

    if !compare_manifest_to_resource(&manifest, plugin_subject, store).await? {
        return Err(AtomicError::from(
            "Manifest namespace + name does match that of the resource",
        ));
    }

    let wasm_target_name = format!("{}.{}.wasm", manifest.namespace, manifest.name);
    let json_target_name = format!("{}.{}.json", manifest.namespace, manifest.name);
    let encoded_subject = general_purpose::URL_SAFE.encode(drive_subject);

    // Compute target paths for rollback tracking
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(&encoded_subject);
    let wasm_path = target_dir.join(&wasm_target_name);
    let json_path = target_dir.join(&json_target_name);
    let ui_js_path = target_dir.join(format!("{}.{}.ui.js", manifest.namespace, manifest.name));
    let ui_css_path = target_dir.join(format!("{}.{}.ui.css", manifest.namespace, manifest.name));

    // Determine if this is a fresh install or an update by saving the old metadata
    let meta_key = PluginMetaKey::new(drive_subject, &manifest.namespace, &manifest.name);
    let old_plugin_meta = store.get_plugin_meta(&meta_key)?;
    let is_update = old_plugin_meta.is_some();

    // Back up existing files before extraction so we can restore them on failure
    let wasm_backup = wasm_path.with_extension("wasm.bak");
    let json_backup = json_path.with_extension("json.bak");
    let ui_js_backup = ui_js_path.with_extension("js.bak");
    let ui_css_backup = ui_css_path.with_extension("css.bak");

    if is_update {
        if wasm_path.exists() {
            std::fs::copy(&wasm_path, &wasm_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing wasm file: {}", e))
            })?;
        }
        if json_path.exists() {
            std::fs::copy(&json_path, &json_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing json file: {}", e))
            })?;
        }
        if ui_js_path.exists() {
            std::fs::copy(&ui_js_path, &ui_js_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing ui.js file: {}", e))
            })?;
        }
        if ui_css_path.exists() {
            std::fs::copy(&ui_css_path, &ui_css_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing ui.css file: {}", e))
            })?;
        }
    }

    // Run the installation steps. If any step fails, we roll back all side effects.
    let result: AtomicResult<()> = async {
        // 2. Extract plugin files to disk
        let target_dir = extract_plugin_to_disk(
            zip_file,
            plugins_dir,
            &encoded_subject,
            &manifest.namespace,
            &manifest.name,
        )?;

        // 3. Create a new agent for the plugin if needed
        create_plugin_meta(store, drive_subject, &manifest, plugin_subject).await?;

        // 4. Load Plugin
        let engine = Arc::new(build_engine()?);
        let wasm_load_path = target_dir.join(&wasm_target_name);

        let scope = ClassExtenderScope::Drive(drive_subject.to_string());
        let scoped_cache = plugin_cache_dir.join("scoped").join(&encoded_subject);

        if !scoped_cache.exists() {
            std::fs::create_dir_all(&scoped_cache).ok();
        }

        let (plugin, _) = load_plugin_from_disk(
            &wasm_load_path,
            &target_dir,
            &scoped_cache,
            scope,
            engine,
            store,
        )
        .await?;

        if let Some(plugin) = plugin {
            store.add_class_extender(plugin)?;
        } else {
            return Err(AtomicError::from("Failed to load installed plugin"));
        }

        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            // Success: clean up backup files
            if is_update {
                std::fs::remove_file(&wasm_backup).ok();
                std::fs::remove_file(&json_backup).ok();
                std::fs::remove_file(&ui_js_backup).ok();
                std::fs::remove_file(&ui_css_backup).ok();
            }
            Ok(())
        }
        Err(e) => {
            warn!("Plugin installation failed, rolling back: {}", e);
            rollback_plugin_install(
                store,
                drive_subject,
                &manifest.namespace,
                &manifest.name,
                &meta_key,
                old_plugin_meta,
                &wasm_path,
                &json_path,
                &ui_js_path,
                &ui_css_path,
                &wasm_backup,
                &json_backup,
                &ui_js_backup,
                &ui_css_backup,
            )
            .await;
            Err(e)
        }
    }
}

/// Rolls back a failed plugin installation by restoring file backups and metadata
/// (for updates) or removing newly created files and metadata (for fresh installs).
#[allow(clippy::too_many_arguments)]
async fn rollback_plugin_install(
    store: &Db,
    drive_subject: &str,
    namespace: &str,
    name: &str,
    meta_key: &PluginMetaKey,
    old_plugin_meta: Option<PluginMeta>,
    wasm_path: &Path,
    json_path: &Path,
    ui_js_path: &Path,
    ui_css_path: &Path,
    wasm_backup: &Path,
    json_backup: &Path,
    ui_js_backup: &Path,
    ui_css_backup: &Path,
) {
    if let Some(old_meta) = old_plugin_meta {
        // Update: restore backed up files
        if wasm_backup.exists() {
            if let Err(e) = std::fs::rename(wasm_backup, wasm_path) {
                error!("Rollback: failed to restore wasm backup: {}", e);
            }
        }
        if json_backup.exists() {
            if let Err(e) = std::fs::rename(json_backup, json_path) {
                error!("Rollback: failed to restore json backup: {}", e);
            }
        }
        if ui_js_backup.exists() {
            if let Err(e) = std::fs::rename(ui_js_backup, ui_js_path) {
                error!("Rollback: failed to restore ui.js backup: {}", e);
            }
        }
        if ui_css_backup.exists() {
            if let Err(e) = std::fs::rename(ui_css_backup, ui_css_path) {
                error!("Rollback: failed to restore ui.css backup: {}", e);
            }
        }

        // Restore the old plugin metadata
        if let Err(e) = store.set_plugin_meta(meta_key, &old_meta) {
            error!("Rollback: failed to restore plugin metadata: {}", e);
        }
    } else {
        // Fresh install: remove newly created files
        if wasm_path.exists() {
            std::fs::remove_file(wasm_path).ok();
        }
        if json_path.exists() {
            std::fs::remove_file(json_path).ok();
        }
        if ui_js_path.exists() {
            std::fs::remove_file(ui_js_path).ok();
        }
        if ui_css_path.exists() {
            std::fs::remove_file(ui_css_path).ok();
        }

        // Clean up metadata that was created during this failed install
        if let Err(e) = delete_plugin_meta(store, drive_subject, namespace, name).await {
            error!("Rollback: failed to delete plugin metadata: {}", e);
        }
    }
}

async fn create_plugin_meta(
    store: &Db,
    drive_subject: &str,
    manifest: &PluginManifest,
    plugin_subject: &str,
) -> AtomicResult<()> {
    let namespace = &manifest.namespace;
    let name = &manifest.name;

    let key = PluginMetaKey::new(drive_subject, namespace, name);
    let plugin_meta = store.get_plugin_meta(&key)?;

    let agent: Agent = if let Some(plugin_meta) = plugin_meta {
        Agent::from_secret(&plugin_meta.agent_secret)?
    } else {
        // If the plugin meta does not exist yet we create a new agent.
        let new_agent = Agent::new(Some(name))?;

        let mut agent_resource = new_agent.to_resource()?;
        let full_name = format!("{}/{}", namespace, name);
        agent_resource
            .set(
                urls::NAME.into(),
                atomic_lib::Value::String(full_name),
                store,
            )
            .await?;
        agent_resource.save_locally(store).await?;

        new_agent
    };

    if manifest.has_permission(PermissionType::FullDriveAccess) {
        let mut drive = store.get_resource(&drive_subject.into()).await?;
        drive.push(
            urls::WRITE,
            atomic_lib::values::SubResource::Subject(agent.subject.clone()),
            true,
        )?;
        drive.push(
            urls::READ,
            atomic_lib::values::SubResource::Subject(agent.subject.clone()),
            true,
        )?;
        drive.save(store).await?;
    }

    store.set_plugin_meta(
        &key,
        &PluginMeta {
            subject: plugin_subject.to_string(),
            agent_secret: agent.build_secret()?.clone(),
            manifest: manifest.clone(),
        },
    )?;

    Ok(())
}

async fn delete_plugin_meta(
    store: &Db,
    drive_subject: &str,
    namespace: &str,
    name: &str,
) -> AtomicResult<()> {
    let key = PluginMetaKey::new(drive_subject, namespace, name);

    let Some(plugin_meta) = store.get_plugin_meta(&key)? else {
        // The plugin does not have any metadata so we don't have to delete anything.
        return Ok(());
    };

    // Delete the agent resource
    let agent = Agent::from_secret(&plugin_meta.agent_secret)?;
    let mut agent_resource = store.get_resource(&agent.subject.clone()).await?;
    agent_resource.destroy(store).await?;

    // Delete the plugin metadata
    store.delete_plugin_meta(&key)?;

    Ok(())
}

async fn load_plugin_from_disk(
    path: &Path,
    plugin_dir: &Path,
    plugin_cache_path: &Path,
    scope: ClassExtenderScope,
    engine: Arc<Engine>,
    db: &Db,
) -> AtomicResult<(Option<ClassExtender>, PathBuf)> {
    let owned_folder_path = setup_plugin_data_dir(path, plugin_dir);

    // Attempt to find the plugin subject from the store metadata
    let (plugin_subject, agent, manifest) = match &scope {
        ClassExtenderScope::Drive(drive_subject) => {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let stem_path = Path::new(stem);
            let namespace = stem_path.file_stem().and_then(|s| s.to_str());
            let name = stem_path.extension().and_then(|s| s.to_str());

            let (Some(namespace), Some(name)) = (namespace, name) else {
                return Err(AtomicError::from(format!(
                    "Invalid plugin filename (expected namespace.name.wasm): {}",
                    path.display()
                )));
            };

            let key = PluginMetaKey::new(drive_subject, namespace, name);
            let meta = db.get_plugin_meta(&key).map_err(|e| {
                AtomicError::from(format!("Failed to get plugin metadata from store: {}", e))
            })?;

            let Some(m) = meta else {
                return Err(AtomicError::from(format!(
                    "Plugin metadata not found in store for {}.{}",
                    namespace, name
                )));
            };

            let agent = Agent::from_secret(&m.agent_secret)?;

            (Some(m.subject), Some(agent), Some(m.manifest))
        }
        ClassExtenderScope::Global => (None, None, None),
    };

    let wasm_bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read Wasm file at {}: {}", path.display(), e);
            return Ok((None, PathBuf::new())); // Or return Error? Original code returned None.
        }
    };

    let hash = digest(&SHA256, &wasm_bytes);
    let hash_hex = hex_encode(hash.as_ref());
    let cwasm_filename = format!("{}.cwasm", hash_hex);
    let cwasm_path = plugin_cache_path.join(cwasm_filename);
    let cwasm_path_ret = cwasm_path.clone();

    match WasmPlugin::load(
        engine.clone(),
        &wasm_bytes,
        path,
        &cwasm_path,
        owned_folder_path,
        db,
        scope,
        plugin_subject,
        agent,
        manifest,
    )
    .await
    {
        Ok(plugin) => {
            info!(
                "Loaded {}",
                path.file_name().unwrap_or(OsStr::new("Unknown")).display()
            );
            Ok((Some(plugin.into_class_extender()), cwasm_path_ret))
        }
        Err(err) => {
            error!(
                error = %err,
                path = %path.display(),
                "Failed to load Wasm class extender"
            );
            Ok((None, cwasm_path_ret))
        }
    }
}

fn compile_and_save_component(
    engine: &Engine,
    wasm_bytes: &[u8],
    wasm_path: &Path,
    cwasm_path: &Path,
) -> AtomicResult<Component> {
    info!(
        "Pre-compiling {}",
        wasm_path
            .file_name()
            .unwrap_or(OsStr::new("Unknown"))
            .display()
    );

    let component_bytes = engine
        .precompile_component(wasm_bytes)
        .map_err(|e| AtomicError::from(format!("Failed to precompile component: {}", e)))?;

    if let Err(e) = std::fs::write(cwasm_path, &component_bytes) {
        warn!(
            "Failed to write cwasm file to {}: {}",
            cwasm_path.display(),
            e
        );
    } else {
        info!("Saved pre-compiled component to {}", cwasm_path.display());
    }

    unsafe { Component::deserialize(engine, &component_bytes) }
        .map_err(|e| AtomicError::from(format!("Failed to deserialize compiled component: {}", e)))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn cleanup_cache(cache_dir: &Path, used_files: &HashSet<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension() == Some(std::ffi::OsStr::new("cwasm"))
                && !used_files.contains(&path)
            {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(
                        "Failed to delete unused cwasm file {}: {}",
                        path.display(),
                        e
                    );
                } else {
                    info!("Deleted unused cwasm file: {}", path.display());
                }
            }
        }
    }
}

fn decode_subject(b64_subject: &str) -> AtomicResult<String> {
    let subject = String::from_utf8(
        general_purpose::URL_SAFE
            .decode(b64_subject.as_bytes())
            .map_err(|e| AtomicError::from(format!("Failed to decode subject: {}", e)))?,
    )
    .map_err(|e| AtomicError::from(format!("Failed to decode subject: {}", e)))?;

    Ok(subject)
}

fn check_if_commit_changes_plugin(commit: &Commit, resource: &Resource) -> AtomicResult<bool> {
    // Check if the resource it changes is currently a plugin.
    if let Ok(is_a) = resource.get(urls::IS_A) {
        let resource_classes = is_a.to_subjects(None)?;

        if resource_classes.contains(&urls::PLUGIN.to_string()) {
            return Ok(true);
        }
    }

    // Check if the Loro update sets isA to include Plugin.
    if let Some(loro_bytes) = &commit.loro_update {
        let doc = atomic_lib::loro::AtomicLoroDoc::new();
        let _ = doc.import_update(loro_bytes);
        if let Some(is_a_str) = doc.get_string_property(urls::IS_A) {
            if is_a_str.contains(urls::PLUGIN) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

async fn compare_manifest_to_resource(
    manifest: &PluginManifest,
    subject: &str,
    db: &Db,
) -> AtomicResult<bool> {
    let resource = db.get_resource(&subject.into()).await?;
    let name = resource.get(urls::NAME)?;
    let namespace = resource.get(urls::NAMESPACE)?;

    if !name.contains_value(&Value::String(manifest.name.clone())) {
        return Ok(false);
    }

    if !namespace.contains_value(&Value::String(manifest.namespace.clone())) {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod path_safety_tests {
    use super::*;

    #[test]
    fn safe_relative_path_rejects_traversal() {
        assert!(safe_relative_path("../x").is_none());
        assert!(safe_relative_path("a/../../x").is_none());
        assert!(safe_relative_path("/etc/passwd").is_none());
        assert!(safe_relative_path("a\\..\\b").is_none());
        assert!(safe_relative_path("").is_none());
        assert_eq!(
            safe_relative_path("img/logo.png"),
            Some(PathBuf::from("img/logo.png"))
        );
    }

    #[test]
    fn ensure_direct_child_rejects_escapes() {
        let parent = Path::new("/plugins/scoped/abc");
        assert!(ensure_direct_child(parent, &parent.join("ns.name.wasm")).is_ok());
        assert!(ensure_direct_child(parent, &parent.join("../x")).is_err());
        assert!(ensure_direct_child(parent, &parent.join("a/b")).is_err());
        assert!(ensure_direct_child(parent, parent).is_err());
    }

    /// Regression test for GHSA-vr56-vwrw-w2vg: a traversal payload in namespace/name must
    /// never delete anything outside the drive's scoped plugin directory.
    #[tokio::test]
    async fn uninstall_rejects_path_traversal() {
        let db = Db::init_temp("uninstall_rejects_path_traversal")
            .await
            .unwrap();
        let (_agent, drive) = db.setup("Attacker").await.unwrap();

        let plugins_dir =
            std::env::temp_dir().join(format!("atomic_uninstall_traversal_{}", std::process::id()));
        let victim_dir = plugins_dir.join("victim");
        std::fs::create_dir_all(&victim_dir).unwrap();
        let victim_file = victim_dir.join("target.wasm");
        std::fs::write(&victim_file, b"do not delete").unwrap();

        let encoded_subject = general_purpose::URL_SAFE.encode(&drive);
        let target_dir = plugins_dir
            .join(CLASS_EXTENDER_DIR_NAME)
            .join("scoped")
            .join(&encoded_subject);
        std::fs::create_dir_all(&target_dir).unwrap();

        // Traverses from target_dir up to plugins_dir/victim/target.wasm
        let result =
            uninstall_plugin("target", "../../../victim/", &drive, &db, &plugins_dir).await;
        assert!(result.is_err(), "traversal namespace must be rejected");
        assert!(victim_file.exists(), "victim file must not be deleted");

        // Same for the assets dir branch: namespace resolving to a directory outside target_dir.
        let result = uninstall_plugin("target", "../../../victim", &drive, &db, &plugins_dir).await;
        assert!(result.is_err());
        assert!(victim_dir.exists(), "victim directory must not be deleted");

        std::fs::remove_dir_all(&plugins_dir).ok();
    }
}
