//! Server modules: world `server-module`, the class extender on the host ABI.
//!
//! A module is a component that hooks into the commit and read path of the
//! classes it names (`hooks`). What it can do from there is what any app can
//! do: the `store`, `net` and `calls` imports are the same code as for a
//! `sandboxed-app` ([`AbiState`]), so rights, error codes and the planner are
//! shared. It runs as its Installation's agent: reads are bounded by that agent
//! (the caller and the Installation are the same identity), `store.apply` is
//! signed by it, and a module without an Installation (the operator's `global`
//! folder) is the public agent, which reads what anyone may and writes nothing.
//!
//! Each hook gets a fresh instance. A commit the module's own agent signed does
//! not trigger it, so a module does not react to its own writes.

use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::{
        BoxFuture, ClassExtender, ClassExtenderScope, CommitExtenderContext, GetExtenderContext,
    },
    db::drive_prefix_from_subject,
    errors::{AtomicError, AtomicResult},
    parse::{parse_propval, ParseOpts, SaveOpts},
    storelike::ResourceResponse,
    Db, Storelike,
};
use wasmtime::{
    component::{Component, HasSelf, Linker},
    Engine, Store, Trap,
};

use super::{
    bindings::atomic::host::types::{Problem, Resource as WitResource, Severity},
    convert::{to_wit_resource, wit_value_json},
    module_bindings::{
        atomic::host::context,
        exports::atomic::host::hooks::{CommitInfo, GetAnswer},
        ServerModule as Bindings, ServerModulePre as BindingsPre,
    },
    registry::HostAbiRegistry,
    run::{build_host, AbiHost, AbiState, CallBudget},
    HostError,
};
use crate::plugins::{
    host_core::{self, HostCore, ResourceGrants, Runtime},
    manifest::{CapabilityName, Manifest},
};

/// What a hook gets, instantiation to answer, host calls it waits on included
/// (fuel does not count those). A component yields at every fuel interval, so
/// dropping the hook at the deadline stops it at once. Past it the hook fails
/// like one out of fuel: a `before-commit` refuses the commit, an
/// `after-commit` is logged.
const HOOK_DEADLINE: Duration = Duration::from_secs(5);

pub(super) async fn within<T>(
    deadline: Duration,
    hook: impl Future<Output = AtomicResult<T>>,
) -> AtomicResult<T> {
    tokio::time::timeout(deadline, hook)
        .await
        .unwrap_or_else(|_| {
            Err(AtomicError::other_error(format!(
                "Wasm plugin exceeded its time limit of {} seconds",
                deadline.as_secs_f32()
            )))
        })
}

/// Where a module lives and who it is, as the loader found it.
pub struct ModuleParts {
    /// The file it was loaded from; names its registration.
    pub file_name: String,
    pub scope: ClassExtenderScope,
    /// The Installation (or legacy plugin resource) it belongs to.
    pub installation: Option<String>,
    /// The Installation's agent. Its key is held by the node.
    pub agent: Option<Agent>,
    /// A folder of its own, writable with the `storage` capability.
    pub storage_dir: Option<PathBuf>,
    pub manifest: Option<Manifest>,
    /// The node's registry, so `calls` finds the apps of the drive.
    pub registry: Arc<HostAbiRegistry>,
}

#[derive(Clone)]
pub struct ServerModule {
    inner: Arc<Inner>,
}

/// What runs the hooks.
enum Backend {
    /// A component, in a fresh instance per hook.
    Wasm {
        engine: Arc<Engine>,
        /// The host ABI linked once, so a hook only instantiates.
        pre: BindingsPre<AbiState>,
    },
    /// Compiled in: a built-in app. Same hooks, same imports, same registry.
    Native(Arc<dyn NativeHooks>),
}

/// The `hooks` interface of `atomic-host/wit/host.wit` as a Rust trait, for a
/// module compiled into the server (a built-in app). A native module differs
/// from a component only in how it is loaded: it is registered through
/// [`ServerModule`] like one, so it gets the same `commit-info`, the same
/// "own commits do not trigger it" rule and the same answer handling, and its
/// imports are the very `Host` implementations of [`AbiState`] a component
/// is linked against (`store::Host::query(imports, ..)`), checked by the same
/// `Grant`. It runs for the reader (see [`HostCore::for_builtin`]) because it
/// has no Installation to run as.
pub trait NativeHooks: Send + Sync {
    fn classes(&self) -> Vec<String>;

    fn on_get<'a>(
        &'a self,
        _imports: &'a mut AbiState,
        _resource: WitResource,
        _agent: String,
        _query: Vec<(String, String)>,
    ) -> BoxFuture<'a, Result<Option<GetAnswer>, HostError>> {
        Box::pin(async { Ok(None) })
    }

    fn before_commit<'a>(
        &'a self,
        _imports: &'a mut AbiState,
        _commit: CommitInfo,
        _after: WitResource,
    ) -> BoxFuture<'a, Vec<Problem>> {
        Box::pin(async { Vec::new() })
    }

    fn after_commit<'a>(
        &'a self,
        _imports: &'a mut AbiState,
        _commit: CommitInfo,
        _after: WitResource,
    ) -> BoxFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }
}

struct Inner {
    backend: Backend,
    db: Arc<Db>,
    parts: ModuleParts,
    classes: Vec<String>,
}

fn trap(error: wasmtime::Error) -> AtomicError {
    if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
        return AtomicError::other_error("Wasm plugin exceeded its fuel limit".to_string());
    }
    AtomicError::other_error(error.to_string())
}

fn host_error(error: HostError) -> AtomicError {
    AtomicError::other_error(format!("{}: {}", error.code, error.message))
}

/// Whom a built-in app serves: the reader, and the drive its subject is in.
struct Reader<'a> {
    agent: &'a ForAgent,
    subject: &'a str,
}

impl ServerModule {
    /// Loads a component and asks it which classes it extends.
    pub async fn new(
        engine: Arc<Engine>,
        component: Component,
        db: &Db,
        parts: ModuleParts,
    ) -> AtomicResult<Self> {
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(trap)?;
        Bindings::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state).map_err(trap)?;
        let pre =
            BindingsPre::new(linker.instantiate_pre(&component).map_err(trap)?).map_err(trap)?;
        let mut inner = Inner {
            backend: Backend::Wasm { engine, pre },
            db: Arc::new(db.clone()),
            parts,
            classes: Vec::new(),
        };
        let probe = Self {
            inner: Arc::new(inner),
        };
        // The Installation may not exist yet (activation loads the module in
        // the commit that creates it), and `classes` needs no rights.
        let (instance, mut store) = probe.instantiate(false).await?;
        let classes = instance
            .atomic_host_hooks()
            .call_classes(&mut store)
            .await
            .map_err(trap)?;
        inner = Arc::into_inner(probe.inner).expect("the probe is the only handle");
        inner.classes = classes;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// A module compiled into the server: a built-in app. Registered with
    /// [`ServerModule::into_class_extender`] exactly like a component.
    pub fn native(hooks: Arc<dyn NativeHooks>, db: &Db, parts: ModuleParts) -> Self {
        Self {
            inner: Arc::new(Inner {
                classes: hooks.classes(),
                backend: Backend::Native(hooks),
                db: Arc::new(db.clone()),
                parts,
            }),
        }
    }

    /// The classes the module extends.
    pub fn classes(&self) -> &[String] {
        &self.inner.classes
    }

    /// The host of one hook: the Installation resolved now, so a pause or a
    /// revocation takes effect on the next hook.
    async fn host(
        &self,
        installed: bool,
        reader: Option<&Reader<'_>>,
    ) -> Result<AbiHost, HostError> {
        let inner = &self.inner;
        let budget = Arc::new(CallBudget::default());
        let mut host = match (
            &inner.parts.scope,
            &inner.parts.installation,
            &inner.parts.agent,
        ) {
            (ClassExtenderScope::Drive(drive), Some(installation), Some(agent)) if installed => {
                // A module that calls apps finds the ones installed since it
                // last ran; the others have no use for the query.
                if inner
                    .parts
                    .manifest
                    .as_ref()
                    .is_some_and(|m| !m.uses.is_empty())
                {
                    inner.parts.registry.refresh(&inner.db, drive).await;
                }
                build_host(
                    &inner.parts.registry,
                    &inner.db,
                    (
                        drive,
                        installation,
                        inner.parts.manifest.clone().map(Arc::new),
                    ),
                    ForAgent::from(agent),
                    0,
                    budget,
                )
                .await?
            }
            _ => AbiHost {
                registry: inner.parts.registry.clone(),
                db: inner.db.clone(),
                drive: String::new(),
                installation: String::new(),
                manifest: None,
                core: HostCore::for_builtin(
                    inner.db.clone(),
                    match (&inner.backend, reader) {
                        (Backend::Native(_), Some(reader)) => reader.agent.clone(),
                        _ => ForAgent::Public,
                    },
                ),
                depth: 0,
                budget,
            },
        };
        if let (Backend::Native(_), Some(reader)) = (&inner.backend, reader) {
            host.drive = drive_prefix_from_subject(&reader.subject.into()).to_string();
        }
        host.core = host.core.clone().as_server_module();
        Ok(host)
    }

    /// The imports of one hook and the limits it runs under.
    async fn state(
        &self,
        installed: bool,
        reader: Option<&Reader<'_>>,
    ) -> AtomicResult<(AbiState, host_core::Limits)> {
        let inner = &self.inner;
        let manifest = inner.parts.manifest.as_ref();
        let host = self.host(installed, reader).await.map_err(host_error)?;
        let grants = match (&inner.parts.scope, &inner.parts.installation) {
            (ClassExtenderScope::Drive(drive), Some(installation)) if installed => {
                host_core::installation_grants(&inner.db, drive, installation, manifest).await
            }
            _ => ResourceGrants::from_v2(manifest),
        };
        let limits = host_core::limits(Runtime::ClassExtender, grants);

        let mut state = AbiState::new(host, limits.store_limits());
        if let Some(dir) = &inner.parts.storage_dir {
            let writable = manifest.is_some_and(|m| m.has_capability(CapabilityName::Storage));
            state = state
                .with_storage_dir(dir, writable)
                .map_err(AtomicError::other_error)?;
        }
        Ok((state, limits))
    }

    async fn instantiate(&self, installed: bool) -> AtomicResult<(Bindings, Store<AbiState>)> {
        let Backend::Wasm { engine, pre } = &self.inner.backend else {
            return Err(AtomicError::other_error(
                "a native module has no instance".to_string(),
            ));
        };
        let (state, limits) = self.state(installed, None).await?;
        let mut store = Store::new(engine, state);
        store.limiter(|state| &mut state.limits);
        limits.meter(&mut store).map_err(AtomicError::other_error)?;

        let instance = pre.instantiate_async(&mut store).await.map_err(trap)?;
        Ok((instance, store))
    }

    fn signed_by_module(&self, context: &CommitExtenderContext<'_>) -> bool {
        self.inner
            .parts
            .agent
            .as_ref()
            .is_some_and(|agent| agent.subject == context.commit.signer)
    }

    async fn commit_info(&self, context: &CommitExtenderContext<'_>) -> AtomicResult<CommitInfo> {
        // The commit as plain JSON-AD, `subject` included: the deterministic
        // serialization used for signing leaves it out of a genesis commit.
        let commit = context.commit.into_resource(context.store).await?;
        let origin = context
            .store
            .get_base_domain()
            .unwrap_or_else(|| "http://localhost".to_string());
        Ok(CommitInfo {
            subject: context.resource.get_subject().to_string(),
            signer: context.commit.signer.to_string(),
            commit_json: commit.to_json_ad(Some(&origin))?,
            is_new: context.is_new,
        })
    }

    async fn on_get(&self, context: GetExtenderContext<'_>) -> AtomicResult<ResourceResponse> {
        let resource_wit = to_wit_resource(context.db_resource);
        let agent = context.for_agent.to_string();
        let query: Vec<(String, String)> = context
            .url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let answer = match &self.inner.backend {
            Backend::Wasm { .. } => {
                let (instance, mut store) = self.instantiate(true).await?;
                instance
                    .atomic_host_hooks()
                    .call_on_get(&mut store, &resource_wit, &agent, &query)
                    .await
                    .map_err(trap)?
            }
            Backend::Native(hooks) => {
                let reader = Reader {
                    agent: context.for_agent,
                    subject: context.db_resource.get_subject().as_str(),
                };
                let (mut state, _) = self.state(true, Some(&reader)).await?;
                hooks
                    .on_get(&mut state, resource_wit.clone(), agent, query)
                    .await
            }
        }
        .map_err(host_error)?;
        let Some(GetAnswer {
            resource: answer,
            referenced,
        }) = answer
        else {
            return Ok(ResourceResponse::Resource(context.db_resource.clone()));
        };

        // Only what the module changed is rebuilt: the rest (a Loro document,
        // say) never crosses the boundary twice. Values are parsed by the
        // datatype of their property, as every other write is.
        let before = resource_wit;
        let opts = ParseOpts {
            save: SaveOpts::DontSave,
            for_agent: ForAgent::Sudo,
            ..Default::default()
        };
        let mut resource = context.db_resource.clone();
        for pv in answer
            .propvals
            .iter()
            .filter(|pv| !before.propvals.contains(pv))
        {
            let json = wit_value_json(&pv.value).map_err(host_error)?;
            let (property, value) =
                parse_propval(&pv.property, &json, None, context.store, &opts).await?;
            resource.set_unsafe(property, value)?;
        }
        for pv in &before.propvals {
            if !answer.propvals.iter().any(|a| a.property == pv.property) {
                resource.remove_propval(&pv.property)?;
            }
        }
        if referenced.is_empty() {
            return Ok(ResourceResponse::Resource(resource));
        }

        // Sent along as the store holds them, if the reader may see them.
        let reader = Reader {
            agent: context.for_agent,
            subject: context.db_resource.get_subject().as_str(),
        };
        let (state, _) = self.state(true, Some(&reader)).await?;
        let found = referenced_for_reader(&state.host, context.for_agent, referenced).await;
        Ok(ResourceResponse::ResourceWithReferenced(resource, found))
    }

    async fn before_commit(&self, context: CommitExtenderContext<'_>) -> AtomicResult<()> {
        if self.signed_by_module(&context) {
            return Ok(());
        }
        let info = self.commit_info(&context).await?;
        let after = to_wit_resource(context.resource);
        let problems = match &self.inner.backend {
            Backend::Wasm { .. } => {
                let (instance, mut store) = self.instantiate(true).await?;
                instance
                    .atomic_host_hooks()
                    .call_before_commit(&mut store, &info, &after)
                    .await
                    .map_err(trap)?
            }
            Backend::Native(hooks) => {
                let (mut state, _) = self.state(true, None).await?;
                hooks.before_commit(&mut state, info.clone(), after).await
            }
        };

        let mut refusals = Vec::new();
        for problem in problems {
            match problem.severity {
                Severity::Error => refusals.push(problem.message),
                Severity::Warning => {
                    tracing::warn!(subject = %info.subject, "server module: {}", problem.message)
                }
            }
        }
        if refusals.is_empty() {
            Ok(())
        } else {
            Err(AtomicError::other_error(refusals.join("; ")))
        }
    }

    async fn after_commit(&self, context: CommitExtenderContext<'_>) -> AtomicResult<()> {
        if self.signed_by_module(&context) {
            return Ok(());
        }
        let info = self.commit_info(&context).await?;
        let after = to_wit_resource(context.resource);
        match &self.inner.backend {
            Backend::Wasm { .. } => {
                let (instance, mut store) = self.instantiate(true).await?;
                instance
                    .atomic_host_hooks()
                    .call_after_commit(&mut store, &info, &after)
                    .await
                    .map_err(trap)?
            }
            Backend::Native(hooks) => {
                let (mut state, _) = self.state(true, None).await?;
                hooks.after_commit(&mut state, info, after).await
            }
        }
        .map_err(host_error)
    }

    /// The registration the store keeps, one handler per hook.
    pub fn into_class_extender(self) -> ClassExtender {
        let id = match &self.inner.parts.scope {
            ClassExtenderScope::Drive(drive) => {
                format!("{drive}:{}", self.inner.parts.file_name)
            }
            ClassExtenderScope::Global => format!("global:{}", self.inner.parts.file_name),
        };
        let (get, before, after) = (self.clone(), self.clone(), self.clone());

        let mut builder = ClassExtender::builder()
            .id(id)
            .classes(self.inner.classes.clone())
            .on_resource_get(ClassExtender::wrap_get_handler(move |context| {
                let module = get.clone();
                Box::pin(async move { within(HOOK_DEADLINE, module.on_get(context)).await })
            }))
            .before_commit(ClassExtender::wrap_commit_handler(move |context| {
                let module = before.clone();
                Box::pin(async move { within(HOOK_DEADLINE, module.before_commit(context)).await })
            }))
            .after_commit(ClassExtender::wrap_commit_handler(move |context| {
                let module = after.clone();
                Box::pin(async move { within(HOOK_DEADLINE, module.after_commit(context)).await })
            }))
            .scope(self.inner.parts.scope.clone());
        if let Some(subject) = self.inner.parts.installation.clone() {
            builder = builder.subject(subject);
        }
        builder.build()
    }
}

/// Who the module is and what it was configured with. The agent is the
/// caller of the grant: it is the one every `store` call is checked against.
impl context::Host for AbiState {
    async fn get(&mut self) -> context::ModuleContext {
        let installation = &self.host.installation;
        context::ModuleContext {
            installation: (!installation.is_empty()).then(|| installation.clone()),
            agent: match self.host.core.grant().caller() {
                ForAgent::AgentSubject(subject) => Some(subject.to_string()),
                _ => None,
            },
            config: self.host.core.get_config().await,
        }
    }
}

/// The resources an `on-get` answer points at, as `reader` may see them. The
/// module's own state reads as the Installation's agent, which may see more
/// than the person asking, so the reader is asked too.
pub(super) async fn referenced_for_reader(
    host: &AbiHost,
    reader: &ForAgent,
    referenced: Vec<String>,
) -> Vec<atomic_lib::Resource> {
    let mut found = Vec::new();
    for subject in referenced {
        let Ok(resource) = host.core.get_resource(&subject).await else {
            continue;
        };
        if atomic_lib::hierarchy::check_read(&*host.db, &resource, reader)
            .await
            .is_ok()
        {
            found.push(resource);
        }
    }
    found
}
