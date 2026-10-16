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

use std::{path::PathBuf, sync::Arc};

use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::{
        ClassExtender, ClassExtenderScope, CommitExtenderContext, GetExtenderContext,
    },
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
    bindings::atomic::host::types::Severity,
    convert::{to_wit_resource, wit_value_json},
    module_bindings::{
        atomic::host::context, exports::atomic::host::hooks::CommitInfo, ServerModule as Bindings,
    },
    registry::HostAbiRegistry,
    run::{build_host, AbiHost, AbiState, CallBudget},
    HostError,
};
use crate::plugins::{
    host_core::{self, HostCore, ResourceGrants, Runtime},
    manifest::{CapabilityName, Manifest},
};

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
    pub data_dir: Option<PathBuf>,
    pub manifest: Option<Manifest>,
}

#[derive(Clone)]
pub struct ServerModule {
    inner: Arc<Inner>,
}

struct Inner {
    engine: Arc<Engine>,
    component: Component,
    db: Arc<Db>,
    /// Private to the module: `calls` finds no other app through it yet.
    registry: Arc<HostAbiRegistry>,
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

impl ServerModule {
    /// Loads a component and asks it which classes it extends.
    pub async fn new(
        engine: Arc<Engine>,
        component: Component,
        db: &Db,
        parts: ModuleParts,
    ) -> AtomicResult<Self> {
        let mut inner = Inner {
            engine,
            component,
            db: Arc::new(db.clone()),
            registry: Arc::default(),
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

    /// The classes the module extends.
    pub fn classes(&self) -> &[String] {
        &self.inner.classes
    }

    /// The host of one hook: the Installation resolved now, so a pause or a
    /// revocation takes effect on the next hook.
    async fn host(&self, installed: bool) -> Result<AbiHost, HostError> {
        let inner = &self.inner;
        let budget = Arc::new(CallBudget::default());
        let mut host = match (
            &inner.parts.scope,
            &inner.parts.installation,
            &inner.parts.agent,
        ) {
            (ClassExtenderScope::Drive(drive), Some(installation), Some(agent)) if installed => {
                build_host(
                    &inner.registry,
                    &inner.db,
                    (drive, installation, inner.parts.manifest.clone()),
                    ForAgent::from(agent),
                    0,
                    budget,
                )
                .await?
            }
            _ => AbiHost {
                registry: inner.registry.clone(),
                db: inner.db.clone(),
                drive: String::new(),
                installation: String::new(),
                manifest: None,
                core: HostCore::for_global_module(inner.db.clone())
                    .map_err(|e| super::error(super::code::FORBIDDEN, e))?,
                depth: 0,
                budget,
            },
        };
        host.core = host.core.clone().as_server_module();
        Ok(host)
    }

    async fn instantiate(&self, installed: bool) -> AtomicResult<(Bindings, Store<AbiState>)> {
        let inner = &self.inner;
        let manifest = inner.parts.manifest.as_ref();
        let host = self.host(installed).await.map_err(host_error)?;
        let grants = match (&inner.parts.scope, &inner.parts.installation) {
            (ClassExtenderScope::Drive(drive), Some(installation)) if installed => {
                host_core::installation_grants(&inner.db, drive, installation, manifest).await
            }
            _ => ResourceGrants::from_v2(manifest),
        };
        let limits = host_core::limits(Runtime::ClassExtender, grants);

        let mut state = AbiState::new(host, limits.store_limits());
        if let Some(dir) = &inner.parts.data_dir {
            let writable = manifest.is_some_and(|m| m.has_capability(CapabilityName::Storage));
            state = state
                .with_data_dir(dir, writable)
                .map_err(AtomicError::other_error)?;
        }
        let mut store = Store::new(&inner.engine, state);
        store.limiter(|state| &mut state.limits);
        limits.meter(&mut store).map_err(AtomicError::other_error)?;

        let mut linker = Linker::new(&inner.engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(trap)?;
        Bindings::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state).map_err(trap)?;
        let instance = Bindings::instantiate_async(&mut store, &inner.component, &linker)
            .await
            .map_err(trap)?;
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
        let (instance, mut store) = self.instantiate(true).await?;
        let answer = instance
            .atomic_host_hooks()
            .call_on_get(
                &mut store,
                &to_wit_resource(context.db_resource),
                &context.for_agent.to_string(),
            )
            .await
            .map_err(trap)?
            .map_err(host_error)?;
        let Some(answer) = answer else {
            return Ok(ResourceResponse::Resource(context.db_resource.clone()));
        };

        // Only what the module changed is rebuilt: the rest (a Loro document,
        // say) never crosses the boundary twice. Values are parsed by the
        // datatype of their property, as every other write is.
        let before = to_wit_resource(context.db_resource);
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
        Ok(ResourceResponse::Resource(resource))
    }

    async fn before_commit(&self, context: CommitExtenderContext<'_>) -> AtomicResult<()> {
        if self.signed_by_module(&context) {
            return Ok(());
        }
        let info = self.commit_info(&context).await?;
        let (instance, mut store) = self.instantiate(true).await?;
        let problems = instance
            .atomic_host_hooks()
            .call_before_commit(&mut store, &info, &to_wit_resource(context.resource))
            .await
            .map_err(trap)?;

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
        let (instance, mut store) = self.instantiate(true).await?;
        instance
            .atomic_host_hooks()
            .call_after_commit(&mut store, &info, &to_wit_resource(context.resource))
            .await
            .map_err(trap)?
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
                Box::pin(async move { module.on_get(context).await })
            }))
            .before_commit(ClassExtender::wrap_commit_handler(move |context| {
                let module = before.clone();
                Box::pin(async move { module.before_commit(context).await })
            }))
            .after_commit(ClassExtender::wrap_commit_handler(move |context| {
                let module = after.clone();
                Box::pin(async move { module.after_commit(context).await })
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
