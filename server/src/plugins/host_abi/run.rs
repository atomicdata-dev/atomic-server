//! One invocation of an app's `invoke` export, in a fresh instance.
//!
//! Nothing survives between invocations: a new store, a new instance, a new
//! fuel and memory budget. The rights of the invocation are fixed here, when
//! the host is built, from two things only: who asked, and what the app's own
//! Installation holds.

use std::{future::Future, pin::Pin, sync::Arc};

use atomic_lib::{agents::ForAgent, Db};
use wasmtime::{
    component::{Linker, ResourceTable},
    Store, StoreLimits,
};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use super::{
    bindings::SandboxedApp,
    code, error,
    registry::{HostAbiRegistry, LoadedApp, MAX_CALL_DEPTH},
    HostError,
};
use crate::plugins::host_core::{self, HostCore, Runtime};

/// The failure of a call, as the ABI reports it to a calling app.
pub type CallError = HostError;

/// What one instance is allowed to do and on whose behalf.
pub(super) struct AbiHost {
    pub registry: Arc<HostAbiRegistry>,
    pub db: Arc<Db>,
    pub app: Arc<LoadedApp>,
    /// Reads, fetches and secrets, under the caller and the Installation's
    /// agent. The caller is the agent the entry call came from, at every hop;
    /// a calling app's own rights are never passed on.
    pub core: HostCore,
    /// `calls.call` hops between the entry call and this instance.
    pub depth: usize,
    /// The agent the entry call came from, if any. Every app down the chain is
    /// bounded by it too, so going through apps never lets someone do what
    /// they could not do themselves (no confused deputy). `None` for work
    /// nobody asked for, which runs as the apps alone.
    pub entry: Option<ForAgent>,
}

pub struct AbiState {
    table: ResourceTable,
    ctx: WasiCtx,
    limits: StoreLimits,
    pub(super) host: AbiHost,
}

impl AbiState {
    pub(super) fn new(host: AbiHost, limits: StoreLimits) -> Self {
        Self {
            table: ResourceTable::new(),
            // No stdio, no filesystem, no sockets, no clock beyond WASI's:
            // everything else an app can reach is an import the host wrote.
            ctx: WasiCtxBuilder::new().build(),
            limits,
            host,
        }
    }
}

/// `types` has no functions; the trait only marks the interface as linked.
impl super::bindings::atomic::host::types::Host for AbiState {}

impl WasiView for AbiState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

/// The identity an app runs as when another app calls it: its own agent, or
/// nobody (the public agent) when its Installation has none.
async fn own_identity(db: &Db, app: &LoadedApp) -> ForAgent {
    let key = atomic_lib::db::app_agent::AppAgentKey::new(&app.drive, &app.installation);
    match db.get_app_agent_info(&key) {
        Ok(Some(info)) => ForAgent::AgentSubject(info.agent.into()),
        _ => ForAgent::Public,
    }
}

/// Builds the host for one invocation, with the Installation resolved now:
/// a paused or revoked app fails here, on its next call.
pub(super) async fn build_host(
    registry: &Arc<HostAbiRegistry>,
    db: &Arc<Db>,
    app: &Arc<LoadedApp>,
    caller: Option<ForAgent>,
    depth: usize,
) -> Result<AbiHost, HostError> {
    let entry = caller.clone();
    let caller = match caller {
        Some(caller) => caller,
        None => own_identity(db, app).await,
    };
    let core = HostCore::for_run(
        db.clone(),
        &app.drive,
        &app.installation,
        caller.clone(),
        Some(app.manifest.clone()),
    )
    .await
    .map_err(|e| error(code::FORBIDDEN, e))?;

    Ok(AbiHost {
        registry: registry.clone(),
        db: db.clone(),
        app: app.clone(),
        core,
        depth,
        entry,
    })
}

type Call<'a> = Pin<Box<dyn Future<Output = Result<String, HostError>> + Send + 'a>>;

/// Calls `interface.function` on the provider the drive has for it.
///
/// `caller` is the agent the entry call came from, bounded by the provider's
/// own agent, also for apps further down the chain; `None` is work nobody
/// asked for, which runs as the provider alone.
/// `depth` is the number of hops so far.
///
/// Boxed because an app can call back into the host, which calls this again.
#[allow(clippy::too_many_arguments)]
pub fn call_export<'a>(
    registry: &'a Arc<HostAbiRegistry>,
    db: &'a Arc<Db>,
    drive: &'a str,
    interface: &'a str,
    function: &'a str,
    args: &'a str,
    caller: Option<ForAgent>,
    depth: usize,
) -> Call<'a> {
    Box::pin(async move {
        if depth >= MAX_CALL_DEPTH {
            return Err(error(
                code::DEPTH_EXCEEDED,
                format!("apps may call each other at most {MAX_CALL_DEPTH} deep"),
            ));
        }
        let app = registry
            .provider_of(drive, interface, function)
            .ok_or_else(|| {
                error(
                    code::NOT_FOUND,
                    format!(
                        "no installed app in this drive declares the export {interface} {function}"
                    ),
                )
            })?;
        let export = app
            .export(interface, function)
            .expect("provider_of found it");

        let parsed: serde_json::Value = serde_json::from_str(args).map_err(|e| {
            error(
                code::INVALID_ARGUMENT,
                format!("the arguments are not JSON: {e}"),
            )
        })?;
        export
            .input_schema
            .validate(&parsed)
            .map_err(|e| error(code::INVALID_ARGUMENT, e))?;

        let host = build_host(registry, db, &app, caller, depth).await?;
        let result = run_invoke(host, interface, function, args).await?;

        // The app is trusted to compute, not to describe what it computed.
        let parsed: serde_json::Value = serde_json::from_str(&result).map_err(|e| {
            error(
                code::INTERNAL,
                format!("{interface} {function} returned something that is not JSON: {e}"),
            )
        })?;
        export.output_schema.validate(&parsed).map_err(|e| {
            error(
                code::INTERNAL,
                format!("{interface} {function} returned a result its outputSchema forbids: {e}"),
            )
        })?;
        Ok(result)
    })
}

/// An entry call: loads the drive's apps that are not loaded yet, then calls as
/// `caller`, whose rights are bounded by the provider's own agent.
pub async fn call_as(
    registry: &Arc<HostAbiRegistry>,
    db: &Arc<Db>,
    drive: &str,
    interface: &str,
    function: &str,
    args: &str,
    caller: ForAgent,
) -> Result<String, HostError> {
    registry.refresh(db, drive).await;
    call_export(
        registry,
        db,
        drive,
        interface,
        function,
        args,
        Some(caller),
        0,
    )
    .await
}

async fn run_invoke(
    host: AbiHost,
    interface: &str,
    function: &str,
    args: &str,
) -> Result<String, HostError> {
    let app = host.app.clone();
    let grants = host_core::installation_grants(
        &host.db,
        &app.drive,
        &app.installation,
        Some(&app.manifest),
    )
    .await;
    let limits = host_core::limits(Runtime::App, grants);

    let mut linker: Linker<AbiState> = Linker::new(&app.engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)
        .map_err(|e| error(code::INTERNAL, format!("could not link WASI: {e}")))?;
    SandboxedApp::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |s| s)
        .map_err(|e| error(code::INTERNAL, format!("could not link the host ABI: {e}")))?;

    let mut store = Store::new(&app.engine, AbiState::new(host, limits.store_limits()));
    store.limiter(|state| &mut state.limits);
    limits
        .meter(&mut store)
        .map_err(|e| error(code::INTERNAL, e))?;

    let instance = SandboxedApp::instantiate_async(&mut store, &app.component, &linker)
        .await
        .map_err(|e| error(code::TRAP, format!("could not start the app: {e}")))?;

    match instance
        .atomic_host_app()
        .call_invoke(&mut store, interface, function, args)
        .await
    {
        Ok(result) => result,
        // Out of fuel, out of memory, a panic: the app failed, the host did not.
        Err(e) => Err(error(code::TRAP, format!("the app was stopped: {e}"))),
    }
}
