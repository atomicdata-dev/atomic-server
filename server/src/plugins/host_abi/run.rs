//! One invocation of an app's `invoke` export, in a fresh instance.
//!
//! Nothing survives between invocations: a new store, a new instance, a new
//! fuel and memory budget. The rights of the invocation are fixed here, when
//! the host is built, from two things only: who asked, and what the app's own
//! Installation holds.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use atomic_lib::{agents::ForAgent, sync::protocol::CallBudgetWire, Db};
use wasmtime::{
    component::{Component, Linker, ResourceTable},
    Engine, Store, StoreLimits,
};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use super::{
    bindings::{SandboxedApp, SandboxedAppPre},
    code, error,
    forward::Forward,
    registry::{HostAbiRegistry, LoadedApp, MAX_CALL_DEPTH},
    HostError,
};
use crate::plugins::{
    app_schema::check_values,
    host_core::{self, HostCore, Runtime},
    manifest::{ExportEffect, Manifest},
};

/// The failure of a call, as the ABI reports it to a calling app.
pub type CallError = HostError;

/// What one instance is allowed to do and on whose behalf.
pub(super) struct AbiHost {
    pub registry: Arc<HostAbiRegistry>,
    pub db: Arc<Db>,
    /// Where the app is installed and what its release declares. A QuickJS run
    /// plugin has the same (see `js.rs`); its manifest may be absent (a legacy
    /// draft), which declares nothing.
    pub drive: String,
    pub installation: String,
    pub manifest: Option<Arc<Manifest>>,
    /// Reads, fetches and secrets, under the caller and the Installation's
    /// agent. The caller is the agent the entry call came from, at every hop;
    /// a calling app's own rights are never passed on.
    pub core: HostCore,
    /// `calls.call` hops between the entry call and this instance.
    pub depth: usize,
    /// What the whole chain of calls, from the entry call down, may still
    /// spend. Shared by every instance in it.
    pub budget: Arc<CallBudget>,
}

/// How many `calls.call` hops, entry call included, one chain may make in
/// total (depth only bounds one branch; a fan-out is bounded by this).
pub const CHAIN_CALLS: u64 = 64;
/// Fuel the whole chain shares. An instance takes up to its own fuel limit
/// from this pool and gives back what it did not use, so a chain of apps
/// cannot together run longer than a few apps' worth of work.
pub const CHAIN_FUEL: u64 = 16_000_000_000;
/// How long an entry call may take, wall clock, however it is spent.
pub const ENTRY_TIMEOUT: Duration = Duration::from_secs(30);

/// The cumulative budget of one entry call. Limits that apply per instance
/// (fuel, memory, depth) still apply; this is the sum across the chain.
#[derive(Debug)]
pub struct CallBudget {
    calls: AtomicU64,
    fuel: AtomicU64,
    /// The effects any export in the chain may have; `None` is any. A frame
    /// may only cause reads, so an app it calls cannot pass its call on to
    /// one that writes.
    effects: Option<Vec<ExportEffect>>,
    /// Whether an app that declares secrets may run anywhere in the chain.
    secrets: bool,
    /// Whether a call with no provider here may go to a peer node. Off on a
    /// node serving a forwarded call: one hop, so two nodes cannot bounce a
    /// call between them.
    forward: bool,
    /// The node that forwarded this chain to us and vouched for its caller.
    /// Every hop that needs write on the drive needs it for this agent too, so
    /// naming someone else's agent never gets a peer more than its own rights.
    vouched_by: Option<ForAgent>,
}

impl Default for CallBudget {
    fn default() -> Self {
        Self::new(CHAIN_CALLS, CHAIN_FUEL)
    }
}

impl CallBudget {
    pub fn new(calls: u64, fuel: u64) -> Self {
        Self {
            calls: AtomicU64::new(calls),
            fuel: AtomicU64::new(fuel),
            effects: None,
            secrets: true,
            forward: true,
            vouched_by: None,
        }
    }

    /// The budget a forwarded call arrives with, from `wire`. It can only be
    /// as large as this node's own default, and narrower where the sender
    /// narrowed it: an effect this node does not know is dropped, never read
    /// as "any". `via` is the peer that vouched for the caller.
    pub fn from_wire(wire: &CallBudgetWire, via: ForAgent) -> Self {
        let mut budget = Self::new(wire.calls.min(CHAIN_CALLS), wire.fuel.min(CHAIN_FUEL));
        budget.effects = wire.effects.as_ref().map(|names| {
            names
                .iter()
                .filter_map(|name| ExportEffect::from_name(name))
                .collect()
        });
        budget.secrets = wire.secrets;
        budget.forward = false;
        budget.vouched_by = Some(via);
        budget
    }

    /// What is left, for a frame (`CALL`), with `calls` and `fuel` as the share
    /// handed to the peer.
    pub(super) fn wire(&self, calls: u64, fuel: u64) -> CallBudgetWire {
        CallBudgetWire {
            calls,
            fuel,
            effects: self
                .effects
                .as_ref()
                .map(|e| e.iter().map(|e| e.name().to_string()).collect()),
            secrets: self.secrets,
        }
    }

    /// Whether this chain may go to a peer node.
    pub(super) fn may_forward(&self) -> bool {
        self.forward
    }

    /// Takes everything still in the pool, to hand to a peer that continues the
    /// chain: while it runs, nothing here can be spent a second time.
    pub(super) fn reserve(&self) -> (u64, u64) {
        (
            self.calls.swap(0, Ordering::SeqCst),
            self.fuel.swap(0, Ordering::SeqCst),
        )
    }

    /// Puts back what a peer did not spend. Never more than was reserved.
    pub(super) fn refund(&self, calls: u64, fuel: u64) {
        self.calls.fetch_add(calls, Ordering::SeqCst);
        self.fuel.fetch_add(fuel, Ordering::SeqCst);
    }

    /// Calls still in the pool.
    pub fn calls_left(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// The same budget, with only these effects allowed anywhere in the chain.
    pub fn only(mut self, effects: Vec<ExportEffect>) -> Self {
        self.effects = Some(effects);
        self
    }

    /// The same budget, where no app that declares secrets may run. For a
    /// caller who may not spend them (a read-only connection), however far
    /// down the chain the app is.
    pub fn without_secrets(mut self) -> Self {
        self.secrets = false;
        self
    }

    pub(super) fn allows(&self, effect: ExportEffect) -> Result<(), HostError> {
        match &self.effects {
            Some(allowed) if !allowed.contains(&effect) => Err(error(
                code::FORBIDDEN,
                format!("this call may not cause an export with the effect {effect:?}"),
            )),
            _ => Ok(()),
        }
    }

    /// Whether anything in this chain may write: false when the effects were
    /// narrowed to leave `write` out. A `read` export can still call
    /// `store.apply`, so this is checked there too, not only per export.
    pub(super) fn may_write(&self) -> bool {
        self.effects
            .as_ref()
            .is_none_or(|allowed| allowed.contains(&ExportEffect::Write))
    }

    pub(super) fn has_voucher(&self) -> bool {
        self.vouched_by.is_some()
    }

    /// For a forwarded chain, the node that vouched must be able to write the
    /// drive as well: a peer never gets more than its own rights.
    pub(super) async fn check_vouch_write(
        &self,
        db: &Db,
        drive_resource: &atomic_lib::Resource,
    ) -> Result<(), HostError> {
        let Some(via) = &self.vouched_by else {
            return Ok(());
        };
        atomic_lib::hierarchy::check_write(db, drive_resource, via)
            .await
            .map(|_| ())
            .map_err(|e| {
                error(
                    code::FORBIDDEN,
                    format!("the node that forwarded this call may not write the drive: {e}"),
                )
            })
    }

    /// Fuel still in the pool.
    pub fn fuel_left(&self) -> u64 {
        self.fuel.load(Ordering::SeqCst)
    }

    fn take_call(&self) -> Result<(), HostError> {
        self.calls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .map(|_| ())
            .map_err(|_| {
                error(
                    code::DEPTH_EXCEEDED,
                    format!("one call may cause at most {CHAIN_CALLS} calls between apps"),
                )
            })
    }

    /// Up to `want` fuel, or an error when the pool is empty.
    pub(super) fn take_fuel(&self, want: u64) -> Result<u64, HostError> {
        let before = self
            .fuel
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |pool| {
                (pool > 0).then(|| pool - pool.min(want))
            })
            .map_err(|_| {
                error(
                    code::DEPTH_EXCEEDED,
                    "the apps in this call chain used all the work one call may cause",
                )
            })?;
        Ok(before.min(want))
    }

    pub(super) fn give_back(&self, fuel: u64) {
        self.fuel.fetch_add(fuel, Ordering::SeqCst);
    }
}

pub struct AbiState {
    table: ResourceTable,
    ctx: WasiCtx,
    pub(super) limits: StoreLimits,
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

impl AbiState {
    /// The module's own folder as `/`: readable, and writable when its
    /// manifest holds the `storage` capability. Nothing else of the disk.
    pub(super) fn with_storage_dir(
        mut self,
        dir: &std::path::Path,
        writable: bool,
    ) -> Result<Self, String> {
        use wasmtime_wasi::{DirPerms, FilePerms};
        let (dir_perms, file_perms) = if writable {
            (
                DirPerms::READ | DirPerms::MUTATE,
                FilePerms::READ | FilePerms::WRITE,
            )
        } else {
            (DirPerms::READ, FilePerms::READ)
        };
        self.ctx = WasiCtxBuilder::new()
            .preopened_dir(dir, "/", dir_perms, file_perms)
            .map_err(|e| format!("Failed to preopen directory: {e}"))?
            .build();
        Ok(self)
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

/// Links the host ABI once per loaded app, so a call only instantiates.
pub(super) fn instance_pre(
    engine: &Engine,
    component: &Component,
) -> Result<SandboxedAppPre<AbiState>, String> {
    let mut linker: Linker<AbiState> = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)
        .map_err(|e| format!("could not link WASI: {e}"))?;
    SandboxedApp::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |s| s)
        .map_err(|e| format!("could not link the host ABI: {e}"))?;
    let pre = linker
        .instantiate_pre(component)
        .map_err(|e| format!("the app does not fit the host ABI: {e}"))?;
    SandboxedAppPre::new(pre).map_err(|e| format!("the app does not fit the host ABI: {e}"))
}

/// Builds the host for one invocation, with the Installation resolved now:
/// a paused or revoked app fails here, on its next call.
pub(super) async fn build_host(
    registry: &Arc<HostAbiRegistry>,
    db: &Arc<Db>,
    (drive, installation, manifest): (&str, &str, Option<Arc<Manifest>>),
    caller: ForAgent,
    depth: usize,
    budget: Arc<CallBudget>,
) -> Result<AbiHost, HostError> {
    let core = HostCore::for_run(db.clone(), drive, installation, caller, manifest.clone())
        .await
        .map_err(|e| error(code::FORBIDDEN, e))?
        .vouched_by(budget.vouched_by.clone());

    Ok(AbiHost {
        registry: registry.clone(),
        db: db.clone(),
        drive: drive.to_string(),
        installation: installation.to_string(),
        manifest,
        core,
        depth,
        budget,
    })
}

type Call<'a> = Pin<Box<dyn Future<Output = Result<String, HostError>> + Send + 'a>>;

/// Calls `interface.function` on the provider the drive has for it.
///
/// `caller` is the agent the entry call came from, bounded by the provider's
/// own agent, also for apps further down the chain.
/// `depth` is the number of hops so far; `budget` is shared by the whole chain.
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
    caller: ForAgent,
    depth: usize,
    budget: Arc<CallBudget>,
) -> Call<'a> {
    Box::pin(async move {
        budget.take_call()?;
        let forward = || Forward {
            registry,
            db,
            drive,
            interface,
            function,
            args,
            caller: &caller,
            depth,
            budget: &budget,
        };
        if depth >= MAX_CALL_DEPTH {
            return Err(error(
                code::DEPTH_EXCEEDED,
                format!("apps may call each other at most {MAX_CALL_DEPTH} deep"),
            ));
        }
        let Some(app) = registry.provider_of(drive, interface, function) else {
            // No app here: a node that syncs this drive may have it.
            if let Some(outcome) = forward().send().await {
                return outcome;
            }
            return Err(error(
                code::NOT_FOUND,
                format!(
                    "no installed app in this drive declares the export {interface} {function}"
                ),
            ));
        };
        let export = app
            .export(interface, function)
            .expect("provider_of found it");
        budget.allows(export.effect)?;
        if !budget.secrets && !app.manifest.secrets.is_empty() {
            return Err(error(
                code::FORBIDDEN,
                "this call may not cause an app that declares secrets to run",
            ));
        }
        // An app runs where its secrets are. This node has the app but not
        // every secret it declares: a peer that has them runs it instead. With
        // no peer that does, it runs here and fails where it needs the secret.
        if !super::forward::holds_secrets(db, &app) {
            match forward().send().await {
                // A peer without the app says nothing about this one.
                Some(Err(e)) if e.code == code::NOT_FOUND => {}
                Some(outcome) => return outcome,
                None => {}
            }
        }
        // At every hop, not only the entry: a read export must not let a reader
        // cause a write. An app that declares secrets can spend them whatever
        // its exports say they do, so calling it takes the same rights as
        // `/plugin-run`: write on the drive.
        if matches!(export.effect, ExportEffect::Write | ExportEffect::External)
            || !app.manifest.secrets.is_empty()
        {
            use atomic_lib::Storelike;
            let drive_resource = db
                .get_resource(&drive.into())
                .await
                .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
            atomic_lib::hierarchy::check_write(&**db, &drive_resource, &caller)
                .await
                .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
            budget.check_vouch_write(db, &drive_resource).await?;
        }

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
        check_values(
            db,
            app.manifest.schema.as_ref(),
            &export.input_schema,
            &parsed,
        )
        .await
        .map_err(|e| error(code::INVALID_ARGUMENT, e))?;

        let host = build_host(
            registry,
            db,
            (&app.drive, &app.installation, Some(app.manifest.clone())),
            caller,
            depth,
            budget,
        )
        .await?;
        // What the callee gets is what was validated, not the caller's bytes.
        let result = run_invoke(host, &app, interface, function, &parsed.to_string()).await?;

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
        check_values(
            db,
            app.manifest.schema.as_ref(),
            &export.output_schema,
            &parsed,
        )
        .await
        .map_err(|e| {
            error(
                code::INTERNAL,
                format!("{interface} {function} returned a result its outputSchema forbids: {e}"),
            )
        })?;
        Ok(parsed.to_string())
    })
}

/// The entry call of every outside caller (`/host/call`, MCP): the agent must
/// be able to read the drive, the drive's apps are loaded, and the call runs
/// under `budget` with [`ENTRY_TIMEOUT`]. Write on the drive, for exports that
/// write, reach out or belong to an app with secrets, is checked by
/// [`call_export`] at every hop. A caller must not be the public agent.
#[allow(clippy::too_many_arguments)]
pub async fn call_for_agent(
    registry: &Arc<HostAbiRegistry>,
    db: &Arc<Db>,
    drive: &str,
    interface: &str,
    function: &str,
    args: &str,
    caller: ForAgent,
    budget: Arc<CallBudget>,
) -> Result<String, HostError> {
    call_for_agent_at(
        registry, db, drive, interface, function, args, caller, budget, 0,
    )
    .await
}

/// [`call_for_agent`] for a chain that already made `depth` hops, which is how
/// a forwarded call enters the node that runs it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn call_for_agent_at(
    registry: &Arc<HostAbiRegistry>,
    db: &Arc<Db>,
    drive: &str,
    interface: &str,
    function: &str,
    args: &str,
    caller: ForAgent,
    budget: Arc<CallBudget>,
    depth: usize,
) -> Result<String, HostError> {
    use atomic_lib::Storelike;
    // Before anything is loaded or run: the caller must see the drive.
    let drive_resource = db
        .get_resource(&drive.into())
        .await
        .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
    atomic_lib::hierarchy::check_read(&**db, &drive_resource, &caller)
        .await
        .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
    registry.refresh(db, drive).await;
    with_deadline(
        ENTRY_TIMEOUT,
        call_export(
            registry, db, drive, interface, function, args, caller, depth, budget,
        ),
    )
    .await
}

/// Runs `work`, giving up after `deadline`. The work is dropped, which stops
/// an app at its next await or fuel yield.
pub(super) async fn with_deadline<F>(deadline: Duration, work: F) -> Result<String, HostError>
where
    F: Future<Output = Result<String, HostError>>,
{
    tokio::time::timeout(deadline, work)
        .await
        .unwrap_or_else(|_| {
            Err(error(
                code::TRAP,
                format!(
                    "the call was stopped after {} seconds",
                    deadline.as_secs_f32()
                ),
            ))
        })
}

/// An error an app returned, with a code outside the ABI made `internal`.
pub(super) fn app_error(e: HostError) -> HostError {
    if code::ALL.contains(&e.code.as_str()) {
        e
    } else {
        error(code::INTERNAL, e.message)
    }
}

async fn run_invoke(
    host: AbiHost,
    app: &Arc<LoadedApp>,
    interface: &str,
    function: &str,
    args: &str,
) -> Result<String, HostError> {
    let budget = host.budget.clone();
    let grants = host_core::installation_grants(
        &host.db,
        &app.drive,
        &app.installation,
        Some(app.manifest.as_ref()),
    )
    .await;
    let limits = host_core::limits(Runtime::App, grants);

    let mut store = Store::new(&app.engine, AbiState::new(host, limits.store_limits()));
    store.limiter(|state| &mut state.limits);
    limits
        .meter(&mut store)
        .map_err(|e| error(code::INTERNAL, e))?;
    // The instance's fuel comes out of what the whole chain has left.
    let allowance = budget.take_fuel(limits.fuel)?;
    store
        .set_fuel(allowance)
        .map_err(|e| error(code::INTERNAL, format!("could not meter the app: {e}")))?;

    let outcome = async {
        let instance = app
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| error(code::TRAP, format!("could not start the app: {e}")))?;

        match instance
            .atomic_host_app()
            .call_invoke(&mut store, interface, function, args)
            .await
        {
            // The app's own failure. Only the codes of the ABI mean something
            // to a caller (and to an HTTP status); an invented one is just
            // the app failing.
            Ok(result) => result.map_err(app_error),
            // Out of fuel, out of memory, a panic: the app failed, the host did not.
            Err(e) => Err(error(code::TRAP, format!("the app was stopped: {e}"))),
        }
    }
    .await;

    // What this instance did not use goes back to the chain.
    budget.give_back(store.get_fuel().unwrap_or(0));
    outcome
}
