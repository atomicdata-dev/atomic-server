//! Forwarding a call to another node (`planning/host-abi.md`, step 6).
//!
//! A drive's apps may be installed on one node and not on another that syncs
//! the same drive. When [`super::call_export`] finds no provider here, or finds
//! the app but not the secrets it declares, the call goes to a peer from the
//! known-peers list that syncs the drive, as a `CALL` on the Iroh stream the
//! sync already uses (`lib/src/sync/call.rs`, `docs/src/websockets.md`). The
//! signature is the same: interface, function, JSON args, JSON result, ABI
//! error codes.
//!
//! Rights across the hop:
//!
//! - **Identity.** The stream's `AUTH` is the forwarding *node's* agent, as for
//!   a sync. The caller's key is not on that node (callers sign for the node
//!   they talk to, and a signed request replayed at another node is the thing
//!   the `drive#nodeId` binding exists to stop), so the `CALL` names the caller
//!   and the node vouches for it.
//! - **Nothing widens.** The serving node runs [`call_for_agent_at`] for the
//!   named caller, so every check there applies: caller read on the drive,
//!   `check_write` on every hop that writes, the Installation's own agent, the
//!   `uses` and scope grants. On top, the vouching node's own agent needs read
//!   on the drive and write wherever a hop writes
//!   ([`CallBudget::from_wire`]), so a node can only vouch for what it could do
//!   itself.
//! - **Budget.** The calls, fuel, effects and secrets flag still left travel in
//!   the frame; the serving node caps them at its own limits and never widens
//!   them. The sender hands over its whole remaining pool and gets back what
//!   was not spent, so a chain cannot spend the same budget twice.
//! - **Depth** counts across the hop, and a node serving a forwarded call does
//!   not forward it again.

use std::{future::Future, pin::Pin, sync::Arc};

use atomic_lib::{
    agents::ForAgent,
    sync::{
        call::{call_known_peers_using, CallFuture, CallHandler, Endpoint},
        protocol::{CallFailure, CallRequest, CallResponse},
    },
    urls, Db, Storelike,
};

use super::{
    code, error,
    registry::{HostAbiRegistry, LoadedApp},
    run::{call_for_agent_at, CallBudget},
    HostError,
};

type Forwarded<'a> = Pin<Box<dyn Future<Output = Option<CallResponse>> + Send + 'a>>;

/// Sends a call to a node that can run it.
pub trait CallForwarder: Send + Sync {
    /// The peer's answer, or `None` when no peer syncs the drive or none could
    /// be reached (the call is then answered as if there were no forwarding).
    fn forward<'a>(&'a self, db: &'a Db, request: &'a CallRequest) -> Forwarded<'a>;
}

/// Forwards over Iroh to the known peers of the drive.
pub struct IrohForwarder {
    /// `None` is the node's own endpoint ([`atomic_lib::sync::peer::endpoint`]);
    /// tests that run several nodes in a process name theirs.
    endpoint: Option<Endpoint>,
}

impl IrohForwarder {
    pub fn node() -> Self {
        Self { endpoint: None }
    }

    pub fn using(endpoint: Endpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
        }
    }
}

impl CallForwarder for IrohForwarder {
    fn forward<'a>(&'a self, db: &'a Db, request: &'a CallRequest) -> Forwarded<'a> {
        Box::pin(async move {
            let endpoint = match &self.endpoint {
                Some(endpoint) => endpoint,
                None => atomic_lib::sync::peer::endpoint()?,
            };
            call_known_peers_using(endpoint, db, request).await
        })
    }
}

/// One call that may go to a peer.
pub(super) struct Forward<'a> {
    pub registry: &'a Arc<HostAbiRegistry>,
    pub db: &'a Arc<Db>,
    pub drive: &'a str,
    pub interface: &'a str,
    pub function: &'a str,
    pub args: &'a str,
    pub caller: &'a ForAgent,
    pub depth: usize,
    pub budget: &'a Arc<CallBudget>,
}

impl Forward<'_> {
    /// The peer's answer, or `None` when the call stays local: forwarding is
    /// off for this chain, there is no forwarder, the caller is not an agent
    /// (a node cannot vouch for `sudo`), or no peer answered.
    pub(super) async fn send(&self) -> Option<Result<String, HostError>> {
        if !self.budget.may_forward() {
            return None;
        }
        let forwarder = self.registry.forwarder()?;
        let ForAgent::AgentSubject(caller) = self.caller else {
            return None;
        };
        let (calls, fuel) = self.budget.reserve();
        let request = CallRequest {
            drive: self.drive.to_string(),
            interface: self.interface.to_string(),
            function: self.function.to_string(),
            args: self.args.to_string(),
            caller: caller.to_string(),
            depth: self.depth as u32 + 1,
            budget: self.budget.wire(calls, fuel),
        };
        let Some(response) = forwarder.forward(self.db, &request).await else {
            self.budget.refund(calls, fuel);
            return None;
        };
        self.budget
            .refund(response.calls_left.min(calls), response.fuel_left.min(fuel));
        Some(match response.error {
            // A peer's code means something only if it is one of ours.
            Some(e) if code::ALL.contains(&e.code.as_str()) => Err(error(&e.code, e.message)),
            Some(e) => Err(error(code::INTERNAL, e.message)),
            None => Ok(response.result.unwrap_or_default()),
        })
    }
}

/// Whether this node holds every secret the app declares.
pub(super) fn holds_secrets(db: &Db, app: &LoadedApp) -> bool {
    if app.manifest.secrets.is_empty() {
        return true;
    }
    let held = db
        .list_plugin_secrets(&app.drive, &app.installation)
        .unwrap_or_default();
    app.manifest.secrets.iter().all(|want| {
        held.iter()
            .any(|h| h.name == want.name && h.origins.iter().any(|o| o == &want.origin))
    })
}

/// Runs forwarded calls on this node.
pub struct ServedCalls {
    pub registry: Arc<HostAbiRegistry>,
}

impl CallHandler for ServedCalls {
    fn call(&self, store: Db, via: ForAgent, request: CallRequest) -> CallFuture<'_> {
        Box::pin(serve(self.registry.clone(), Arc::new(store), via, request))
    }
}

/// The agent a peer named as the caller. Never `sudo` or the public: a node
/// vouches for agents, it does not hand out its own powers.
fn caller_of(named: &str) -> Result<ForAgent, HostError> {
    if named.is_empty() || named == urls::SUDO_AGENT || named == urls::PUBLIC_AGENT {
        return Err(error(
            code::FORBIDDEN,
            "a forwarded call must name the agent it is for",
        ));
    }
    Ok(ForAgent::from(named))
}

pub(super) async fn serve(
    registry: Arc<HostAbiRegistry>,
    db: Arc<Db>,
    via: ForAgent,
    request: CallRequest,
) -> CallResponse {
    let budget = Arc::new(CallBudget::from_wire(&request.budget, via.clone()));
    let outcome = async {
        let caller = caller_of(&request.caller)?;
        // A node vouches for people, not for an app: the agent an Installation
        // signs as is never a caller, or a peer could make any app act as any
        // other.
        // Read off the app-agent table, not the loaded apps: an Installation
        // whose app is not (yet) loaded here has an agent too.
        if db
            .app_agents_in_drive(&request.drive)
            .into_iter()
            .any(|agent| ForAgent::AgentSubject(agent.into()) == caller)
        {
            return Err(error(
                code::FORBIDDEN,
                "a forwarded call cannot be made as an Installation's own agent",
            ));
        }
        if matches!(via, ForAgent::Public) {
            return Err(error(
                code::FORBIDDEN,
                "the forwarding node did not identify",
            ));
        }
        // The node must see the drive itself; the caller's read is checked
        // with the call.
        let drive = db
            .get_resource(&request.drive.as_str().into())
            .await
            .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
        atomic_lib::hierarchy::check_read(&*db, &drive, &via)
            .await
            .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
        call_for_agent_at(
            &registry,
            &db,
            &request.drive,
            &request.interface,
            &request.function,
            &request.args,
            caller,
            budget.clone(),
            request.depth as usize,
        )
        .await
    }
    .await;
    let (result, error) = match outcome {
        Ok(result) => (Some(result), None),
        Err(e) => (
            None,
            Some(CallFailure {
                code: e.code,
                message: e.message,
            }),
        ),
    };
    CallResponse {
        result,
        error,
        calls_left: budget.calls_left(),
        fuel_left: budget.fuel_left(),
    }
}
