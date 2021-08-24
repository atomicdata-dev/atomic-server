//! The Commit Monitor checks for new commits and notifies listeners.
//! It is mostly used by WebSockets to notify front-end clients of changes Resources.

// TODO: define messages between CommitMonitor and WebSocketConnection
use crate::actor_messages::{CommitMessage, Connect, Disconnect, WsMessage};
use actix::prelude::{Actor, Context, Handler, Recipient};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

type Socket = Recipient<WsMessage>;

/// The Commit Monitor is an Actor that checks for new commits and notifies listeners.
pub struct CommitMonitor {
    /// Maintains a list of all the resources that are being subscribed to, and maps these to websocket connections.
    subscriptions: HashMap<String, HashSet<Socket>>,
}

impl CommitMonitor {}

// Since his Actor only starts once, there is no need to handle its lifecycle
impl Actor for CommitMonitor {
    type Context = Context<Self>;
}

impl Default for CommitMonitor {
    fn default() -> CommitMonitor {
        CommitMonitor {
            subscriptions: HashMap::new(),
        }
    }
}

/// Handler for Disconnect message.
impl Handler<Disconnect> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _: &mut Context<Self>) {
        log::info!("handle disconnect");
    }
}

/// Handler for Disconnect message.
impl Handler<CommitMessage> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: CommitMessage, _: &mut Context<Self>) {
        log::info!("handle commit");
        let commit = msg.commit;
        if let Some(set) = self.subscriptions.get(&commit.subject) {
            for socket in set {
                log::info!(
                    "Updating socket {:?} with commit for {}",
                    socket,
                    commit.subject
                );
            }
        } else {
            log::info!("No subscribers for {}", commit.subject);
        }
    }
}
