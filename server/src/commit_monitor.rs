//! The Commit Monitor checks for new commits and notifies listeners.
//! It is used for WebSockets to notify front-end clients of changes in Resources,
//! and to update the Search index.

use crate::{
    actor_messages::{CommitMessage, Subscribe},
    config::Config,
    handlers::web_sockets::WebSocketConnection,
    search::SearchState,
};
use actix::{
    prelude::{Actor, Context, Handler},
    Addr,
};
use atomic_lib::Db;
use std::collections::{HashMap, HashSet};

/// The Commit Monitor is an Actor that manages subscriptions for subjects and sends Commits to listeners.
pub struct CommitMonitor {
    /// Maintains a list of all the resources that are being subscribed to, and maps these to websocket connections.
    subscriptions: HashMap<String, HashSet<Addr<WebSocketConnection>>>,
    store: Db,
    search_state: SearchState,
    config: Config,
}

// Since his Actor only starts once, there is no need to handle its lifecycle
impl Actor for CommitMonitor {
    type Context = Context<Self>;
}

impl Handler<Subscribe> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: Subscribe, _: &mut Context<Self>) {
        let mut set = if let Some(set) = self.subscriptions.get(&msg.subject) {
            set.clone()
        } else {
            HashSet::new()
        };
        set.insert(msg.addr);
        log::info!("handle subscribe {} ", msg.subject);
        self.subscriptions.insert(msg.subject, set);
    }
}

impl Handler<CommitMessage> for CommitMonitor {
    type Result = ();

    /// When a commit comes in, send it to any listening subscribers,
    /// and update the indexes (value index + search index).
    // This has a bunch of .unwrap() / panics, which is not ideal.
    // However, I don't want to make this a blocking call,
    // I want commits to succeed (no 500 response) even if indexing fails,
    // also because performance is imporatant here -
    // dealing with these indexing things synchronously would be too slow.
    fn handle(&mut self, msg: CommitMessage, _: &mut Context<Self>) {
        log::info!(
            "handle commit for {} with id {}. Current connections: {}",
            msg.subject,
            msg.commit_response.commit.get_subject(),
            self.subscriptions.len()
        );

        // Update the value index
        msg.commit_response
            .full_commit
            .apply_changes(msg.commit_response.resource_old.clone(), &self.store, true)
            .unwrap();

        // Update the search index
        if let Some(resource) = &msg.commit_response.resource_new {
            if self.config.opts.remove_previous_search {
                crate::search::remove_resource(&self.search_state, &msg.subject).unwrap();
            };
            // Add new resource to search index
            crate::search::add_resource(&self.search_state, resource).unwrap();
            // Commit the changset to the search index.
            // This is a slow operation!
            self.search_state.writer.write().unwrap().commit().unwrap();
        } else {
            crate::search::remove_resource(&self.search_state, &msg.subject).unwrap();
        }

        if let Some(subscribers) = self.subscriptions.get(&msg.subject) {
            log::info!(
                "Sending commit {} to {} subscribers",
                msg.subject,
                subscribers.len()
            );
            for connection in subscribers {
                connection.do_send(msg.clone());
            }
        } else {
            log::info!("No subscribers for {}", msg.subject);
        }
    }
}

/// Spawns a commit monitor actor
pub fn create_commit_monitor(
    store: Db,
    search_state: SearchState,
    config: Config,
) -> Addr<CommitMonitor> {
    crate::commit_monitor::CommitMonitor::create(|_ctx: &mut Context<CommitMonitor>| {
        CommitMonitor {
            subscriptions: HashMap::new(),
            store,
            search_state,
            config,
        }
    })
}
