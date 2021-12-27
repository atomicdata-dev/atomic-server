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
use atomic_lib::{Db, Storelike};
use chrono::Local;
use std::collections::{HashMap, HashSet};

/// The Commit Monitor is an Actor that manages subscriptions for subjects and sends Commits to listeners.
/// It's also responsible for checking whether the rights are present
pub struct CommitMonitor {
    /// Maintains a list of all the resources that are being subscribed to, and maps these to websocket connections.
    subscriptions: HashMap<String, HashSet<Addr<WebSocketConnection>>>,
    store: Db,
    search_state: SearchState,
    config: Config,
    last_search_commit: chrono::DateTime<Local>,
}

// Since his Actor only starts once, there is no need to handle its lifecycle
impl Actor for CommitMonitor {
    type Context = Context<Self>;
}

impl Handler<Subscribe> for CommitMonitor {
    type Result = ();

    // A message comes in when a client subscribes to a subject.
    fn handle(&mut self, msg: Subscribe, _: &mut Context<Self>) {
        // check if the agent has the rights to subscribe to this resource
        if let Ok(resource) = self.store.get_resource(&msg.subject) {
            match atomic_lib::hierarchy::check_read(&self.store, &resource, &msg.agent) {
                Ok(_explanation) => {
                    let mut set = if let Some(set) = self.subscriptions.get(&msg.subject) {
                        set.clone()
                    } else {
                        HashSet::new()
                    };
                    set.insert(msg.addr);
                    // tracing::info!("handle subscribe {} ", msg.subject);
                    self.subscriptions.insert(msg.subject.clone(), set);
                }
                Err(unauthorized_err) => {
                    tracing::info!(
                        "Not allowed {}  to subscribe to {}: {}",
                        &msg.agent,
                        &msg.subject,
                        unauthorized_err
                    );
                }
            }
        }
    }
}

impl Handler<CommitMessage> for CommitMonitor {
    type Result = ();

    /// When a commit comes in, send it to any listening subscribers,
    /// and update the value index.
    /// The search index is only updated if the last search commit is 15 seconds or older.
    // This has a bunch of .unwrap() / panics, which is not ideal.
    // However, I don't want to make this a blocking call,
    // I want commits to succeed (no 500 response) even if indexing fails,
    // also because performance is imporatant here -
    // dealing with these indexing things synchronously would be too slow.
    fn handle(&mut self, msg: CommitMessage, _: &mut Context<Self>) {
        let target = msg.commit_response.full_commit.subject.clone();

        tracing::info!(
            "handle commit for {} with id {}. Current connections: {}",
            target,
            msg.commit_response.commit.get_subject(),
            self.subscriptions.len()
        );

        // Notify websocket listeners
        if let Some(subscribers) = self.subscriptions.get(&target) {
            tracing::info!(
                "Sending commit {} to {} subscribers",
                target,
                subscribers.len()
            );
            for connection in subscribers {
                connection.do_send(msg.clone());
            }
        } else {
            tracing::info!("No subscribers for {}", target);
        }

        // Update the value index
        msg.commit_response
            .full_commit
            .apply_changes(msg.commit_response.resource_old.clone(), &self.store, true)
            .unwrap();

        // Update the search index
        if let Some(resource) = &msg.commit_response.resource_new {
            if self.config.opts.remove_previous_search {
                crate::search::remove_resource(&self.search_state, &target).unwrap();
            };
            // Add new resource to search index
            crate::search::add_resource(&self.search_state, resource).unwrap();

            // TODO: This is not ideal, as it does not _delay_ the search index update, but it prevents it.
            // Current implementation should work just fine in most scenario's.
            let commit_duration = chrono::Duration::seconds(15);
            let now = chrono::Local::now();
            let since_last_commit = now - self.last_search_commit;
            if since_last_commit > commit_duration {
                // This is a slow operation!
                // Commit the changset to the search index.
                self.search_state.writer.write().unwrap().commit().unwrap();
                self.last_search_commit = now;
            }
        } else {
            // If there is no new resource, it must have been deleted, so let's remove it from the search index.
            crate::search::remove_resource(&self.search_state, &target).unwrap();
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
            last_search_commit: chrono::Local::now(),
        }
    })
}
