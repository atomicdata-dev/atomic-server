//! The host layer: what an app shell around `atomic_lib` shows and does, with
//! no UI and no transport in it.
//!
//! An app that keeps its own store on the device (the Flutter app today; the
//! Tauri desktop app and native iOS/Android shells next, or a CLI) needs more
//! than the store's own API: the rows of its home lists, a chat's entries, a
//! conversation decrypted for this device's agent, the plain text of a
//! resource for an AI, and the call surface of the embedded web renderer. That
//! logic used to live in the Flutter bridge crate (`flutter/rust`); it lives
//! here so every host shares one copy and one set of tests. A host binds it to
//! its own process state (a global store, an FFI or IPC layer) and stays thin.
//!
//! - [`rows`]: one resource as a list row (title, class name, emoji), read
//!   from local propvals only.
//! - [`lists`]: the home lists (AI chats, favorites, recently opened, activity),
//!   icons and full-text search across drives.
//! - [`chats`]: AI chats stored as `ChatLog` pages: read, start, append.
//! - [`chat_rooms`]: the chat of a meeting or chat room (`ChatLog` entries): read, send.
//! - [`conversations`]: end-to-end encrypted conversations: list, read, send.
//! - [`context`]: a resource as plain text, to hand to an AI.
//! - [`create`]: a new resource of a class in a drive (the "New" buttons).
//! - [`notifications`]: the Inbox of the private drive: list, mark read.
//! - [`recents`]: the event-driven, persisted index behind the home lists.
//! - [`embed`]: the dispatcher the embedded web renderer's `NativeClientDb`
//!   talks to, with its signing policy.
//!
//! Two seams are left to the host, because they depend on what the host is
//! connected to:
//!
//! - [`LocalWritePusher`]: what happens after a local write is applied and
//!   queued in the outbox (drain it to a server, hand it to live peers). A
//!   host without a network passes [`NoPush`].
//! - [`AgentProfileFetcher`]: how the profile of an agent this device does not
//!   hold is looked up (the Flutter host asks the connected server).
//!   [`profiles::AgentProfiles`] caches the results in memory and is shared by
//!   the lists (names, in the background) and the embedded page (the whole
//!   profile, with a short wait).
//!
//! Native only: hosts run a tokio runtime; the browser has its own store.

pub mod chat_rooms;
pub mod chats;
pub mod context;
pub mod conversations;
pub mod create;
pub mod embed;
pub mod lists;
pub mod notifications;
pub mod profiles;
pub mod recents;
pub mod rows;

#[cfg(test)]
pub(crate) mod test_support;

use crate::commit::{CommitOpts, CommitResponse};
use async_trait::async_trait;

/// Sends a write on after it was applied locally and queued in the outbox.
#[async_trait]
pub trait LocalWritePusher: Send + Sync {
    /// Called once per local write, with what applying it returned.
    async fn push(&self, response: &CommitResponse);
}

/// A [`LocalWritePusher`] that sends nothing: the write waits in the outbox.
pub struct NoPush;

#[async_trait]
impl LocalWritePusher for NoPush {
    async fn push(&self, _response: &CommitResponse) {}
}

/// Looks up the profile of an agent this device does not hold.
#[async_trait]
pub trait AgentProfileFetcher: Send + Sync {
    /// The agent's resource as JSON-AD (at least its name and public key),
    /// `None` when it cannot be found (now). [`profiles::AgentProfiles`]
    /// bounds how long this may take.
    async fn fetch_agent_resource(&self, agent: &str) -> Option<String>;
}

/// An [`AgentProfileFetcher`] that knows no agents.
pub struct NoProfiles;

#[async_trait]
impl AgentProfileFetcher for NoProfiles {
    async fn fetch_agent_resource(&self, _agent: &str) -> Option<String> {
        None
    }
}

/// The options of a commit this device signs for its own agent.
pub fn own_commit_opts() -> CommitOpts {
    CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    }
}
