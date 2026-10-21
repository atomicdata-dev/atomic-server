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
//! - [`own_profile`]: this device's agent's profile: read, edit.
//! - [`peer_search`]: looking for this agent's other devices, with retries and
//!   a status a screen can show.
//! - [`store_stats`]: how much data this device holds (disk, per drive).
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
pub mod own_profile;
pub mod peer_search;
pub mod profiles;
pub mod recents;
pub mod rows;
pub mod store_stats;

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

    /// The server's `GET /history-attribution?subject=...` answer for a
    /// resource (who signed its history), as the JSON body, requested with
    /// the agent's signature like the web app does. `None` when there is no
    /// server, it refuses or it cannot be reached.
    async fn fetch_history_attribution(&self, _subject: &str) -> Option<String> {
        None
    }
}

/// `GET {origin}/history-attribution?subject=...` with the agent's signature,
/// the request the web app's Drive Activity makes per resource
/// (`store.getHistoryAttribution`). The signed URL is the URL requested,
/// query included. The body is the server's JSON; `None` on any failure.
pub async fn fetch_history_attribution(
    origin: &str,
    subject: &str,
    agent: Option<&crate::agents::Agent>,
) -> Option<String> {
    let base = format!("{}/history-attribution", origin.trim_end_matches('/'));
    let url = url::Url::parse_with_params(&base, [("subject", subject)]).ok()?;
    crate::client::fetch_body(url.as_str(), "application/json", agent)
        .await
        .ok()
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

#[cfg(test)]
mod attribution_fetch_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-shot HTTP server that records the request and answers `body`.
    async fn serve(body: &'static str, status: u16) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let reply = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(reply.as_bytes()).await.unwrap();
            request
        });
        (origin, task)
    }

    #[tokio::test]
    async fn the_request_is_the_webs_signed_history_attribution_get() {
        let (origin, task) = serve(r#"{"attributions":[]}"#, 200).await;
        let agent = crate::agents::Agent::new(Some("Me")).unwrap();
        let body = fetch_history_attribution(&origin, "did:ad:abc", Some(&agent)).await;
        assert_eq!(body.as_deref(), Some(r#"{"attributions":[]}"#));
        let request = task.await.unwrap().to_ascii_lowercase();
        assert!(
            request.starts_with("get /history-attribution?subject=did%3aad%3aabc "),
            "{request}"
        );
        for header in ["x-atomic-signature:", "x-atomic-public-key:", "x-atomic-timestamp:"] {
            assert!(request.contains(header), "{header} in {request}");
        }
    }

    #[tokio::test]
    async fn a_refusal_is_none() {
        let (origin, _task) = serve("{}", 403).await;
        assert!(fetch_history_attribution(&origin, "did:ad:abc", None)
            .await
            .is_none());
    }
}
