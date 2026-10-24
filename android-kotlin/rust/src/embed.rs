//! The embedded renderer's channel: one async dispatch call, and store changes
//! pushed to the page. The call contract is `atomic_lib::host::embed::EmbedHost`
//! (the Flutter app binds the same one): `method` and a JSON array of
//! arguments in, JSON out. This module only adds what a host decides:
//!
//! - which `LocalWritePusher` follows a page write: the real one, so the commit
//!   reaches the server, live peers and paired devices (`state::pusher`),
//! - agent names come from the connected server (`state::profiles`),
//! - an echo filter, so the page is not told about the commits it applied
//!   itself (re-reading a document under the cursor would fight the editor),
//! - coalescing: a burst of store events is one `changed([...])` call.

use crate::{
    error::CoreResult,
    state::{db, node, profiles, pusher, recents},
    types::EmbedListener,
};
use atomic_lib::{
    host::embed::EmbedHost,
    DbEvent,
};
use serde_json::Value as Json;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

/// How long a write of the page itself is not echoed back to it.
const ECHO_WINDOW: Duration = Duration::from_millis(2500);
/// Events of one burst are sent together after this quiet time.
const BATCH_WINDOW: Duration = Duration::from_millis(60);

/// The page's own recent writes, by resource id.
#[derive(Default)]
pub(crate) struct EchoFilter {
    writes: Mutex<HashMap<String, Instant>>,
}

/// The id part of a subject, whatever its spelling (`did:ad:x`, `atomic:x`).
fn key(subject: &str) -> &str {
    subject
        .strip_prefix("did:ad:")
        .or_else(|| subject.strip_prefix("atomic:"))
        .unwrap_or(subject)
}

impl EchoFilter {
    pub(crate) fn wrote(&self, subject: &str) {
        let mut writes = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        writes.retain(|_, at| now.duration_since(*at) < ECHO_WINDOW);
        writes.insert(key(subject).to_string(), now);
    }

    /// True when `subject` changed because of the page's own commit.
    pub(crate) fn is_echo(&self, subject: &str) -> bool {
        let writes = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        writes
            .get(key(subject))
            .is_some_and(|at| at.elapsed() < ECHO_WINDOW)
    }
}

/// The subject a page commit (the body of `applyCommit`) is about.
fn commit_subject(args_json: &str) -> Option<String> {
    let args: Vec<Json> = serde_json::from_str(args_json).ok()?;
    let commit: Json = serde_json::from_str(args.first()?.as_str()?).ok()?;
    commit[atomic_lib::urls::SUBJECT].as_str().map(str::to_string)
}

/// The host of one process: built when the first call arrives (after
/// `open_store`).
pub(crate) struct Embed {
    host: EmbedHost,
    pub(crate) echo: EchoFilter,
}

impl Embed {
    pub(crate) fn new(host: EmbedHost) -> Self {
        Embed { host, echo: EchoFilter::default() }
    }

    pub(crate) async fn call(&self, method: &str, args_json: &str) -> Result<String, String> {
        let answer = self.host.call(method, args_json).await?;
        if method == "applyCommit" {
            if let Some(subject) = commit_subject(args_json) {
                self.echo.wrote(&subject);
            }
        }
        Ok(answer)
    }
}

pub(crate) fn embed() -> CoreResult<&'static Embed> {
    static EMBED: OnceLock<Embed> = OnceLock::new();
    if let Some(embed) = EMBED.get() {
        return Ok(embed);
    }
    let host = EmbedHost::new(node()?, pusher(), profiles())
        .with_recents(recents().clone());
    Ok(EMBED.get_or_init(|| Embed::new(host)))
}

/// The subjects a burst of events asks the page to read again: changed
/// resources and destroyed ones (the page drops them), once each, minus the
/// page's own writes. `QueryMembership` carries a query, not a resource.
pub(crate) fn changed_subjects(events: &[DbEvent], echo: &EchoFilter) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for event in events {
        let subject = match event {
            DbEvent::Changed { subject, .. } if !echo.is_echo(&subject.to_string()) => {
                subject.to_string()
            }
            DbEvent::Destroyed { subject, .. } => subject.to_string(),
            _ => continue,
        };
        if seen.insert(subject.clone()) {
            out.push(subject);
        }
    }
    out
}

/// Pushes store changes to `listener` until the task is aborted.
pub(crate) fn spawn_pusher(
    listener: Arc<dyn EmbedListener>,
) -> CoreResult<tokio::task::AbortHandle> {
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = db()?.subscribe_events();
    let echo = &embed()?.echo;
    let handle = tokio::spawn(async move {
        loop {
            let mut burst = Vec::new();
            match rx.recv().await {
                Ok(event) => burst.push(event),
                // Events were dropped: nothing says which, the page keeps what it has.
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            }
            let deadline = tokio::time::Instant::now() + BATCH_WINDOW;
            while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                burst.push(event);
            }
            let subjects = changed_subjects(&burst, echo);
            if !subjects.is_empty() {
                listener.on_changed(subjects);
            }
        }
    });
    Ok(handle.abort_handle())
}
