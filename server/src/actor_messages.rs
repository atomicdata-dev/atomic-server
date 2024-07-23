//! The actor messages are used for communication between Actix Actors.
//! In this case it's for communication between the CommitMonitor and the WebSocketConnection.

use actix::{prelude::Message, Addr};

/// Subscribes a WebSocketConnection to a Subject.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    pub subject: String,
    pub agent: String,
}

/// A message containing a Resource, which should be sent to subscribers
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct CommitMessage {
    /// Full resource of the Commit itself, the new resource, and the old one
    pub commit_response: atomic_lib::commit::CommitResponse,
}
