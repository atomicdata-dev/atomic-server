//! The actor messages are used for communication between Actix Actors.
//! In this case it's for communication between the CommitMonitor and the WebSocketConnection.

use actix::{prelude::Message, Addr};

//WebSocketConnection responds to this to pipe it through to the actual client
#[derive(Message)]
#[rtype(result = "()")]
pub struct WsMessage(pub String);

/// Subscribes a WebSocketConnection to a Subject.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    pub subject: String,
}

/// A message containing a Resource, which should be sent to subscribers
#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct CommitMessage {
    /// Target subject of the commit
    pub subject: String,
    /// Full resource of the Commit itself, the new resource, and the old one
    pub commit_response: atomic_lib::commit::CommitResponse,
}
