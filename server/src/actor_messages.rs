//! The actor messages are used for communication between Actix Actors.
//! In this case it's for communication between the CommitMonitor and the WebSocketConnection.

use actix::{
    prelude::{Message, Recipient},
    Addr,
};
use uuid::Uuid;

//WebSocketConnection responds to this to pipe it through to the actual client
#[derive(Message)]
#[rtype(result = "()")]
pub struct WsMessage(pub String);

//WebSocketConnection sends this to the CommitMonitor to.. I don't know why?
#[derive(Message)]
#[rtype(result = "()")]
pub struct Connect {
    pub addr: Recipient<WsMessage>,
    pub CommitMonitor_id: Uuid,
    pub self_id: Uuid,
}

//WebSocketConnection sends this to a CommitMonitor to remove all subscriptions.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub room_id: Uuid,
    pub id: Uuid,
}

/// Subscribes a WebSocketConnection to a Subject.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    // pub websocket_id: Uuid,
    pub subject: String,
}

/// A message containing a Resource, which should be sent to subscribers
#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct CommitMessage {
    /// Target subject of the commit
    pub subject: String,
    /// Full resource of the Commit itself
    pub resource: atomic_lib::Resource,
}
