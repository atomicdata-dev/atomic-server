//! Integration test: drive-scoped ephemeral presence (issue #1229).
//!
//! Presence updates are opaque Loro EphemeralStore blobs relayed through
//! `CommitMonitor`'s drive-keyed presence map. The contract pinned
//! here:
//!
//! 1. An update broadcast by one presence subscriber reaches every other
//!    subscriber of the same drive — and never echoes back to the sender.
//! 2. The broadcaster caches each connection's latest state and replays it
//!    to late joiners at subscribe time, so a newly-opened tab sees who is
//!    present without waiting for the next heartbeat.
//! 3. Subscribing is the auth gate: an agent without read access on the
//!    drive never gets fan-out, and a connection that skipped
//!    `PRESENCE_SUBSCRIBE` cannot broadcast into the drive.
//!
//! Run with: cargo test -p atomic-server --test drive_presence

use atomic_lib::{
    client::{
        connected::Client,
        ws::{WsClient, WsMessage},
    },
    errors::AtomicResult,
};
use std::time::Duration;
use tokio::sync::broadcast::Receiver;

/// Start an AtomicServer on a random port in a background thread.
use crate::common::{start_server, wait_for_server};

/// Wait up to `secs` for a `PresenceUpdate` on `drive`; `None` on timeout.
async fn recv_presence(rx: &mut Receiver<WsMessage>, drive: &str, secs: u64) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            match rx.recv().await {
                Ok(WsMessage::PresenceUpdate { subject, update }) if subject == drive => {
                    return Some(update);
                }
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    })
    .await
    .unwrap_or(None)
}

#[tokio::test]
async fn presence_relays_caches_and_gates() -> AtomicResult<()> {
    let port = start_server("drive_presence");
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{}", port);
    let ws_url = format!("ws://localhost:{}/ws", port);

    let client = Client::new(&server_url).await?;
    let agent_a = client.new_agent("Alice").await?;
    let drive = client.new_public_drive(&agent_a, "Presence Drive").await?;

    let client_b = Client::new(&server_url).await?;
    let agent_b = client_b.new_agent("Bob").await?;

    // ----- Alice and Bob subscribe to the drive's presence channel -----
    let ws_a = WsClient::connect(&ws_url).await?;
    ws_a.authenticate(&agent_a).await?;
    ws_a.subscribe_presence(&drive).await?;

    let ws_b = WsClient::connect(&ws_url).await?;
    ws_b.authenticate(&agent_b).await?;
    ws_b.subscribe_presence(&drive).await?;

    let mut rx_a = ws_a.subscribe();
    let mut rx_b = ws_b.subscribe();

    // Let both subscriptions register in the broadcaster's map.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ----- Relay: Alice broadcasts, Bob receives, Alice gets no echo -----
    // Bytes are opaque to the server; production sends
    // `EphemeralStore.encodeAll()`, a distinctive blob suffices here.
    // The broadcaster admits an update only from a connection whose
    // subscribe has finished its read check, and that check is a store
    // read the actor runs concurrently; on a loaded host the first update
    // can land before it. Production re-announces on a heartbeat, so do
    // the same here rather than sleeping longer.
    let alice_state: Vec<u8> = b"alice-presence-state".to_vec();
    let mut received = None;
    for _ in 0..10 {
        ws_a.send_presence_update(&drive, &alice_state).await?;
        if let Some(bytes) = recv_presence(&mut rx_b, &drive, 1).await {
            received = Some(bytes);
            break;
        }
    }
    let received = received.expect("Bob should receive Alice's presence update");
    assert_eq!(
        received, alice_state,
        "Bob should receive the exact bytes Alice broadcast"
    );

    assert!(
        recv_presence(&mut rx_a, &drive, 1).await.is_none(),
        "Sender should not receive its own presence update (got echo)"
    );

    // ----- Cache replay: a late joiner sees Alice's state immediately -----
    let client_c = Client::new(&server_url).await?;
    let agent_c = client_c.new_agent("Carol").await?;
    let ws_c = WsClient::connect(&ws_url).await?;
    ws_c.authenticate(&agent_c).await?;
    let mut rx_c = ws_c.subscribe();
    ws_c.subscribe_presence(&drive).await?;

    let replayed = recv_presence(&mut rx_c, &drive, 5)
        .await
        .expect("Late joiner should receive Alice's cached presence state");
    assert_eq!(
        replayed, alice_state,
        "Replayed state should be Alice's latest broadcast"
    );

    // ----- Gate: broadcasting without subscribing goes nowhere -----
    let ws_d = WsClient::connect(&ws_url).await?;
    ws_d.authenticate(&agent_b).await?;
    ws_d.send_presence_update(&drive, b"not-subscribed").await?;

    assert!(
        recv_presence(&mut rx_b, &drive, 1).await.is_none(),
        "Updates from a non-subscribed connection must not fan out"
    );

    // ----- Gate: no read access on the drive → subscribe is refused -----
    // Alice's *private* drive: Bob can't read it, so his subscription is
    // dropped and Alice's broadcasts never reach him.
    let private_drive = client.new_drive(&agent_a, "Private Drive").await?;

    let ws_a2 = WsClient::connect(&ws_url).await?;
    ws_a2.authenticate(&agent_a).await?;
    ws_a2.subscribe_presence(&private_drive).await?;

    let ws_b2 = WsClient::connect(&ws_url).await?;
    ws_b2.authenticate(&agent_b).await?;
    let mut rx_b2 = ws_b2.subscribe();
    ws_b2.subscribe_presence(&private_drive).await?;

    tokio::time::sleep(Duration::from_millis(300)).await;
    ws_a2
        .send_presence_update(&private_drive, b"secret-location")
        .await?;

    assert!(
        recv_presence(&mut rx_b2, &private_drive, 1).await.is_none(),
        "Agent without read access must not receive presence for a private drive"
    );

    Ok(())
}
