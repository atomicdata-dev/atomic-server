//! Integration test: Loro ephemeral updates (cursor / presence) propagate
//! from one WS client to other subscribers of the same subject.
//!
//! Pins the migration contract introduced in #1173 (Yjs → Loro): the
//! live-cursor sync moved from y-protocols awareness frames to Loro
//! ephemeral updates broadcast through `CommitMonitor`. The same
//! `LORO_SYNC_SUBSCRIBE`-keyed map drives both document sync AND
//! ephemeral cursor fan-out (`commit_monitor.rs`'s drive subscribers
//! handle persisted edits; the Loro maps on the same actor handle
//! real-time-only presence). A future cleanup that splits the maps without rewiring
//! the ephemeral handler would silently strand cursors — that's the
//! regression this test catches.
//!
//! Run with: cargo test -p atomic-server --test loro_ephemeral_sync

use atomic_lib::{
    client::{
        connected::Client,
        ws::{WsClient, WsMessage},
    },
    errors::AtomicResult,
};
use std::time::Duration;

/// Start an AtomicServer on a random port in a background thread.
use crate::common::{start_server, wait_for_server};

#[tokio::test]
async fn ephemeral_update_broadcasts_to_other_subscribers() -> AtomicResult<()> {
    let port = start_server("loro_ephemeral_sync");
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{}", port);
    let ws_url = format!("ws://localhost:{}/ws", port);

    // ----- Alice creates a public drive + a resource -----
    let client_a = Client::new(&server_url).await?;
    let agent_a = client_a.new_agent("Alice").await?;
    let drive_a = client_a.new_public_drive(&agent_a, "Alice's Drive").await?;

    let mut resource = client_a.new_resource(&drive_a)?;
    resource.set_name("Doc with cursors")?;
    resource.set_unsafe(
        atomic_lib::urls::SHORTNAME.into(),
        atomic_lib::Value::Slug("ephemeral-doc".into()),
    )?;
    resource.set_unsafe(
        atomic_lib::urls::DESCRIPTION.into(),
        atomic_lib::Value::String("A test document for ephemeral cursor sync".into()),
    )?;
    resource.set_unsafe(
        atomic_lib::urls::IS_A.into(),
        atomic_lib::Value::ResourceArray(vec![atomic_lib::urls::CLASS.into()]),
    )?;
    let subject = resource.save_remote(client_a.store()).await?;

    // ----- Both clients connect WS + subscribe to LORO_SYNC for the doc -----
    // The Loro broadcaster keys ephemeral fan-out by `LORO_SYNC_SUBSCRIBE`
    // entries — there is no separate `LORO_EPHEMERAL_SUBSCRIBE` frame.
    let client_b = Client::new(&server_url).await?;
    let agent_b = client_b.new_agent("Bob").await?;

    let ws_a = WsClient::connect(&ws_url).await?;
    ws_a.authenticate(&agent_a).await?;
    ws_a.subscribe_loro_sync(&subject).await?;

    let ws_b = WsClient::connect(&ws_url).await?;
    ws_b.authenticate(&agent_b).await?;
    ws_b.subscribe_loro_sync(&subject).await?;

    let mut rx_a = ws_a.subscribe();
    let mut rx_b = ws_b.subscribe();

    // Let both subscriptions register in the broadcaster's map.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ----- Alice sends an ephemeral update -----
    // The bytes are opaque to the server (it just relays); the production
    // payload would be `EphemeralStore.encodeAll()` from loro-crdt.
    // A non-empty distinctive blob is enough to verify the relay.
    let cursor_bytes: Vec<u8> = b"alice-cursor-blob".to_vec();
    ws_a.send_loro_ephemeral_update(&subject, &cursor_bytes)
        .await?;

    // ----- Bob should receive it within 5s -----
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx_b.recv().await {
                Ok(WsMessage::LoroEphemeralUpdate { subject: s, update }) => {
                    if s == subject {
                        return Ok::<Vec<u8>, atomic_lib::errors::AtomicError>(update);
                    }
                }
                Ok(WsMessage::Error { message, .. }) => {
                    tracing::warn!("WS B error: {}", message);
                }
                Ok(_) => continue,
                Err(e) => {
                    return Err(format!("WS B channel closed: {}", e).into());
                }
            }
        }
    })
    .await
    .map_err(|_| "Timeout: Bob did not receive the ephemeral update within 5 seconds")??;

    assert_eq!(
        received, cursor_bytes,
        "Bob should receive the exact bytes Alice broadcast"
    );

    // ----- Sender suppression: Alice should NOT receive her own update -----
    // The broadcaster skips the originating address (`subscriber.addr ==
    // sender_addr` check in `commit_monitor.rs`). A regression that
    // forgot to skip self would echo every cursor move back to the typer
    // and double-render their own caret.
    let echo = tokio::time::timeout(Duration::from_millis(400), async {
        loop {
            match rx_a.recv().await {
                Ok(WsMessage::LoroEphemeralUpdate { subject: s, .. }) if s == subject => {
                    return true;
                }
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await;

    assert!(
        echo.is_err(),
        "Sender should not receive its own ephemeral update (got echo)"
    );

    Ok(())
}
