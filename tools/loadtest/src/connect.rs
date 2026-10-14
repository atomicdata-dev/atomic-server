//! Scenario `connect`: N idle authenticated WebSocket clients held open.

use crate::common::*;
use crate::Common;
use atomic_lib::client::ws::{WsClient, WsMessage};
use serde_json::{json, Value as Json};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::broadcast::error::RecvError;

/// The real client's liveness rules (browser/lib/src/liveness.ts).
const IDLE_PROBE: Duration = Duration::from_secs(20);
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);
const CHECK_EVERY: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Shared {
    connect_ms: Mutex<Vec<f64>>,
    auth_ms: Mutex<Vec<f64>>,
    keepalive_rtt_ms: Mutex<Vec<f64>>,
    ok: AtomicU64,
    held: AtomicU64,
    dropped: AtomicU64,
    keepalives_sent: AtomicU64,
    errors: Errors,
}

pub async fn run(
    common: &Common,
    clients: usize,
    ramp_secs: f64,
    hold_secs: f64,
    drives: usize,
) -> Res<Json> {
    let url = ws_url(&common.server);
    eprintln!("setting up {drives} drive(s)...");
    let (_client, drive_list) = setup_drives(&common.server, drives, &[]).await?;
    let agents = (0..clients)
        .map(|i| new_agent(&format!("c{i}")))
        .collect::<Res<Vec<_>>>()?;

    let shared = Arc::new(Shared::default());
    let started = Instant::now();
    let hold = Duration::from_secs_f64(hold_secs);
    eprintln!("connecting {clients} clients over {ramp_secs}s, holding {hold_secs}s...");

    let mut handles = Vec::with_capacity(clients);
    for (i, agent) in agents.into_iter().enumerate() {
        let shared = shared.clone();
        let url = url.clone();
        let drive = drive_list[i % drive_list.len()].clone();
        let delay = Duration::from_secs_f64(ramp_secs * i as f64 / clients.max(1) as f64);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            match connect_client(&url, &agent, Some(&drive)).await {
                Err(e) => shared.errors.add(classify(&e)),
                Ok((ws, connect, authed)) => {
                    shared.connect_ms.lock().unwrap().push(connect);
                    shared.auth_ms.lock().unwrap().push(authed);
                    shared.ok.fetch_add(1, Relaxed);
                    hold_open(ws, hold, &shared).await;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    let wall = started.elapsed().as_secs_f64();

    let ok = shared.ok.load(Relaxed);
    let connect = summarize(shared.connect_ms.lock().unwrap().clone());
    let authed = summarize(shared.auth_ms.lock().unwrap().clone());
    let rtt = summarize(shared.keepalive_rtt_ms.lock().unwrap().clone());
    println!(
        "connect: {ok}/{clients} succeeded ({} failed)",
        shared.errors.total()
    );
    println!("  connect+auth latency: {}", line(&authed));
    println!(
        "  held to the end: {}, dropped while holding: {}",
        shared.held.load(Relaxed),
        shared.dropped.load(Relaxed)
    );
    println!("  keepalive rtt: {}", line(&rtt));
    if shared.errors.total() > 0 {
        println!("  failures: {}", shared.errors.to_json());
    }
    Ok(json!({
        "scenario": "connect",
        "config": { "server": common.server, "clients": clients, "ramp_secs": ramp_secs,
                    "hold_secs": hold_secs, "drives": drives },
        "wall_secs": wall,
        "success": ok,
        "failed": shared.errors.total(),
        "success_rate": ok as f64 / clients.max(1) as f64,
        "held_to_end": shared.held.load(Relaxed),
        "dropped_while_holding": shared.dropped.load(Relaxed),
        "keepalives_sent": shared.keepalives_sent.load(Relaxed),
        "connect_ms": connect,
        "connect_plus_auth_ms": authed,
        "keepalive_rtt_ms": rtt,
        "errors": shared.errors.to_json(),
    }))
}

/// Hold a connection open, probing like the real client: after 20 s of
/// silence send KEEPALIVE; close if the probe goes unanswered for 25 s.
async fn hold_open(ws: WsClient, hold: Duration, shared: &Shared) {
    let end = Instant::now() + hold;
    let mut rx = ws.subscribe();
    let mut last_inbound = Instant::now();
    let mut probe_sent: Option<Instant> = None;
    let mut tick = tokio::time::interval(CHECK_EVERY);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(end.into()) => {
                shared.held.fetch_add(1, Relaxed);
                return;
            }
            _ = ws.wait_closed() => {
                shared.dropped.fetch_add(1, Relaxed);
                shared.errors.add("dropped_while_holding: socket closed");
                return;
            }
            msg = rx.recv() => match msg {
                Ok(WsMessage::Keepalive) => {
                    if let Some(t) = probe_sent.take() {
                        shared.keepalive_rtt_ms.lock().unwrap().push(ms(t.elapsed()));
                    }
                    last_inbound = Instant::now();
                }
                Ok(WsMessage::Error { code, .. }) => {
                    shared.errors.add(format!("server_error_frame code={code}"));
                    last_inbound = Instant::now();
                }
                Ok(_) => {
                    probe_sent = None;
                    last_inbound = Instant::now();
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            },
            _ = tick.tick() => {
                match probe_sent {
                    Some(t) if t.elapsed() >= PROBE_TIMEOUT => {
                        shared.dropped.fetch_add(1, Relaxed);
                        shared.errors.add("dropped_while_holding: keepalive unanswered");
                        return;
                    }
                    None if last_inbound.elapsed() >= IDLE_PROBE => {
                        if ws.send_keepalive().await.is_err() {
                            shared.dropped.fetch_add(1, Relaxed);
                            shared.errors.add("dropped_while_holding: send failed");
                            return;
                        }
                        shared.keepalives_sent.fetch_add(1, Relaxed);
                        probe_sent = Some(Instant::now());
                    }
                    _ => {}
                }
            }
        }
    }
}
