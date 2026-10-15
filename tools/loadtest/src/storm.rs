//! Scenario `storm`: reconnect after the server drops, with the real client's
//! backoff (1 s doubling to 30 s, no jitter; `--jitter` adds full jitter).

use crate::common::*;
use crate::Common;
use rand::Rng;
use serde_json::{json, Value as Json};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub struct Opts {
    pub clients: usize,
    pub ramp_secs: f64,
    pub kill_cmd: Option<String>,
    pub expect_restart: bool,
    pub jitter: bool,
    pub wait_secs: f64,
    pub max_recover_secs: f64,
}

#[derive(Default)]
struct Shared {
    connected: AtomicU64,
    reconnected: AtomicU64,
    attempts: AtomicU64,
    /// t0: the moment the kill command started, or the first observed drop.
    t0: Mutex<Option<Instant>>,
    first_drop: Mutex<Option<Instant>>,
    /// Seconds after t0 at which each client was back (authed + subscribed).
    recovered_secs: Mutex<Vec<f64>>,
    reconnect_ms: Mutex<Vec<f64>>,
    errors: Errors,
    initial_errors: Errors,
}

pub async fn run(common: &Common, o: Opts) -> Res<Json> {
    if o.kill_cmd.is_none() && !o.expect_restart {
        return Err("pass --kill-cmd '<cmd>' or --expect-restart (you restart the server)".into());
    }
    let url = ws_url(&common.server);
    let (_client, drives) = setup_drives(&common.server, 1, &[]).await?;
    let drive = drives[0].clone();
    let agents = (0..o.clients)
        .map(|i| new_agent(&format!("s{i}")))
        .collect::<Res<Vec<_>>>()?;

    let shared = Arc::new(Shared::default());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    eprintln!("connecting {} clients over {}s...", o.clients, o.ramp_secs);

    let mut handles = Vec::new();
    for (i, agent) in agents.into_iter().enumerate() {
        let shared = shared.clone();
        let url = url.clone();
        let drive = drive.clone();
        let mut stop = stop_rx.clone();
        let jitter = o.jitter;
        let delay = Duration::from_secs_f64(o.ramp_secs * i as f64 / o.clients.max(1) as f64);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let ws = match connect_client(&url, &agent, Some(&drive)).await {
                Ok((ws, _, _)) => ws,
                Err(e) => {
                    shared.initial_errors.add(classify(&e));
                    return;
                }
            };
            shared.connected.fetch_add(1, Relaxed);
            tokio::select! {
                _ = ws.wait_closed() => {}
                _ = stop.changed() => return,
            }
            let dropped_at = Instant::now();
            {
                let mut fd = shared.first_drop.lock().unwrap();
                fd.get_or_insert(dropped_at);
                let mut t0 = shared.t0.lock().unwrap();
                t0.get_or_insert(dropped_at);
            }
            drop(ws);

            // The real client: wait retryDelay, double it (cap 30 s), try again;
            // reset to 1 s on success.
            let mut delay_ms: u64 = 1000;
            loop {
                let wait = if jitter {
                    rand::thread_rng().gen_range(0..=delay_ms)
                } else {
                    delay_ms
                };
                delay_ms = (delay_ms * 2).min(30_000);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(wait)) => {}
                    _ = stop.changed() => return,
                }
                shared.attempts.fetch_add(1, Relaxed);
                let t = Instant::now();
                let attempt = tokio::select! {
                    r = connect_client(&url, &agent, Some(&drive)) => r,
                    _ = stop.changed() => return,
                };
                match attempt {
                    Ok((ws, _, _)) => {
                        let t0 = shared.t0.lock().unwrap().unwrap_or(dropped_at);
                        shared
                            .recovered_secs
                            .lock()
                            .unwrap()
                            .push(t0.elapsed().as_secs_f64());
                        shared.reconnect_ms.lock().unwrap().push(ms(t.elapsed()));
                        shared.reconnected.fetch_add(1, Relaxed);
                        let _ = stop.changed().await;
                        drop(ws);
                        return;
                    }
                    Err(e) => shared.errors.add(classify(&e)),
                }
            }
        }));
    }

    // Wait for the initial connections.
    let ramp_end = Instant::now() + Duration::from_secs_f64(o.ramp_secs + 30.0);
    while Instant::now() < ramp_end {
        let done = shared.connected.load(Relaxed) + shared.initial_errors.total();
        if done >= o.clients as u64 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let connected = shared.connected.load(Relaxed);
    println!("storm: {connected}/{} clients connected", o.clients);
    if connected == 0 {
        let _ = stop_tx.send(true);
        return Err(format!(
            "no client connected: {}",
            shared.initial_errors.to_json()
        ));
    }

    // Kill, or wait for the operator.
    let kill_status = Arc::new(Mutex::new(None::<String>));
    if let Some(cmd) = o.kill_cmd.clone() {
        eprintln!("running kill command: {cmd}");
        *shared.t0.lock().unwrap() = Some(Instant::now());
        let ks = kill_status.clone();
        match tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .spawn()
        {
            Ok(mut child) => {
                tokio::spawn(async move {
                    let r = child
                        .wait()
                        .await
                        .map(|st| st.to_string())
                        .unwrap_or_else(s);
                    *ks.lock().unwrap() = Some(r);
                });
            }
            Err(e) => return Err(format!("kill command failed to start: {e}")),
        }
    } else {
        eprintln!(
            "waiting up to {}s for the server to drop; restart it now",
            o.wait_secs
        );
    }

    let wait_end = Instant::now() + Duration::from_secs_f64(o.wait_secs);
    let mut saw_drop = false;
    let mut recover_end: Option<Instant> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let t0 = *shared.t0.lock().unwrap();
        if let Some(t0) = t0 {
            if shared.first_drop.lock().unwrap().is_some() {
                saw_drop = true;
            }
            let end = *recover_end.get_or_insert(t0 + Duration::from_secs_f64(o.max_recover_secs));
            if shared.reconnected.load(Relaxed) >= connected || Instant::now() >= end {
                break;
            }
        } else if Instant::now() >= wait_end {
            break;
        }
    }
    let _ = stop_tx.send(true);
    for h in handles {
        let _ = h.await;
    }

    let reconnected = shared.reconnected.load(Relaxed);
    let mut rec = shared.recovered_secs.lock().unwrap().clone();
    rec.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at_pct = |p: f64| -> Json {
        let need = ((p * connected as f64).ceil() as usize).max(1);
        match rec.get(need - 1) {
            Some(v) => json!((v * 100.0).round() / 100.0),
            None => Json::Null,
        }
    };
    let first_drop_after_t0 = match (
        *shared.t0.lock().unwrap(),
        *shared.first_drop.lock().unwrap(),
    ) {
        (Some(t0), Some(fd)) => Some(fd.duration_since(t0).as_secs_f64()),
        _ => None,
    };
    println!(
        "  drop observed: {saw_drop}; reconnected {reconnected}/{connected}; \
         t50={} t95={} t100={} (s after t0)",
        at_pct(0.50),
        at_pct(0.95),
        at_pct(1.0)
    );
    println!(
        "  reconnect attempts: {}, failed attempts: {}",
        shared.attempts.load(Relaxed),
        shared.errors.total()
    );
    if shared.errors.total() > 0 {
        println!("  failures: {}", shared.errors.to_json());
    }
    Ok(json!({
        "scenario": "storm",
        "config": { "server": common.server, "clients": o.clients, "ramp_secs": o.ramp_secs,
                    "kill_cmd": o.kill_cmd, "expect_restart": o.expect_restart,
                    "jitter": o.jitter, "max_recover_secs": o.max_recover_secs },
        "initially_connected": connected,
        "initial_failures": shared.initial_errors.to_json(),
        "drop_observed": saw_drop,
        "first_drop_secs_after_t0": first_drop_after_t0,
        "reconnected": reconnected,
        "not_reconnected": connected.saturating_sub(reconnected),
        "t50_secs": at_pct(0.50),
        "t95_secs": at_pct(0.95),
        "t100_secs": at_pct(1.0),
        "reconnect_attempts": shared.attempts.load(Relaxed),
        "reconnect_connect_auth_ms": summarize(shared.reconnect_ms.lock().unwrap().clone()),
        "failed_attempts_by_error": shared.errors.to_json(),
        "kill_cmd_exit": *kill_status.lock().unwrap(),
        "note": "t0 = start of --kill-cmd, or the first observed drop with --expect-restart",
    }))
}
