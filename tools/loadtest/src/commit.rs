//! Scenario `commit`: W writers edit their own resources at R/s while N
//! subscribers hold a drive subscription. Measures COMMIT ack latency and
//! fan-out lag (commit sent -> UPDATE received at a subscriber).

use crate::common::*;
use crate::Common;
use atomic_lib::{
    agents::Agent,
    client::{
        commit_to_wire_json,
        connected::Client,
        ws::{WsClient, WsMessage},
    },
    identifiers,
    sync::protocol,
    urls, Resource, Value,
};
use serde_json::{json, Value as Json};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
use tokio::sync::{broadcast::error::RecvError, watch, Barrier};

/// When each commit left a writer, keyed by commit id, with the latest send
/// time per subject as a fallback for UPDATE frames that carry no commit id.
#[derive(Default)]
struct SentTimes {
    by_commit: HashMap<String, Instant>,
    by_subject: HashMap<String, Instant>,
}

#[derive(Default)]
struct Shared {
    sent: RwLock<SentTimes>,
    ack_ms: Mutex<Vec<f64>>,
    commits_sent: AtomicU64,
    commits_ok: AtomicU64,
    errors: Errors,
    sub_connected: AtomicU64,
    writers_ready: AtomicU64,
    /// Samples of the server's error messages, one per bucket.
    samples: Mutex<HashMap<String, String>>,
}

struct SubResult {
    lag_ms: Vec<f64>,
    matched: u64,
    unmatched: u64,
    broadcast_lagged: u64,
}

pub async fn run(
    common: &Common,
    writers: usize,
    subscribers: usize,
    rate: f64,
    duration: f64,
    ramp_secs: f64,
) -> Res<Json> {
    let url = ws_url(&common.server);
    let writer_agents = (0..writers)
        .map(|i| new_agent(&format!("w{i}")))
        .collect::<Res<Vec<_>>>()?;
    eprintln!("setting up drive with {writers} writers...");
    let (client, drives) = setup_drives(&common.server, 1, &writer_agents).await?;
    let drive = drives[0].clone();
    let shared = Arc::new(Shared::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (go_tx, go_rx) = watch::channel(false);

    // Subscribers first, so they are registered before the first commit.
    let mut sub_handles = Vec::new();
    for i in 0..subscribers {
        let agent = new_agent(&format!("sub{i}"))?;
        let (shared, url, drive, stop) =
            (shared.clone(), url.clone(), drive.clone(), stop_rx.clone());
        let delay = Duration::from_secs_f64(ramp_secs * i as f64 / subscribers.max(1) as f64);
        sub_handles.push(tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            subscriber(&url, agent, &drive, shared, stop).await
        }));
    }
    let deadline = Instant::now() + Duration::from_secs_f64(ramp_secs + 30.0);
    while shared.sub_connected.load(Relaxed) + shared.errors.total() < subscribers as u64
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let subs_up = shared.sub_connected.load(Relaxed);
    eprintln!("{subs_up}/{subscribers} subscribers up; starting {writers} writers");

    let barrier = Arc::new(Barrier::new(writers + 1));
    let load_secs = Duration::from_secs_f64(duration);
    let mut writer_handles = Vec::new();
    for (i, agent) in writer_agents.into_iter().enumerate() {
        let (shared, url, drive, client) =
            (shared.clone(), url.clone(), drive.clone(), client.clone());
        let (barrier, mut go) = (barrier.clone(), go_rx.clone());
        writer_handles.push(tokio::spawn(async move {
            let ready = writer_init(i, &url, &agent, &drive, &client, &shared).await;
            barrier.wait().await;
            let _ = go.changed().await;
            if let Some((ws, resource)) = ready {
                writer_loop(i, ws, agent, resource, client, &shared, rate, load_secs).await;
            }
        }));
    }
    barrier.wait().await;
    let ready = shared.writers_ready.load(Relaxed);
    eprintln!("{ready}/{writers} writers ready; load for {duration}s");
    tokio::time::sleep(Duration::from_millis(1000)).await; // let SUBs settle
    let start = Instant::now();
    let _ = go_tx.send(true);
    for h in writer_handles {
        let _ = h.await;
    }
    let send_window = start.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_secs(3)).await; // drain fan-out
    let _ = stop_tx.send(true);

    let mut lag = Vec::new();
    let (mut matched, mut unmatched, mut lagged) = (0, 0, 0);
    for h in sub_handles {
        if let Ok(Some(r)) = h.await {
            lag.extend(r.lag_ms);
            matched += r.matched;
            unmatched += r.unmatched;
            lagged += r.broadcast_lagged;
        }
    }

    let ok = shared.commits_ok.load(Relaxed);
    let sent = shared.commits_sent.load(Relaxed);
    let ack = summarize(shared.ack_ms.lock().unwrap().clone());
    let fan = summarize(lag);
    let expected = ok * subs_up;
    println!(
        "commit: sent {sent}, acked {ok}, errors {}",
        shared.errors.total()
    );
    println!(
        "  achieved: {:.1} commits/s (target {:.1})",
        ok as f64 / send_window,
        writers as f64 * rate
    );
    println!("  commit ack latency: {}", line(&ack));
    println!("  fan-out lag:        {}", line(&fan));
    println!(
        "  updates received {matched}, expected about {expected} ({:.1}%), broadcast lag drops {lagged}",
        if expected > 0 { matched as f64 * 100.0 / expected as f64 } else { 0.0 }
    );
    if shared.errors.total() > 0 {
        println!("  errors: {}", shared.errors.to_json());
    }
    Ok(json!({
        "scenario": "commit",
        "config": { "server": common.server, "writers": writers, "subscribers": subscribers,
                    "rate_per_writer": rate, "duration_secs": duration },
        "subscribers_connected": subs_up,
        "writers_ready": ready,
        "commits_sent": sent,
        "commits_acked": ok,
        "send_window_secs": send_window,
        "target_commits_per_sec": writers as f64 * rate,
        "achieved_commits_per_sec": ok as f64 / send_window,
        "commit_ack_ms": ack,
        "fanout_lag_ms": fan,
        "updates_matched": matched,
        "updates_unmatched": unmatched,
        "updates_expected": expected,
        "subscriber_broadcast_lagged": lagged,
        "errors": shared.errors.to_json(),
        "error_samples": json!(*shared.samples.lock().unwrap()),
    }))
}

fn record_error(shared: &Shared, key: String, sample: &str) {
    shared.errors.add(key.clone());
    shared
        .samples
        .lock()
        .unwrap()
        .entry(key)
        .or_insert_with(|| sample.chars().take(200).collect());
}

async fn subscriber(
    url: &str,
    agent: Agent,
    drive: &str,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) -> Option<SubResult> {
    let ws = match connect_client(url, &agent, Some(drive)).await {
        Ok((ws, _, _)) => ws,
        Err(e) => {
            record_error(&shared, format!("subscriber_connect: {}", classify(&e)), &e);
            return None;
        }
    };
    let mut rx = ws.subscribe();
    shared.sub_connected.fetch_add(1, Relaxed);
    let mut r = SubResult {
        lag_ms: Vec::new(),
        matched: 0,
        unmatched: 0,
        broadcast_lagged: 0,
    };
    loop {
        tokio::select! {
            _ = stop.changed() => return Some(r),
            msg = rx.recv() => match msg {
                Ok(WsMessage::Update { subject, commit_id, .. }) => {
                    let now = Instant::now();
                    let sent = shared.sent.read().unwrap();
                    let at = commit_id
                        .as_ref()
                        .and_then(|c| sent.by_commit.get(c))
                        .or_else(|| sent.by_subject.get(&subject))
                        .copied();
                    drop(sent);
                    match at {
                        Some(t) => {
                            r.lag_ms.push(ms(now.saturating_duration_since(t)));
                            r.matched += 1;
                        }
                        None => r.unmatched += 1,
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => r.broadcast_lagged += n,
                Err(RecvError::Closed) => return Some(r),
            },
        }
    }
}

fn resource_in(drive: &str, name: &str) -> Result<Resource, String> {
    let mut res = Resource::new("did:ad:placeholder".into());
    res.set_unsafe(urls::IS_A.into(), vec![urls::PARAGRAPH].into())
        .map_err(s)?;
    res.set_unsafe(urls::PARENT.into(), drive.to_string().into())
        .map_err(s)?;
    res.set_name(name).map_err(s)?;
    res.set_unsafe(urls::DESCRIPTION.into(), Value::String("v0".into()))
        .map_err(s)?;
    Ok(res)
}

/// Connect, AUTH, and create this writer's resource through a genesis commit.
async fn writer_init(
    i: usize,
    url: &str,
    agent: &Agent,
    drive: &str,
    client: &Arc<Client>,
    shared: &Shared,
) -> Option<(WsClient, Resource)> {
    let fail = |stage: &str, e: String| {
        record_error(shared, format!("writer_{stage}: {}", classify(&e)), &e);
        None
    };
    let ws = match connect_client(url, agent, None).await {
        Ok((ws, _, _)) => ws,
        Err(e) => return fail("connect", e),
    };
    let mut res = match resource_in(drive, &format!("loadtest-w{i}")) {
        Ok(r) => r,
        Err(e) => return fail("build", e),
    };
    let store = client.store();
    let response = match res.save_as_genesis_signed_by(agent, store).await {
        Ok(r) => r,
        Err(e) => return fail("genesis_sign", s(e)),
    };
    let json = match commit_to_wire_json(&response.commit, store).await {
        Ok(j) => j,
        Err(e) => return fail("genesis_json", s(e)),
    };
    if let Err(e) = ws.post_commit(1, &json).await {
        return fail("genesis_post", s(e));
    }
    shared.writers_ready.fetch_add(1, Relaxed);
    Some((ws, res))
}

#[allow(clippy::too_many_arguments)]
async fn writer_loop(
    i: usize,
    ws: WsClient,
    agent: Agent,
    mut res: Resource,
    client: Arc<Client>,
    shared: &Arc<Shared>,
    rate: f64,
    load: Duration,
) {
    let store = client.store();
    let end = Instant::now() + load;
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate.max(0.001)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut waiters = Vec::new();
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        if Instant::now() >= end {
            break;
        }
        n += 1;
        // Sign sequentially: each edit builds on the previous commit.
        let signed = async {
            res.set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String(format!("writer {i} edit {n}")),
            )
            .map_err(s)?;
            let response = res.save_as(&agent, store).await.map_err(s)?;
            let sig = response.commit.signature.clone().ok_or("unsigned commit")?;
            let json = commit_to_wire_json(&response.commit, store)
                .await
                .map_err(s)?;
            Ok::<_, String>((identifiers::commit_subject(&sig), json))
        }
        .await;
        let (commit_id, json) = match signed {
            Ok(v) => v,
            Err(e) => {
                record_error(shared, format!("sign: {}", classify(&e)), &e);
                continue;
            }
        };
        let rid = (n % 60_000) as u16 + 2;
        let mut rx = ws.subscribe();
        let t = Instant::now();
        {
            let mut sent = shared.sent.write().unwrap();
            sent.by_commit.insert(commit_id, t);
            sent.by_subject.insert(res.get_subject().to_string(), t);
        }
        if let Err(e) = ws.send_binary(protocol::encode_commit(rid, &json)).await {
            record_error(shared, format!("send: {}", classify(&s(e))), "send failed");
            break;
        }
        shared.commits_sent.fetch_add(1, Relaxed);
        let shared = shared.clone();
        waiters.push(tokio::spawn(async move {
            let outcome = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match rx.recv().await {
                        Ok(WsMessage::CommitOk { request_id, .. }) if request_id == rid => {
                            return Ok(())
                        }
                        Ok(WsMessage::Error {
                            request_id,
                            code,
                            message,
                        }) if request_id == rid => {
                            return Err((format!("commit_error code={code}"), message))
                        }
                        Err(RecvError::Closed) => {
                            return Err(("socket_closed".to_string(), String::new()))
                        }
                        _ => {}
                    }
                }
            })
            .await;
            match outcome {
                Ok(Ok(())) => {
                    shared.ack_ms.lock().unwrap().push(ms(t.elapsed()));
                    shared.commits_ok.fetch_add(1, Relaxed);
                }
                Ok(Err((key, msg))) => record_error(&shared, key, &msg),
                Err(_) => record_error(&shared, "commit_ack_timeout".into(), "no COMMIT_OK in 30s"),
            }
        }));
    }
    for w in waiters {
        let _ = w.await;
    }
}
