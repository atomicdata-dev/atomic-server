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
use tokio::{
    sync::{broadcast::error::RecvError, watch, Barrier},
    task::JoinHandle,
};

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
    skipped_ticks: AtomicU64,
    errors: Errors,
    /// Edits made on the writers (applied locally, whether or not sent yet).
    edits_made: AtomicU64,
    /// Edits whose commit the server acknowledged, in total and before the
    /// load window closed.
    edits_acked: AtomicU64,
    edits_acked_in_window: AtomicU64,
    commits_ok_in_window: AtomicU64,
    /// Edits still unsent when a writer gave up flushing.
    edits_unsent: AtomicU64,
    /// BUSY refusals (error code 12), including the rate limiter's.
    busy: AtomicU64,
    /// Time from an edit to the ack of the commit that carried it.
    edit_latency_ms: Mutex<Vec<f64>>,
    /// `pace_ms` of every COMMIT_OK that carried one.
    pace_ms: Mutex<Vec<f64>>,
    /// Edits per commit.
    batch_sizes: Mutex<Vec<f64>>,
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

pub struct Opts {
    pub writers: usize,
    pub subscribers: usize,
    pub rate: f64,
    pub duration: f64,
    pub ramp_secs: f64,
    pub closed_loop: bool,
    /// Local edits per second per writer. Edits accumulate and one commit
    /// carries all pending ones whenever the writer is allowed to send
    /// (previous commit acked, server pace and BUSY waits over).
    pub edit_rate: Option<f64>,
    /// Least time between two commits of a writer, like the app's debounce.
    pub debounce_ms: u64,
}

pub async fn run(common: &Common, opts: Opts) -> Res<Json> {
    let Opts {
        writers,
        subscribers,
        rate,
        duration,
        ramp_secs,
        closed_loop,
        edit_rate,
        debounce_ms,
    } = opts;
    let closed_loop = closed_loop || edit_rate.is_some();
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
                if closed_loop {
                    paced_loop(
                        i,
                        ws,
                        agent,
                        resource,
                        client,
                        &shared,
                        PacedOpts {
                            tick_rate: edit_rate.unwrap_or(rate),
                            edit_model: edit_rate.is_some(),
                            load: load_secs,
                            debounce: Duration::from_millis(debounce_ms),
                        },
                    )
                    .await;
                } else {
                    writer_loop(i, ws, agent, resource, client, &shared, rate, load_secs).await;
                }
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
    let skipped = shared.skipped_ticks.load(Relaxed);
    println!(
        "commit: sent {sent}, acked {ok}, errors {}",
        shared.errors.total()
    );
    let edit_stats = edit_rate.map(|e| {
        let made = shared.edits_made.load(Relaxed);
        let acked = shared.edits_acked.load(Relaxed);
        let in_window = shared.edits_acked_in_window.load(Relaxed);
        let commits_in_window = shared.commits_ok_in_window.load(Relaxed);
        let latency = summarize(shared.edit_latency_ms.lock().unwrap().clone());
        let batch = summarize(shared.batch_sizes.lock().unwrap().clone());
        (e, made, acked, in_window, commits_in_window, latency, batch)
    });
    let pace = summarize(shared.pace_ms.lock().unwrap().clone());
    let busy = shared.busy.load(Relaxed);
    if let Some((e, made, acked, in_window, commits_in_window, latency, batch)) = &edit_stats {
        println!(
            "  edit model: {writers} writers x {e}/s = {:.1} edits/s offered",
            *e * writers as f64
        );
        println!(
            "  edits: made {made}, reached the server {acked} ({} unsent at the end)",
            shared.edits_unsent.load(Relaxed)
        );
        println!(
            "  achieved: {:.1} edits/s, {:.1} commits/s (acked inside the {duration}s window)",
            *in_window as f64 / duration,
            *commits_in_window as f64 / duration
        );
        println!("  edits per commit:   {}", line_plain(batch));
        println!("  edit-to-server latency: {}", line(latency));
    } else {
        println!(
            "  achieved: {:.1} commits/s (target {:.1})",
            ok as f64 / send_window,
            writers as f64 * rate
        );
    }
    if closed_loop {
        println!(
            "  closed loop: {skipped} ticks skipped (previous commit unacked, pace or BUSY wait)"
        );
    }
    println!("  BUSY refusals: {busy}");
    println!("  server pace_ms:     {}", line_plain(&pace));
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
                    "rate_per_writer": rate, "duration_secs": duration,
                    "closed_loop": closed_loop, "edit_rate": edit_rate,
                    "debounce_ms": debounce_ms },
        "subscribers_connected": subs_up,
        "writers_ready": ready,
        "commits_sent": sent,
        "commits_acked": ok,
        "skipped_ticks": skipped,
        "send_window_secs": send_window,
        "target_commits_per_sec": writers as f64 * rate,
        "achieved_commits_per_sec": ok as f64 / send_window,
        "edit_model": edit_stats.as_ref().map(|(e, made, acked, in_window, commits_in_window, latency, batch)| json!({
            "edit_rate_per_writer": e,
            "offered_edits_per_sec": e * writers as f64,
            "edits_made": made,
            "edits_reached_server": acked,
            "edits_unsent_at_end": shared.edits_unsent.load(Relaxed),
            "achieved_edits_per_sec": *in_window as f64 / duration,
            "achieved_commits_per_sec_in_window": *commits_in_window as f64 / duration,
            "edits_per_commit": batch,
            "edit_to_server_latency_ms": latency,
        })),
        "busy_refusals": busy,
        "server_pace_ms": pace,
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
    // A busy node refuses with a retry delay; setting up is not load, so wait
    // it out like the app would.
    let mut tries = 0;
    loop {
        match ws.post_commit(1, &json).await {
            Ok(_) => break,
            Err(e) => {
                let msg = s(e);
                match protocol::retry_after_ms_from_message(&msg) {
                    Some(wait) if msg.contains("code 12") && tries < 60 => {
                        tries += 1;
                        tokio::time::sleep(Duration::from_millis(wait + 100)).await;
                    }
                    _ => return fail("genesis_post", msg),
                }
            }
        }
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
    let mut waiters: Vec<JoinHandle<()>> = Vec::new();
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
        let shared_busy = shared.clone();
        waiters.push(tokio::spawn(async move {
            let outcome = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match rx.recv().await {
                        Ok(WsMessage::CommitOk {
                            request_id,
                            pace_ms,
                            ..
                        }) if request_id == rid => {
                            if let Some(p) = pace_ms {
                                shared_busy.pace_ms.lock().unwrap().push(p as f64);
                            }
                            return Ok(());
                        }
                        Ok(WsMessage::Error {
                            request_id,
                            code,
                            message,
                        }) if request_id == rid => {
                            if code == protocol::error_code::BUSY {
                                shared_busy.busy.fetch_add(1, Relaxed);
                            }
                            return Err((format!("commit_error code={code}"), message));
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

struct PacedOpts {
    /// Ticks per second: edits in the edit model, attempted commits otherwise.
    tick_rate: f64,
    /// Edits accumulate and ride in one commit (`--edit-rate`), instead of
    /// one commit per tick that finds the writer free (`--closed-loop`).
    edit_model: bool,
    load: Duration,
    debounce: Duration,
}

/// The commit a closed-loop writer has sent and not yet seen answered.
struct Inflight {
    rid: u16,
    sent: Instant,
    /// Wire JSON, kept so a BUSY refusal can be resent unchanged (the commit
    /// chain already moved past it).
    json: String,
    /// When each edit in this commit was made.
    edits: Vec<Instant>,
}

/// Closed-loop writer that honours the server's load signals: one commit in
/// flight, at most one commit per `max(debounce, pace_ms)`, and a BUSY
/// refusal is waited out (retry-after plus jitter) and resent, never counted
/// as a failure. In the edit model, edits happen locally at `tick_rate` per
/// second and every commit carries all edits made since the previous one.
async fn paced_loop(
    i: usize,
    ws: WsClient,
    agent: Agent,
    mut res: Resource,
    client: Arc<Client>,
    shared: &Arc<Shared>,
    opts: PacedOpts,
) {
    let store = client.store();
    let start = Instant::now();
    let end = start + opts.load;
    // Pending edits can still be flushed this long after the window closed.
    let flush_deadline = end + Duration::from_secs(15);
    let mut rx = ws.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / opts.tick_rate.max(0.001)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending: Vec<Instant> = Vec::new();
    let mut inflight: Option<Inflight> = None;
    // A BUSY-refused commit waiting for its turn.
    let mut resend: Option<Inflight> = None;
    let mut next_send_at = start;
    let mut pace = Duration::ZERO;
    let mut n: u64 = 0;
    let mut rid_counter: u64 = 0;

    loop {
        let now = Instant::now();
        let closing = now >= end;
        if now >= flush_deadline {
            break;
        }

        // Send when allowed: nothing in flight, pace and BUSY waits over.
        if inflight.is_none() && now >= next_send_at {
            if let Some(mut r) = resend.take() {
                r.sent = now;
                send_registered(&ws, shared, &r).await;
                shared.commits_sent.fetch_add(1, Relaxed);
                inflight = Some(r);
            } else if !pending.is_empty() {
                let edits = std::mem::take(&mut pending);
                let signed = async {
                    let response = res.save_as(&agent, store).await.map_err(s)?;
                    let sig = response.commit.signature.clone().ok_or("unsigned commit")?;
                    let json = commit_to_wire_json(&response.commit, store)
                        .await
                        .map_err(s)?;
                    Ok::<_, String>((identifiers::commit_subject(&sig), json))
                }
                .await;
                match signed {
                    Ok((commit_id, json)) => {
                        rid_counter += 1;
                        let rid = (rid_counter % 60_000) as u16 + 2;
                        let r = Inflight {
                            rid,
                            sent: now,
                            json,
                            edits,
                        };
                        {
                            let mut sent = shared.sent.write().unwrap();
                            sent.by_commit.insert(commit_id, now);
                            sent.by_subject.insert(res.get_subject().to_string(), now);
                        }
                        send_registered(&ws, shared, &r).await;
                        shared.commits_sent.fetch_add(1, Relaxed);
                        inflight = Some(r);
                    }
                    Err(e) => {
                        record_error(shared, format!("sign: {}", classify(&e)), &e);
                        // The edits stay pending; try again at the next chance.
                        pending = edits;
                        next_send_at = now + Duration::from_millis(500);
                    }
                }
            }
        }

        if closing && inflight.is_none() && resend.is_none() && pending.is_empty() {
            break;
        }

        let idle_wake = if inflight.is_none() && (resend.is_some() || !pending.is_empty()) {
            next_send_at.max(Instant::now())
        } else {
            flush_deadline
        };
        let ack_deadline = inflight.as_ref().map(|r| r.sent + Duration::from_secs(30));

        tokio::select! {
            _ = tick.tick(), if !closing => {
                if opts.edit_model {
                    n += 1;
                    if let Err(e) = edit(&mut res, i, n) {
                        record_error(shared, format!("edit: {}", classify(&e)), &e);
                        continue;
                    }
                    shared.edits_made.fetch_add(1, Relaxed);
                    pending.push(Instant::now());
                } else if inflight.is_some() || resend.is_some() || Instant::now() < next_send_at {
                    shared.skipped_ticks.fetch_add(1, Relaxed);
                } else {
                    n += 1;
                    if let Err(e) = edit(&mut res, i, n) {
                        record_error(shared, format!("edit: {}", classify(&e)), &e);
                        continue;
                    }
                    shared.edits_made.fetch_add(1, Relaxed);
                    pending.push(Instant::now());
                }
            }
            _ = tokio::time::sleep_until(idle_wake.into()) => {}
            _ = async {
                match ack_deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                record_error(shared, "commit_ack_timeout".into(), "no COMMIT_OK in 30s");
                break;
            }
            msg = rx.recv() => {
                let Some(cur) = inflight.as_ref() else {
                    if matches!(msg, Err(RecvError::Closed)) {
                        break;
                    }
                    continue;
                };
                match msg {
                    Ok(WsMessage::CommitOk { request_id, pace_ms, .. }) if request_id == cur.rid => {
                        let r = inflight.take().unwrap();
                        let now = Instant::now();
                        shared.ack_ms.lock().unwrap().push(ms(now.duration_since(r.sent)));
                        shared.commits_ok.fetch_add(1, Relaxed);
                        let in_window = now <= end;
                        if in_window {
                            shared.commits_ok_in_window.fetch_add(1, Relaxed);
                        }
                        shared.edits_acked.fetch_add(r.edits.len() as u64, Relaxed);
                        if in_window {
                            shared.edits_acked_in_window.fetch_add(r.edits.len() as u64, Relaxed);
                        }
                        shared.batch_sizes.lock().unwrap().push(r.edits.len() as f64);
                        {
                            let mut lat = shared.edit_latency_ms.lock().unwrap();
                            lat.extend(r.edits.iter().map(|t| ms(now.duration_since(*t))));
                        }
                        if let Some(p) = pace_ms {
                            shared.pace_ms.lock().unwrap().push(p as f64);
                            pace = Duration::from_millis(u64::from(p));
                        }
                        // At most one commit per max(debounce, pace) since the last one.
                        next_send_at = r.sent + pace.max(opts.debounce);
                    }
                    Ok(WsMessage::Error { request_id, code, message }) if request_id == cur.rid => {
                        let r = inflight.take().unwrap();
                        if code == protocol::error_code::BUSY {
                            shared.busy.fetch_add(1, Relaxed);
                            let wait = protocol::retry_after_ms_from_message(&message).unwrap_or(1000);
                            let jitter = rand::random::<f64>() * (wait as f64 * 0.25).min(1000.0);
                            next_send_at =
                                Instant::now() + Duration::from_millis(wait + jitter as u64);
                            pace = pace.max(Duration::from_millis(wait));
                            resend = Some(r);
                        } else {
                            record_error(shared, format!("commit_error code={code}"), &message);
                            // The commit is lost and the chain is broken: stop.
                            break;
                        }
                    }
                    Err(RecvError::Closed) => {
                        record_error(shared, "socket_closed".into(), "");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let unsent = pending.len() as u64
        + resend.map_or(0, |r| r.edits.len() as u64)
        + inflight.map_or(0, |r| r.edits.len() as u64);
    shared.edits_unsent.fetch_add(unsent, Relaxed);
}

async fn send_registered(ws: &WsClient, shared: &Shared, r: &Inflight) {
    if let Err(e) = ws
        .send_binary(protocol::encode_commit(r.rid, &r.json))
        .await
    {
        record_error(shared, format!("send: {}", classify(&s(e))), "send failed");
    }
}

fn edit(res: &mut Resource, writer: usize, n: u64) -> Result<(), String> {
    res.set_unsafe(
        urls::DESCRIPTION.into(),
        Value::String(format!("writer {writer} edit {n}")),
    )
    .map(|_| ())
    .map_err(s)
}
