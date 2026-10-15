//! Shared helpers: percentiles, error bucketing, drive setup, client connect.

use atomic_lib::{
    agents::Agent, client::connected::Client, client::ws::WsClient, urls, Resource, Value,
};
use serde_json::{json, Value as Json};
use std::{
    collections::BTreeMap,
    fmt::Display,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub type Res<T> = Result<T, String>;

pub fn s<E: Display>(e: E) -> String {
    e.to_string()
}

/// `http://host:port` -> `ws://host:port/ws`
pub fn ws_url(server: &str) -> String {
    let base = server.trim_end_matches('/');
    let base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{base}/ws")
}

pub fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Count, min, mean, p50/p95/p99, max of a sample. Values keep the caller's unit.
pub fn summarize(mut v: Vec<f64>) -> Json {
    if v.is_empty() {
        return json!({ "count": 0 });
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let pct = |p: f64| v[(((p * n as f64).ceil() as usize).max(1) - 1).min(n - 1)];
    let round = |x: f64| (x * 100.0).round() / 100.0;
    json!({
        "count": n,
        "min": round(v[0]),
        "mean": round(v.iter().sum::<f64>() / n as f64),
        "p50": round(pct(0.50)),
        "p95": round(pct(0.95)),
        "p99": round(pct(0.99)),
        "max": round(v[n - 1]),
    })
}

/// One-line rendering of `summarize` output for the human summary.
pub fn line(j: &Json) -> String {
    if j["count"].as_u64().unwrap_or(0) == 0 {
        return "no samples".into();
    }
    format!(
        "n={} p50={}ms p95={}ms p99={}ms max={}ms",
        j["count"], j["p50"], j["p95"], j["p99"], j["max"]
    )
}

/// Failure counts keyed by a short, bucketed reason.
#[derive(Default)]
pub struct Errors(Mutex<BTreeMap<String, u64>>);

impl Errors {
    pub fn add(&self, reason: impl Into<String>) {
        *self.0.lock().unwrap().entry(reason.into()).or_default() += 1;
    }
    pub fn total(&self) -> u64 {
        self.0.lock().unwrap().values().sum()
    }
    pub fn to_json(&self) -> Json {
        json!(*self.0.lock().unwrap())
    }
}

/// Bucket an error string so thousands of near-identical failures collapse.
pub fn classify(e: &str) -> String {
    let lower = e.to_lowercase();
    let reason = if lower.contains("timed out") || lower.contains("timeout") {
        "timeout".to_string()
    } else if lower.contains("too many open files") {
        "client_fd_limit (raise ulimit -n)".to_string()
    } else if lower.contains("connection refused") {
        "connection_refused".to_string()
    } else if lower.contains("connection reset") {
        "connection_reset".to_string()
    } else if lower.contains("429") {
        "http_429".to_string()
    } else if lower.contains("503") {
        "http_503".to_string()
    } else {
        e.chars().take(90).collect()
    };
    reason
}

/// Connect, AUTH, and optionally SUB to a drive. Returns the client plus
/// (connect_ms, connect_plus_auth_ms).
pub async fn connect_client(
    ws_url: &str,
    agent: &Agent,
    drive: Option<&str>,
) -> Res<(WsClient, f64, f64)> {
    let t = Instant::now();
    let ws = tokio::time::timeout(Duration::from_secs(20), WsClient::connect(ws_url))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(s)?;
    let connected = ms(t.elapsed());
    ws.authenticate(agent).await.map_err(s)?;
    let authed = ms(t.elapsed());
    if let Some(d) = drive {
        ws.subscribe_drive(d).await.map_err(s)?;
    }
    Ok((ws, connected, authed))
}

pub fn new_agent(name: &str) -> Res<Agent> {
    Agent::new(Some(name)).map_err(s)
}

/// Create a setup agent and `k` public-read drives over HTTP. The setup agent
/// and every agent in `extra_writers` may write to each drive. Returns the
/// client (whose in-memory store signs commits for the writers) and the drives.
pub async fn setup_drives(
    server: &str,
    k: usize,
    extra_writers: &[Agent],
) -> Res<(Arc<Client>, Vec<String>)> {
    let client = Client::new(server).await.map_err(s)?;
    let setup = client.new_agent("loadtest-setup").await.map_err(s)?;
    let mut writers: Vec<String> = vec![setup.subject.to_string()];
    writers.extend(extra_writers.iter().map(|a| a.subject.to_string()));

    let mut drives = Vec::new();
    for i in 0..k.max(1) {
        let mut drive = Resource::new("did:ad:placeholder".into());
        drive
            .set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![urls::DRIVE.into()]),
            )
            .map_err(s)?;
        drive.set_name(&format!("loadtest-drive-{i}")).map_err(s)?;
        drive
            .set_unsafe(
                urls::WRITE.into(),
                Value::ResourceArray(writers.iter().map(|w| w.clone().into()).collect()),
            )
            .map_err(s)?;
        drive
            .set_unsafe(
                urls::READ.into(),
                Value::ResourceArray(vec![urls::PUBLIC_AGENT.into()]),
            )
            .map_err(s)?;
        let subject = drive
            .save_remote(client.store())
            .await
            .map_err(|e| format!("creating drive {i} failed: {e}"))?;
        drives.push(subject);
    }
    Ok((Arc::new(client), drives))
}

/// Like `line`, for samples that are not milliseconds (counts, `pace_ms`
/// values, which already say what they are in the label).
pub fn line_plain(j: &Json) -> String {
    if j["count"].as_u64().unwrap_or(0) == 0 {
        return "no samples".into();
    }
    format!(
        "n={} p50={} p95={} p99={} max={}",
        j["count"], j["p50"], j["p95"], j["p99"], j["max"]
    )
}
