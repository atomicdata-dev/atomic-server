//! Integration tests for the write-load signal: `pace_ms` on `COMMIT_OK`
//! (only for a client that advertises `commit-pace`), `BUSY` above the hard
//! limit, `503` + `Retry-After` over HTTP, and the rate limiter mapped to
//! `BUSY` on the WebSocket.
//!
//! The load is created with tiny limits instead of a real flood:
//! `--commit-soft-limit 0` makes any commit in flight count as pressure, and
//! `--commit-hard-limit 1` refuses a second commit while one is in flight.
//!
//! Run: cargo test -p atomic-server --test it commit_pacing

use atomic_lib::{
    agents::Agent,
    client::{
        commit_to_wire_json,
        connected::Client,
        ws::{WsClient, WsMessage},
    },
    errors::AtomicResult,
    sync::protocol::{self, error_code},
};
use std::time::Duration;

use crate::common::{start_server_with_args, wait_for_server};

/// A signed genesis commit for a new classless resource under `parent`.
async fn genesis_commit_json(
    client: &Client,
    signer: &Agent,
    parent: &str,
    name: &str,
) -> AtomicResult<String> {
    let mut builder = atomic_lib::commit::CommitBuilder::new("placeholder".into());
    builder.set(
        atomic_lib::urls::NAME.into(),
        atomic_lib::Value::String(name.into()),
    );
    builder.set(
        atomic_lib::urls::PARENT.into(),
        atomic_lib::Value::AtomicUrl(parent.into()),
    );
    let commit = atomic_lib::commit::Commit::create_did(builder, signer, client.store()).await?;
    commit_to_wire_json(&commit, client.store()).await
}

struct Setup {
    client: Client,
    agent: Agent,
    drive: String,
    ws_url: String,
    http_url: String,
}

async fn setup(name: &str, args: &[&str]) -> AtomicResult<Setup> {
    let port = start_server_with_args(name, args);
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{port}");
    let client = Client::new(&server_url).await?;
    let agent = client.new_agent("Alice").await?;
    let drive = client.new_drive(&agent, "Drive").await?;
    Ok(Setup {
        client,
        agent,
        drive,
        ws_url: format!("ws://localhost:{port}/ws"),
        http_url: format!("{server_url}/commit"),
    })
}

async fn ws_with_caps(s: &Setup, caps: &[&str]) -> AtomicResult<WsClient> {
    let ws = WsClient::connect(&s.ws_url).await?;
    ws.authenticate(&s.agent).await?;
    // A later HELLO replaces the capabilities the connection listed on open.
    ws.send_binary(protocol::encode_hello_with_caps("test", caps))
        .await?;
    Ok(ws)
}

/// What one COMMIT frame was answered with.
#[derive(Debug)]
enum Answer {
    Ok(WsMessage),
    Err { code: u16, message: String },
}

/// Send `n` genesis commits back to back, without waiting for acks, and
/// collect the answer to each.
async fn pipeline_commits(s: &Setup, ws: &WsClient, n: u16) -> AtomicResult<Vec<Answer>> {
    let mut rx = ws.subscribe();
    for i in 0..n {
        let json = genesis_commit_json(&s.client, &s.agent, &s.drive, &format!("r{i}")).await?;
        ws.send_binary(protocol::encode_commit(i + 1, &json))
            .await?;
    }
    let mut answers = Vec::new();
    let collected = tokio::time::timeout(Duration::from_secs(30), async {
        while answers.len() < n as usize {
            match rx.recv().await {
                Ok(m @ WsMessage::CommitOk { .. }) => answers.push(Answer::Ok(m)),
                Ok(WsMessage::Error { code, message, .. }) => {
                    answers.push(Answer::Err { code, message })
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(collected.is_ok(), "timed out; got {answers:?}");
    Ok(answers)
}

#[tokio::test]
async fn busy_above_the_hard_limit_before_any_work() -> AtomicResult<()> {
    let s = setup(
        "pacing_busy",
        &["--commit-soft-limit", "0", "--commit-hard-limit", "1"],
    )
    .await?;
    let ws = ws_with_caps(&s, &["commit-ok-slim", "commit-pace"]).await?;
    let answers = pipeline_commits(&s, &ws, 30).await?;

    let ok = answers
        .iter()
        .filter(|a| matches!(a, Answer::Ok(_)))
        .count();
    let busy: Vec<&String> = answers
        .iter()
        .filter_map(|a| match a {
            Answer::Err { code, message } if *code == error_code::BUSY => Some(message),
            _ => None,
        })
        .collect();
    assert!(
        ok >= 1,
        "at least the first commit is admitted: {answers:?}"
    );
    assert!(
        !busy.is_empty(),
        "no BUSY above the hard limit: {answers:?}"
    );
    assert_eq!(
        ok + busy.len(),
        answers.len(),
        "every answer is COMMIT_OK or BUSY: {answers:?}"
    );
    for message in busy {
        let ms = protocol::retry_after_ms_from_message(message)
            .unwrap_or_else(|| panic!("no retry_after_ms in {message:?}"));
        // Floor 250 ms, cap 10 s, jitter +-50% of a base in [250, 10000].
        assert!((250..=15_000).contains(&ms), "{message}");
    }

    // The refusals left nothing in flight: once the burst is over a commit
    // is admitted again.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let json = genesis_commit_json(&s.client, &s.agent, &s.drive, "after").await?;
    ws.post_commit(999, &json).await?;
    Ok(())
}

#[tokio::test]
async fn pace_ms_rides_on_commit_ok_only_for_a_client_that_advertises_it() -> AtomicResult<()> {
    // One commit alone counts as pressure (soft 0): pace = 10_000 * 1 / 10.
    let s = setup(
        "pacing_caps",
        &["--commit-soft-limit", "0", "--commit-hard-limit", "10"],
    )
    .await?;

    // Advertises commit-pace: a paced slim ack.
    let ws = ws_with_caps(&s, &["commit-ok-slim", "commit-pace"]).await?;
    let answers = pipeline_commits(&s, &ws, 1).await?;
    match &answers[0] {
        Answer::Ok(WsMessage::CommitOk {
            pace_ms,
            commit_json,
            ..
        }) => {
            assert_eq!(*pace_ms, Some(1000));
            assert!(commit_json.is_none(), "paced acks are slim");
        }
        other => panic!("{other:?}"),
    }

    // Slim only: byte-identical to before, no pace.
    let ws = ws_with_caps(&s, &["commit-ok-slim"]).await?;
    let answers = pipeline_commits(&s, &ws, 1).await?;
    match &answers[0] {
        Answer::Ok(WsMessage::CommitOk {
            pace_ms,
            commit_json,
            ..
        }) => {
            assert_eq!(*pace_ms, None);
            assert!(commit_json.is_none());
        }
        other => panic!("{other:?}"),
    }

    // Advertises commit-pace without commit-ok-slim: the full legacy ack,
    // no pace (the hint only rides on the slim form).
    let ws = ws_with_caps(&s, &["commit-pace"]).await?;
    let answers = pipeline_commits(&s, &ws, 1).await?;
    match &answers[0] {
        Answer::Ok(WsMessage::CommitOk {
            pace_ms,
            commit_json,
            ..
        }) => {
            assert_eq!(*pace_ms, None);
            assert!(commit_json.is_some());
        }
        other => panic!("{other:?}"),
    }

    // A client that sent no HELLO at all.
    let ws = ws_with_caps(&s, &[]).await?;
    let answers = pipeline_commits(&s, &ws, 1).await?;
    assert!(matches!(
        &answers[0],
        Answer::Ok(WsMessage::CommitOk {
            pace_ms: None,
            commit_json: Some(_),
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn pace_is_zero_when_idle() -> AtomicResult<()> {
    let s = setup("pacing_idle", &[]).await?;
    let ws = ws_with_caps(&s, &["commit-ok-slim", "commit-pace"]).await?;
    let answers = pipeline_commits(&s, &ws, 1).await?;
    assert!(matches!(
        &answers[0],
        Answer::Ok(WsMessage::CommitOk {
            pace_ms: Some(0),
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn ws_rate_limit_is_busy_with_the_same_retry_semantics() -> AtomicResult<()> {
    // Two signed writes per minute: the drive was the first.
    let s = setup("pacing_rate", &["--write-rate-limit", "2"]).await?;
    let ws = ws_with_caps(&s, &["commit-ok-slim", "commit-pace"]).await?;

    let first = pipeline_commits(&s, &ws, 1).await?;
    assert!(matches!(&first[0], Answer::Ok(_)), "{first:?}");

    let second = pipeline_commits(&s, &ws, 1).await?;
    match &second[0] {
        Answer::Err { code, message } => {
            assert_eq!(*code, error_code::BUSY, "{message}");
            assert!(message.contains("Too many writes"), "{message}");
            let ms = protocol::retry_after_ms_from_message(message).unwrap();
            assert!(
                ms >= 1000 && ms.is_multiple_of(1000),
                "whole seconds: {message}"
            );
        }
        other => panic!("expected BUSY, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn http_commit_reports_pace_and_sheds_with_503_and_retry_after() -> AtomicResult<()> {
    let s = setup(
        "pacing_http",
        &["--commit-soft-limit", "0", "--commit-hard-limit", "1"],
    )
    .await?;
    let http = reqwest::Client::new();

    // Alone, a commit is admitted and carries the soft signal: one in flight
    // of a hard limit of 1 is the top of the range.
    let json = genesis_commit_json(&s.client, &s.agent, &s.drive, "alone").await?;
    let response = http
        .post(&s.http_url)
        .header("Content-Type", "application/json")
        .body(json)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers()["x-atomic-pace-ms"].to_str().unwrap(),
        "10000"
    );

    // A burst: some are admitted, the rest refused up front.
    let mut tasks = Vec::new();
    for i in 0..30 {
        let json = genesis_commit_json(&s.client, &s.agent, &s.drive, &format!("b{i}")).await?;
        let (http, url) = (http.clone(), s.http_url.clone());
        tasks.push(tokio::spawn(async move {
            let r = http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(json)
                .send()
                .await
                .unwrap();
            let retry_after = r
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_string());
            let retry_ms = r
                .headers()
                .get("x-atomic-retry-after-ms")
                .map(|v| v.to_str().unwrap().to_string());
            (r.status().as_u16(), retry_after, retry_ms)
        }));
    }
    let mut ok = 0;
    let mut shed = 0;
    for task in tasks {
        let (status, retry_after, retry_ms) = task.await.unwrap();
        match status {
            200 => ok += 1,
            503 => {
                shed += 1;
                let secs: u64 = retry_after.expect("Retry-After on 503").parse().unwrap();
                let ms: u64 = retry_ms.expect("retry ms header").parse().unwrap();
                assert!(secs >= 1 && secs == ms.div_ceil(1000), "{secs} vs {ms}");
            }
            other => panic!("unexpected status {other}"),
        }
    }
    assert!(ok >= 1, "ok {ok}, shed {shed}");
    assert!(shed >= 1, "ok {ok}, shed {shed}");
    Ok(())
}

#[tokio::test]
async fn zero_hard_limit_disables_pacing_and_shedding() -> AtomicResult<()> {
    let s = setup("pacing_off", &["--commit-hard-limit", "0"]).await?;
    let ws = ws_with_caps(&s, &["commit-ok-slim", "commit-pace"]).await?;
    let answers = pipeline_commits(&s, &ws, 20).await?;
    for a in &answers {
        assert!(
            matches!(
                a,
                Answer::Ok(WsMessage::CommitOk {
                    pace_ms: Some(0),
                    ..
                })
            ),
            "{a:?}"
        );
    }
    Ok(())
}
