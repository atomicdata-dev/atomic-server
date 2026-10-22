//! `dial_all`: the known peers are dialled at once, each bounded on its own.

use super::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn dials_every_peer_at_once_and_bounds_each() {
    let ids: Vec<String> = ["ok", "slow", "fails"].iter().map(|s| s.to_string()).collect();
    let started = Instant::now();
    let results = dial_all(&ids, Duration::from_millis(300), |id| async move {
        match id.as_str() {
            "ok" => Ok(3u64),
            "slow" => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(1)
            }
            _ => Err("refused".to_string()),
        }
    })
    .await;
    // One slow peer costs its own timeout, not the sum of everyone's.
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(results.len(), 3);
    assert_eq!(results[0], ("ok".to_string(), Ok(3)));
    assert!(matches!(&results[1], (id, Err(e)) if id == "slow" && e.contains("timed out")));
    assert_eq!(results[2], ("fails".to_string(), Err("refused".to_string())));
}

#[tokio::test]
async fn many_dead_peers_take_one_timeout_not_n() {
    let ids: Vec<String> = (0..6).map(|i| format!("gone{i}")).collect();
    let started = Instant::now();
    let results = dial_all(&ids, Duration::from_millis(200), |_| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok::<u64, String>(0)
    })
    .await;
    assert!(results.iter().all(|(_, r)| r.is_err()));
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
}
