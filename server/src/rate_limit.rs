//! Token-bucket rate limiting for the write endpoints.
//!
//! A reachable node used to accept an unbounded stream of `/commit`,
//! `/upload`, `/blob` and `/iroh-sync` requests from anyone
//! (`planning/security-audit-2026-09.md` section D,
//! `planning/foss-public-host-mode.md` Phase 3). Admission policies decide
//! *whether* an agent may write a drive; this decides *how fast* anyone may
//! try. Two buckets sizes: one for requests that carry a signed agent, keyed
//! by that agent, and a much smaller one for requests without one, keyed by
//! the socket peer address. "Signed" means verified: a key is only ever an
//! identity the request has proven (an auth header, a WS `AUTH`, a commit
//! signature that checks out), never one it merely names, or a request could
//! spend someone else's budget. Every bucket refills continuously at
//! `per_minute / 60` tokens per second and holds at most `per_minute`
//! tokens, so a burst up to the minute budget is fine and a sustained flood
//! is not.
//!
//! The limiter is in-process and per node. Clients that hit it get `429`
//! with a `Retry-After`; the browser outbox treats that like any other
//! transient failure and backs off.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Buckets that have been full and untouched for this long are dropped on
/// the next prune, so an agent that wrote once does not pin memory forever.
const PRUNE_EVERY: Duration = Duration::from_secs(300);

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// One write was refused. `retry_after_secs` is when the next token lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited {
    pub retry_after_secs: u64,
}

const MESSAGE_PREFIX: &str = "Too many writes; retry after ";

impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `retry_after_ms=` tail is the machine-readable form shared with
        // `BUSY` (see `atomic_lib::sync::protocol::retry_after_ms_from_message`).
        write!(
            f,
            "{MESSAGE_PREFIX}{} seconds (retry_after_ms={})",
            self.retry_after_secs,
            self.retry_after_secs * 1000
        )
    }
}

/// Recover the `Retry-After` value from a message `RateLimited` produced, so
/// the HTTP error renderer can set the header without a new error field.
pub fn retry_after_from_message(message: &str) -> Option<u64> {
    let rest = message.strip_prefix(MESSAGE_PREFIX)?;
    rest.split(' ').next()?.parse().ok()
}

pub struct WriteRateLimiter {
    agent_per_minute: u32,
    anonymous_per_minute: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
    last_prune: Mutex<Instant>,
}

impl WriteRateLimiter {
    /// `0` for either budget disables that class of limiting.
    pub fn new(agent_per_minute: u32, anonymous_per_minute: u32) -> Self {
        Self {
            agent_per_minute,
            anonymous_per_minute,
            buckets: Mutex::new(HashMap::new()),
            last_prune: Mutex::new(Instant::now()),
        }
    }

    /// A limiter that never refuses. For embedders and tests.
    pub fn disabled() -> Self {
        Self::new(0, 0)
    }

    /// Spend one token for `key`. `anonymous` selects the smaller budget and
    /// namespaces the key so a peer address can never share a bucket with an
    /// agent subject.
    pub fn check(&self, key: &str, anonymous: bool) -> Result<(), RateLimited> {
        self.check_at(key, anonymous, Instant::now())
    }

    fn check_at(&self, key: &str, anonymous: bool, now: Instant) -> Result<(), RateLimited> {
        let per_minute = if anonymous {
            self.anonymous_per_minute
        } else {
            self.agent_per_minute
        };
        if per_minute == 0 {
            return Ok(());
        }
        let capacity = f64::from(per_minute);
        let per_second = capacity / 60.0;
        let namespaced = if anonymous {
            format!("anon:{key}")
        } else {
            // One bucket per agent, not per spelling of its subject: a signer
            // could otherwise double its budget by alternating `atomic:` and
            // `did:ad:`.
            format!(
                "agent:{}",
                atomic_lib::identifiers::canonicalize_scheme(key)
            )
        };

        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        self.maybe_prune(&mut buckets, now);
        let bucket = buckets.entry(namespaced).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let wait = (1.0 - bucket.tokens) / per_second;
        Err(RateLimited {
            retry_after_secs: wait.ceil().max(1.0) as u64,
        })
    }

    fn maybe_prune(&self, buckets: &mut HashMap<String, Bucket>, now: Instant) {
        let mut last = self.last_prune.lock().unwrap_or_else(|e| e.into_inner());
        if now.saturating_duration_since(*last) < PRUNE_EVERY {
            return;
        }
        *last = now;
        let agent_cap = f64::from(self.agent_per_minute);
        let anon_cap = f64::from(self.anonymous_per_minute);
        buckets.retain(|key, bucket| {
            let cap = if key.starts_with("anon:") {
                anon_cap
            } else {
                agent_cap
            };
            let per_second = cap / 60.0;
            let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
            // Keep only buckets that are still short of full: those are the
            // ones whose history matters.
            bucket.tokens + elapsed * per_second < cap
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_spellings_of_an_agent_share_one_bucket() {
        let limiter = WriteRateLimiter::new(2, 0);
        let t0 = Instant::now();
        assert_eq!(limiter.check_at("did:ad:agent:a", false, t0), Ok(()));
        assert_eq!(limiter.check_at("atomic:agent:a", false, t0), Ok(()));
        assert!(limiter.check_at("did:ad:agent:a", false, t0).is_err());
        assert!(limiter.check_at("atomic:agent:a", false, t0).is_err());
    }

    #[test]
    fn burst_up_to_the_budget_then_refuse_with_retry_after() {
        let limiter = WriteRateLimiter::new(3, 0);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.check_at("did:ad:agent:a", false, t0), Ok(()));
        }
        let refused = limiter.check_at("did:ad:agent:a", false, t0).unwrap_err();
        // 3 per minute is one token every 20 seconds.
        assert_eq!(refused.retry_after_secs, 20);
        // Another agent has its own bucket.
        assert_eq!(limiter.check_at("did:ad:agent:b", false, t0), Ok(()));
        // After the refill interval one more token is available.
        let later = t0 + Duration::from_secs(20);
        assert_eq!(limiter.check_at("did:ad:agent:a", false, later), Ok(()));
        assert!(limiter.check_at("did:ad:agent:a", false, later).is_err());
    }

    #[test]
    fn anonymous_budget_is_separate_and_namespaced() {
        let limiter = WriteRateLimiter::new(100, 1);
        let t0 = Instant::now();
        assert_eq!(limiter.check_at("10.0.0.1", true, t0), Ok(()));
        assert!(limiter.check_at("10.0.0.1", true, t0).is_err());
        // The same string as an agent key is a different bucket.
        assert_eq!(limiter.check_at("10.0.0.1", false, t0), Ok(()));
    }

    #[test]
    fn zero_disables_that_class() {
        let limiter = WriteRateLimiter::new(0, 1);
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert_eq!(limiter.check_at("x", false, t0), Ok(()));
        }
        assert_eq!(limiter.check_at("x", true, t0), Ok(()));
        assert!(limiter.check_at("x", true, t0).is_err());
        assert!(WriteRateLimiter::disabled().check("x", true).is_ok());
    }

    #[test]
    fn full_idle_buckets_are_pruned() {
        let limiter = WriteRateLimiter::new(60, 60);
        let t0 = Instant::now();
        limiter.check_at("a", false, t0).unwrap();
        limiter.check_at("b", true, t0).unwrap();
        // "c" is drained and stays short of full for a long time.
        for _ in 0..60 {
            limiter.check_at("c", false, t0).unwrap();
        }
        let later = t0 + PRUNE_EVERY + Duration::from_secs(1);
        // Any check after the prune interval triggers the prune; "c" refilled
        // fully in 60 seconds, so only the bucket touched now survives.
        limiter.check_at("d", false, later).unwrap();
        let keys: Vec<String> = limiter.buckets.lock().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["agent:d".to_string()]);
    }

    #[test]
    fn retry_after_round_trips_through_the_message() {
        let limited = RateLimited {
            retry_after_secs: 7,
        };
        assert_eq!(retry_after_from_message(&limited.to_string()), Some(7));
        assert_eq!(retry_after_from_message("Unauthorized"), None);
    }
}
