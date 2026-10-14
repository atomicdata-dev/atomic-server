//! Write-load tracking: tells clients to commit less often when the node is
//! busy, and refuses commits outright when it is overloaded.
//!
//! The server's cost is per commit, not per edit: every commit rebuilds the
//! resource's Loro document, rewrites its full snapshot and takes one write
//! transaction on redb's single writer. A commit carrying fifty keystrokes
//! costs about what a commit carrying one does. Clients are local first (the
//! edit is already saved on the device, peers see typing live over the
//! ephemeral channel), so when the node is busy they can send fewer, fatter
//! commits at no visible cost. This module is how the node says so.
//!
//! One [`WriteLoad`] is shared by `POST /commit` and the WebSocket `COMMIT`
//! frame. A commit takes a [`WriteGuard`] before any work (signature check,
//! Loro merge, redb write) and holds it until it is answered, so
//! `in_flight` is the number of commits the node is working on or queued
//! behind the writer. By Little's law that equals commit rate times latency,
//! which makes it a direct measure of how far behind the node is.
//!
//! - `in_flight <= soft_limit`: no pressure, `pace_ms = 0`.
//! - between the limits: `pace_ms` rises linearly from 0 to [`MAX_PACE_MS`],
//!   see [`pace_for`]. This is the soft signal; clients stretch their commit
//!   interval and nothing fails.
//! - `in_flight > hard_limit`: [`WriteLoad::try_begin`] refuses with
//!   [`Busy`] before doing any work. This is the hard signal; the client
//!   keeps the edit in its outbox and retries after `retry_after_ms`.
//!
//! The retry delay is the time the node needs to drain what is queued:
//! `in_flight * ewma(commit service time)`, clamped to
//! `[MIN_RETRY_MS, MAX_PACE_MS]` and jittered by +-50% so refused clients do
//! not return in one wave.

use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering::Relaxed},
    Arc,
};
use std::time::Instant;

/// Response header of a successful `POST /commit`: the soft signal in ms.
pub const PACE_HEADER: &str = "X-Atomic-Pace-Ms";
/// Response header of a `503`: the jittered retry delay in ms (the standard
/// `Retry-After` carries it rounded up to whole seconds).
pub const RETRY_AFTER_MS_HEADER: &str = "X-Atomic-Retry-After-Ms";

/// Upper bound of both the pace hint and the retry delay.
pub const MAX_PACE_MS: u32 = 10_000;
/// Lower bound of the retry delay: never tell a client to come right back.
pub const MIN_RETRY_MS: u64 = 250;

/// Defaults, derived from `stresstest/results-2026-10-14.md`: one 4-core node
/// saturates near 200 commits/s. At 100 commits/s ack latency was ~330 ms,
/// so ~33 commits were in flight (Little's law): that is where latency
/// starts to be noticeable, hence a soft limit of 32. At 400 closed-loop
/// writers ~320 were in flight with a 1.5 s ack p50; refusing above 256
/// keeps ack latency near 1 s instead of letting the queue grow.
pub const DEFAULT_SOFT_LIMIT: u32 = 32;
pub const DEFAULT_HARD_LIMIT: u32 = 256;

/// A refused commit: the node is over its hard limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy {
    pub retry_after_ms: u64,
}

impl Busy {
    /// Message text; the error code classifier and the clients parse the
    /// `retry_after_ms=` part.
    pub fn message(&self) -> String {
        atomic_lib::sync::protocol::busy_message(self.retry_after_ms)
    }
}

/// `pace_ms` for `in_flight` commits: 0 up to `soft`, then linear to
/// [`MAX_PACE_MS`] at `hard`. `hard == 0` disables load tracking.
pub fn pace_for(in_flight: u32, soft: u32, hard: u32) -> u32 {
    if hard == 0 || in_flight <= soft {
        return 0;
    }
    let span = u64::from(hard.saturating_sub(soft).max(1));
    let over = u64::from(in_flight - soft);
    ((u64::from(MAX_PACE_MS) * over) / span).min(u64::from(MAX_PACE_MS)) as u32
}

/// Retry delay for a refusal: queue drain time, clamped, then scaled by
/// `jitter` in `[0.5, 1.5]`.
pub fn retry_after_for(in_flight: u32, ewma_service_us: u64, jitter: f64) -> u64 {
    let drain_ms = u64::from(in_flight) * ewma_service_us / 1000;
    let base = drain_ms.clamp(MIN_RETRY_MS, u64::from(MAX_PACE_MS));
    ((base as f64 * jitter.clamp(0.5, 1.5)) as u64).max(MIN_RETRY_MS)
}

pub struct WriteLoad {
    soft: u32,
    hard: u32,
    in_flight: AtomicU32,
    /// Moving average (alpha 1/8) of the time a commit holds a guard, in us.
    ewma_us: AtomicU64,
    refused: AtomicU64,
}

impl WriteLoad {
    /// `hard == 0` disables the tracker: nothing is ever refused, pace is 0.
    /// A `soft` at or above `hard` is clamped just below it.
    pub fn new(soft: u32, hard: u32) -> Arc<Self> {
        let soft = if hard > 0 { soft.min(hard - 1) } else { soft };
        Arc::new(Self {
            soft,
            hard,
            in_flight: AtomicU32::new(0),
            ewma_us: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        })
    }

    pub fn disabled() -> Arc<Self> {
        Self::new(0, 0)
    }

    /// Admit a commit, or refuse it when more than `hard` are in flight.
    /// Call before any expensive work and keep the guard until the commit is
    /// answered.
    pub fn try_begin(self: &Arc<Self>) -> Result<WriteGuard, Busy> {
        let n = self.in_flight.fetch_add(1, Relaxed) + 1;
        if self.hard > 0 && n > self.hard {
            self.in_flight.fetch_sub(1, Relaxed);
            self.refused.fetch_add(1, Relaxed);
            let jitter = 0.5 + rand::random::<f64>();
            return Err(Busy {
                retry_after_ms: retry_after_for(n, self.ewma_us.load(Relaxed), jitter),
            });
        }
        Ok(WriteGuard {
            load: self.clone(),
            started: Instant::now(),
        })
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Relaxed)
    }

    pub fn refused_total(&self) -> u64 {
        self.refused.load(Relaxed)
    }

    pub fn ewma_service_us(&self) -> u64 {
        self.ewma_us.load(Relaxed)
    }

    /// The current soft signal.
    pub fn pace_ms(&self) -> u32 {
        pace_for(self.in_flight(), self.soft, self.hard)
    }
}

/// One commit being worked on. Dropping it frees the slot and feeds the
/// service-time average.
pub struct WriteGuard {
    load: Arc<WriteLoad>,
    started: Instant,
}

impl WriteGuard {
    /// The pace hint to send with this commit's acknowledgement.
    pub fn pace_ms(&self) -> u32 {
        self.load.pace_ms()
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        let us = self.started.elapsed().as_micros() as u64;
        let old = self.load.ewma_us.load(Relaxed);
        let new = if old == 0 { us } else { old - old / 8 + us / 8 };
        self.load.ewma_us.store(new, Relaxed);
        self.load.in_flight.fetch_sub(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pace_is_zero_below_soft_and_max_at_hard() {
        assert_eq!(pace_for(0, 32, 256), 0);
        assert_eq!(pace_for(32, 32, 256), 0);
        assert_eq!(pace_for(33, 32, 256), 44); // 10_000 / 224
        assert_eq!(pace_for(144, 32, 256), 5_000);
        assert_eq!(pace_for(256, 32, 256), MAX_PACE_MS);
        assert_eq!(pace_for(10_000, 32, 256), MAX_PACE_MS);
    }

    #[test]
    fn pace_is_monotonic() {
        let mut last = 0;
        for n in 0..400 {
            let p = pace_for(n, 32, 256);
            assert!(p >= last);
            last = p;
        }
    }

    #[test]
    fn disabled_when_hard_is_zero() {
        assert_eq!(pace_for(1_000_000, 0, 0), 0);
        let load = WriteLoad::disabled();
        let guards: Vec<_> = (0..1000).map(|_| load.try_begin().unwrap()).collect();
        assert_eq!(load.pace_ms(), 0);
        drop(guards);
        assert_eq!(load.in_flight(), 0);
    }

    #[test]
    fn retry_after_tracks_queue_drain_time_with_jitter() {
        // 100 queued at 10 ms each drain in 1 s.
        assert_eq!(retry_after_for(100, 10_000, 1.0), 1_000);
        assert_eq!(retry_after_for(100, 10_000, 0.5), 500);
        assert_eq!(retry_after_for(100, 10_000, 1.5), 1_500);
        // Floor and cap of the base.
        assert_eq!(retry_after_for(1, 1, 1.0), MIN_RETRY_MS);
        assert_eq!(
            retry_after_for(100_000, 100_000, 1.0),
            u64::from(MAX_PACE_MS)
        );
    }

    #[test]
    fn refuses_above_hard_limit_and_frees_slots_on_drop() {
        let load = WriteLoad::new(1, 3);
        let a = load.try_begin().unwrap();
        let _b = load.try_begin().unwrap();
        let _c = load.try_begin().unwrap();
        assert_eq!(load.in_flight(), 3);
        let busy = load.try_begin().err().expect("refused");
        assert!(busy.retry_after_ms >= MIN_RETRY_MS);
        assert_eq!(load.in_flight(), 3, "a refusal must not hold a slot");
        assert_eq!(load.refused_total(), 1);
        assert!(busy.message().contains("retry_after_ms="));
        drop(a);
        assert!(load.try_begin().is_ok());
    }
}
