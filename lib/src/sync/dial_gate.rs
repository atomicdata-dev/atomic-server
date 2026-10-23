//! Which peers are worth dialling now.
//!
//! A paired device that is switched off (or on another network) never
//! answers, and every caller that wants "sync with my devices" (the search
//! loop, the needs-sync screen, drive following, resume) used to dial it
//! again at once, each for the full connect timeout, several at a time.
//! [`DialGate`] is the one place that remembers:
//! - a failed connect puts the peer in a backoff (30 s, doubling per
//!   consecutive failure, capped at 15 min); automatic attempts inside the
//!   window are skipped, not dialled;
//! - only one attempt per peer runs at a time;
//! - a success, [`DialGate::reset_all`] (network change, app back in the
//!   foreground, the user's "sync now") and a forced dial clear/bypass it.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
pub const BACKOFF_CAP: Duration = Duration::from_secs(15 * 60);

/// The backoff after `failures` consecutive failed connects (1 or more).
pub fn backoff_for(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    BACKOFF_BASE.saturating_mul(1u32 << shift).min(BACKOFF_CAP)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    /// Failed recently; the time left of the backoff.
    Backoff(Duration),
    /// Another attempt to this peer is running.
    InFlight,
}

#[derive(Default)]
struct Entry {
    failures: u32,
    retry_at: Option<Instant>,
    in_flight: bool,
}

#[derive(Default)]
pub struct DialGate {
    peers: Mutex<HashMap<String, Entry>>,
}

/// Proof that an attempt to a peer is running; dropping it ends the attempt.
pub struct Attempt<'a> {
    gate: &'a DialGate,
    key: String,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let mut peers = self.gate.lock();
        if let Some(e) = peers.get_mut(&self.key) {
            e.in_flight = false;
        }
    }
}

impl DialGate {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start an attempt to `key`. `force` (the user asked) ignores the
    /// backoff and a running attempt.
    pub fn begin(&self, key: &str, now: Instant, force: bool) -> Result<Attempt<'_>, Skip> {
        let mut peers = self.lock();
        let e = peers.entry(key.to_string()).or_default();
        if !force {
            if e.in_flight {
                return Err(Skip::InFlight);
            }
            if let Some(at) = e.retry_at {
                if at > now {
                    return Err(Skip::Backoff(at - now));
                }
            }
        }
        e.in_flight = true;
        Ok(Attempt {
            gate: self,
            key: key.to_string(),
        })
    }

    pub fn record_failure(&self, key: &str, now: Instant) {
        let mut peers = self.lock();
        let e = peers.entry(key.to_string()).or_default();
        e.failures = e.failures.saturating_add(1);
        e.retry_at = Some(now + backoff_for(e.failures));
    }

    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Forget every backoff (network change, foreground, "sync now").
    pub fn reset_all(&self) {
        for e in self.lock().values_mut() {
            e.failures = 0;
            e.retry_at = None;
        }
    }

    pub fn failures(&self, key: &str) -> u32 {
        self.lock().get(key).map_or(0, |e| e.failures)
    }
}

/// The process's gate, one per Iroh endpoint like the endpoint itself.
pub static DIAL_GATE: LazyLock<DialGate> = LazyLock::new(DialGate::default);

/// Forget which peers were unreachable: dial them again on the next attempt.
pub fn reset_unreachable_peers() {
    DIAL_GATE.reset_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff_for(1), Duration::from_secs(30));
        assert_eq!(backoff_for(2), Duration::from_secs(60));
        assert_eq!(backoff_for(3), Duration::from_secs(120));
        assert_eq!(backoff_for(30), BACKOFF_CAP);
    }

    #[test]
    fn failed_peer_is_skipped_until_window_passes() {
        let g = DialGate::default();
        let t0 = Instant::now();
        drop(g.begin("a", t0, false).unwrap());
        g.record_failure("a", t0);
        assert!(matches!(
            g.begin("a", t0 + Duration::from_secs(10), false),
            Err(Skip::Backoff(_))
        ));
        // Other peers are unaffected.
        assert!(g.begin("b", t0, false).is_ok());
        assert!(g.begin("a", t0 + Duration::from_secs(31), false).is_ok());
    }

    #[test]
    fn second_failure_waits_longer_and_success_resets() {
        let g = DialGate::default();
        let t0 = Instant::now();
        g.record_failure("a", t0);
        g.record_failure("a", t0);
        assert!(g.begin("a", t0 + Duration::from_secs(59), false).is_err());
        assert!(g.begin("a", t0 + Duration::from_secs(61), false).is_ok());
        g.record_success("a");
        assert_eq!(g.failures("a"), 0);
        assert!(g.begin("a", t0, false).is_ok());
    }

    #[test]
    fn no_concurrent_duplicate_attempts() {
        let g = DialGate::default();
        let t0 = Instant::now();
        let first = g.begin("a", t0, false).unwrap();
        assert_eq!(g.begin("a", t0, false).err(), Some(Skip::InFlight));
        drop(first);
        assert!(g.begin("a", t0, false).is_ok());
    }

    #[test]
    fn reset_and_force_bypass_backoff() {
        let g = DialGate::default();
        let t0 = Instant::now();
        g.record_failure("a", t0);
        assert!(g.begin("a", t0, true).is_ok());
        g.reset_all();
        assert!(g.begin("a", t0, false).is_ok());
    }
}
