//! What the host does in the background right now, for a small "busy" mark in
//! the UI: sync runs, following and catching up on drives, picture downloads,
//! activity lookups and scans, uploads.
//!
//! A task takes a [`Guard`] with [`begin`] and holds it while it works; the
//! count goes down when the guard is dropped, also on an early return or a
//! cancelled future. [`snapshot`] is cheap and holds no lock for long, so a
//! screen can poll it every second.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// What a background task is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A peer / home server sync run.
    Sync,
    /// Following and catching up on drives and conversations.
    Drives,
    /// Downloading a profile picture or other file.
    Pictures,
    /// Looking up who changed a resource.
    History,
    /// Building the activity log from the resources held.
    Scan,
    /// Uploading a file.
    Upload,
}

const KINDS: [Kind; 6] = [
    Kind::Sync,
    Kind::Drives,
    Kind::Pictures,
    Kind::History,
    Kind::Scan,
    Kind::Upload,
];

impl Kind {
    /// The name a UI keys on.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Sync => "sync",
            Kind::Drives => "drives",
            Kind::Pictures => "pictures",
            Kind::History => "history",
            Kind::Scan => "scan",
            Kind::Upload => "upload",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

static COUNTS: [AtomicU32; 6] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

#[derive(Default)]
struct Outcome {
    last_error: Option<String>,
    last_ok_ms: Option<i64>,
}

static OUTCOME: Mutex<Outcome> = Mutex::new(Outcome {
    last_error: None,
    last_ok_ms: None,
});

/// Holds one task of a kind in the count until dropped.
#[must_use = "the task counts only while the guard is held"]
pub struct Guard(Kind);

/// Count a task of `kind` as running until the returned guard is dropped.
pub fn begin(kind: Kind) -> Guard {
    COUNTS[kind.index()].fetch_add(1, Ordering::SeqCst);
    Guard(kind)
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Never below zero, whatever happens.
        let _ = COUNTS[self.0.index()].fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            Some(n.saturating_sub(1))
        });
    }
}

/// A background task failed: shown while nothing runs.
pub fn record_error(message: impl Into<String>) {
    if let Ok(mut o) = OUTCOME.lock() {
        o.last_error = Some(message.into());
    }
}

/// A background task succeeded: clears the last error.
pub fn record_ok() {
    if let Ok(mut o) = OUTCOME.lock() {
        o.last_error = None;
        o.last_ok_ms = Some(now_ms());
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// What runs now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub total: u32,
    /// Kinds with at least one task, by [`Kind::name`].
    pub by_kind: BTreeMap<String, u32>,
    pub last_error: Option<String>,
    /// When a task last succeeded (ms since the epoch).
    pub last_ok_ms: Option<i64>,
}

/// The current counts and the last outcome.
pub fn snapshot() -> Status {
    let mut status = Status::default();
    for kind in KINDS {
        let n = COUNTS[kind.index()].load(Ordering::SeqCst);
        if n > 0 {
            status.total += n;
            status.by_kind.insert(kind.name().to_string(), n);
        }
    }
    if let Ok(o) = OUTCOME.lock() {
        status.last_error = o.last_error.clone();
        status.last_ok_ms = o.last_ok_ms;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    // The registry is process-wide and other tests run background code that
    // counts too, so this one asserts on `Upload` (counted by the bridge, not
    // by the library) and on the total only from below.
    fn uploads() -> u32 {
        snapshot().by_kind.get("upload").copied().unwrap_or(0)
    }

    #[test]
    fn counts_guards_by_kind_across_threads_and_keeps_the_outcome() {
        assert_eq!(uploads(), 0);
        let a = begin(Kind::Upload);
        let b = begin(Kind::Upload);
        assert_eq!(uploads(), 2);
        assert!(snapshot().total >= 2);
        drop(a);
        assert_eq!(uploads(), 1);
        drop(b);
        assert_eq!(uploads(), 0);
        assert!(!snapshot().by_kind.contains_key("upload"));

        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..500 {
                        let _g = begin(Kind::Upload);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(uploads(), 0);

        record_error("offline");
        assert_eq!(snapshot().last_error.as_deref(), Some("offline"));
        record_ok();
        let s = snapshot();
        assert_eq!(s.last_error, None);
        assert!(s.last_ok_ms.is_some());
    }
}
