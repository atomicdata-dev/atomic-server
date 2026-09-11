//! Per-store async admission, above the storage transaction barrier.
//!
//! Calls already admitted can finish their nested store operations even when a
//! backup is waiting. Spawned tasks do not inherit admission. This avoids the
//! recursive-read deadlock of a plain fair RwLock around nested store methods.
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{OwnedRwLockWriteGuard, RwLock};

tokio::task_local! { static ADMITTED: Vec<usize>; }

#[derive(Clone, Default)]
pub struct Maintenance(Arc<Inner>);

#[derive(Default)]
struct Inner {
    lock: Arc<RwLock<()>>,
    paused: AtomicBool,
}

impl Maintenance {
    pub fn is_paused(&self) -> bool {
        self.0.paused.load(Ordering::Acquire)
    }

    pub async fn run<F: Future>(&self, work: F) -> F::Output {
        let id = Arc::as_ptr(&self.0) as usize;
        let mut admitted = ADMITTED.try_with(Clone::clone).unwrap_or_default();
        if admitted.contains(&id) {
            return work.await;
        }
        let _guard = self.0.lock.read().await;
        admitted.push(id);
        ADMITTED.scope(admitted, work).await
    }

    /// Cancellation while draining also clears the maintenance flag.
    pub async fn pause(&self) -> Result<Pause, &'static str> {
        if self
            .0
            .paused
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("Backup already in progress");
        }
        let mut pause = Pause {
            inner: self.0.clone(),
            guard: None,
        };
        pause.guard = Some(self.0.lock.clone().write_owned().await);
        Ok(pause)
    }
}

pub struct Pause {
    inner: Arc<Inner>,
    guard: Option<OwnedRwLockWriteGuard<()>>,
}

impl Drop for Pause {
    fn drop(&mut self) {
        self.guard.take();
        self.inner.paused.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_allows_nested_operations_and_blocks_new_work() {
        let gate = Maintenance::default();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let g = gate.clone();
        let writer = tokio::spawn(async move {
            g.run(async {
                entered_tx.send(()).unwrap();
                finish_rx.await.unwrap();
                g.run(async {}).await;
            })
            .await;
        });
        entered_rx.await.unwrap();
        let g = gate.clone();
        let backup = tokio::spawn(async move { g.pause().await.unwrap() });
        while !gate.is_paused() {
            tokio::task::yield_now().await;
        }
        finish_tx.send(()).unwrap();
        writer.await.unwrap();
        let pause = backup.await.unwrap();
        assert!(gate.pause().await.is_err());
        let g = gate.clone();
        let waiter = tokio::spawn(async move { g.run(async { 42 }).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(pause);
        assert_eq!(waiter.await.unwrap(), 42);
        assert!(!gate.is_paused());
    }

    #[tokio::test]
    async fn cancelling_a_drain_restores_admission() {
        let gate = Maintenance::default();
        let guard = gate.0.lock.read().await;
        let g = gate.clone();
        let job = tokio::spawn(async move { g.pause().await });
        while !gate.is_paused() {
            tokio::task::yield_now().await;
        }
        job.abort();
        let _ = job.await;
        assert!(!gate.is_paused());
        drop(guard);
        drop(gate.pause().await.unwrap());
    }
}
