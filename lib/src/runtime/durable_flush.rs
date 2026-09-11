//! Owned native durability worker, independent of HTTP and async executors.

/// Fsync runs off the async executor. Dropping the lifecycle wakes the worker
/// immediately, performs a final flush and joins it; the old detached loop
/// kept the database open forever after a failed bind or an embedder exit.
#[must_use = "Keep the flush guard alive for the lifetime of the node"]
pub struct DurableFlush {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DurableFlush {
    pub(crate) fn start(store: crate::Db) -> std::io::Result<Self> {
        let (stop, rx) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("durable-flush".into())
            .spawn(move || loop {
                let stopping = !matches!(
                    rx.recv_timeout(std::time::Duration::from_millis(100)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                );
                if let Err(error) = store.flush() {
                    tracing::warn!("durable flush failed: {error}");
                }
                if stopping {
                    break;
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for DurableFlush {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("durable-flush thread panicked");
            }
        }
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod tests {
    use super::DurableFlush;
    use crate::{urls, Resource, Storelike, Value};

    #[tokio::test]
    async fn dropping_flush_worker_releases_database_and_persists_final_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.redb");
        let blobs = dir.path().join("blobs");
        let db = crate::Db::init_redb_file(&path, None, &blobs)
            .await
            .unwrap();
        let worker = DurableFlush::start(db.clone()).unwrap();
        let mut resource = Resource::new("did:ad:flush-test".into());
        resource
            .set_unsafe(urls::NAME.into(), Value::String("Durable".into()))
            .unwrap();
        db.add_resource_opts(&resource, false, false, true)
            .await
            .unwrap();
        drop(db);
        // The worker owns the final Db reference. A detached loop would keep
        // redb locked and reopening below would fail with DatabaseAlreadyOpen.
        drop(worker);
        let reopened = crate::Db::init_redb_file(&path, None, &blobs)
            .await
            .unwrap();
        let resource = reopened.get_resource(resource.get_subject()).await.unwrap();
        assert_eq!(resource.get(urls::NAME).unwrap().to_string(), "Durable");
    }
}
