//! Manual comparison of the former periodic-flush boundary and durable acks.
//! Uses synthetic data and independent resources; timings include signing and
//! validation but no network. Never interpret the faster baseline as safe.
use atomic_lib::{
    sync::engine::{ingest_commit_json, CommitIngestOpts},
    Db, Storelike,
};
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual persistence throughput probe"]
async fn compare_acknowledgement_throughput() {
    const EDITS: usize = 16;
    for writers in [1, 4, 16] {
        for durable_ack in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let store = Db::init_redb_file(dir.path(), None, &dir.path().join("uploads"))
                .await
                .unwrap();
            store.set_base_url("http://localhost");
            let (agent, drive) = store.setup("Throughput probe").await.unwrap();
            let mut subjects = Vec::new();
            for writer in 0..writers {
                subjects.push(
                    store
                        .create_resource(
                            "https://atomicdata.dev/classes/Folder",
                            &drive,
                            &format!("Writer {writer}"),
                            None,
                        )
                        .await
                        .unwrap(),
                );
            }
            store.flush().unwrap();
            // Same 100 ms background flush as serve.rs, including for baseline.
            let tick_store = store.clone();
            let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
            let tick = std::thread::spawn(move || {
                while stop_rx.recv_timeout(Duration::from_millis(100))
                    == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                {
                    tick_store.flush().unwrap();
                }
            });
            let started = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for subject in subjects.clone() {
                let store = store.clone();
                let agent = agent.clone();
                tasks.spawn(async move {
                    let mut samples = Vec::new();
                    for edit in 0..EDITS {
                        let begin = Instant::now();
                        let mut resource =
                            store.get_resource(&subject.clone().into()).await.unwrap();
                        resource.set_name(&format!("Edit {edit}")).unwrap();
                        let snapshot = resource.build_state_doc().unwrap().export_snapshot();
                        let mut builder = resource.get_commit_builder().clone();
                        builder.set_loro_update(snapshot);
                        let commit = builder.sign(&agent, &store, &resource).await.unwrap();
                        let json = atomic_lib::client::commit_to_wire_json(&commit, &store)
                            .await
                            .unwrap();
                        if durable_ack {
                            super::apply_commit_json(&store, "http://localhost", &json, None)
                                .await
                                .unwrap();
                        } else {
                            ingest_commit_json(
                                &store,
                                &json,
                                &CommitIngestOpts::hub(None, Some("http://localhost".into())),
                            )
                            .await
                            .unwrap();
                        }
                        samples.push(begin.elapsed().as_secs_f64() * 1000.0);
                    }
                    samples
                });
            }
            let mut samples = Vec::new();
            while let Some(result) = tasks.join_next().await {
                samples.extend(result.unwrap());
            }
            let elapsed = started.elapsed().as_secs_f64();
            let _ = stop_tx.send(());
            tick.join().unwrap();
            store.flush().unwrap();
            for subject in subjects {
                assert_eq!(
                    store
                        .get_resource(&subject.into())
                        .await
                        .unwrap()
                        .get_name()
                        .unwrap(),
                    format!("Edit {}", EDITS - 1)
                );
            }
            samples.sort_by(f64::total_cmp);
            println!("ack_probe writers={writers} durable={durable_ack} operations={} ops_s={:.1} p50_ms={:.2} p95_ms={:.2}",
                samples.len(), samples.len() as f64 / elapsed,
                samples[samples.len() / 2], samples[(samples.len() * 95 / 100).min(samples.len() - 1)]);
        }
    }
}
