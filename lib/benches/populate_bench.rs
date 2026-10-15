//! Benchmarks for DB bootstrap (populate base models + default store).
//!
//! Runs two scenarios:
//!   - `bootstrap/fresh`             — empty DB, empty WatchedQueries tree
//!   - `bootstrap/after_N_watches`   — populate is run a second time against a
//!     DB where N queries have already been watched (the normal state of a
//!     long-running production server)
//!
//! Run with: `cargo bench -p atomic_lib --bench populate_bench --features db-redb`

use atomic_lib::db::trees::Tree;
use atomic_lib::storelike::Query;
use atomic_lib::{Storelike, Subject};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

async fn seed_watched_queries(store: &atomic_lib::Db, count: usize) {
    // `drive` is set to `https://atomicdata.dev` so that populate's atoms
    // (which have subjects under that origin) fall into the same `by_drive`
    // bucket as these seeded filters. This is the worst case for the cache:
    // every atom iterates every filter. The production workload (filters
    // scoped to `http://localhost:9883`, populate atoms under
    // `https://atomicdata.dev`) is covered by the
    // `after_watches_different_drive/*` variants further down.
    seed_watched_queries_with_drive(store, count, "https://atomicdata.dev").await
}

async fn seed_watched_queries_with_drive(store: &atomic_lib::Db, count: usize, drive_str: &str) {
    let drive = Subject::from(drive_str.to_string());
    for i in 0..count {
        let q = Query {
            property: Some(format!("https://example.com/bench/prop/{i}")),
            value: None,
            filters: vec![],
            expression_filters: vec![],
            limit: Some(1),
            offset: 0,
            // `sort_by` makes `requires_query_index(q)` return true, which
            // routes through `query_complex` — the path that calls
            // `q_filter.watch()` (db.rs:1114). Without this, `query()` goes
            // through `query_basic` and nothing is ever watched.
            sort_by: Some(atomic_lib::urls::NAME.to_string()),
            sort_desc: false,
            start_val: None,
            end_val: None,
            include_external: false,
            exclude_trashed: false,
            include_nested: false,
            for_agent: atomic_lib::agents::ForAgent::Sudo,
            drive: Some(drive.clone()),
            aggregation: None,
        };
        // Ignore the result — we only care about the side-effect (a new
        // entry in Tree::WatchedQueries).
        let _ = store.query(&q).await;
    }

    // Sanity check: prove the seed actually landed in the tree. Without this,
    // a silent failure in `query()` would make the bench look fast because
    // the scan iterates 0 entries.
    let actual = store.kv.iter_tree(Tree::WatchedQueries).count();
    assert!(
        actual >= count,
        "seed_watched_queries: expected at least {count} watched queries, got {actual}"
    );
}

fn bench_populate(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("bootstrap");
    group.sample_size(10);

    group.bench_function("fresh", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let mut total = std::time::Duration::ZERO;
                for i in 0..iters {
                    let store = atomic_lib::Db::init_temp(&format!("pop_{i}"))
                        .await
                        .unwrap();
                    let start = std::time::Instant::now();
                    atomic_lib::populate::bootstrap(&store).await.unwrap();
                    total += start.elapsed();
                }
                total
            })
        })
    });

    // Bootstrap over a DB that already contains 10K "user" resources. The
    // default_store vocabulary is still re-added over itself, but the DB is
    // now realistically sized (index trees are deep, reads cost more than
    // on an essentially-empty DB).
    group.bench_function("big_db_10k_resources", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let mut total = std::time::Duration::ZERO;
                for i in 0..iters {
                    let store = atomic_lib::Db::init_temp(&format!("big_{i}"))
                        .await
                        .unwrap();
                    // Pre-populate with 10K "user" resources under the drive.
                    for j in 0..10_000 {
                        let subj = format!("https://localhost/things/{j}");
                        let mut r = atomic_lib::Resource::new(subj.clone());
                        r.set(
                            atomic_lib::urls::NAME.into(),
                            atomic_lib::Value::String(format!("Thing {j}")),
                            &store,
                        )
                        .await
                        .unwrap();
                        r.set(
                            atomic_lib::urls::IS_A.into(),
                            atomic_lib::Value::ResourceArray(vec![atomic_lib::urls::AGENT.into()]),
                            &store,
                        )
                        .await
                        .unwrap();
                        store
                            .add_resource_opts(&r, false, true, true)
                            .await
                            .unwrap();
                    }
                    let start = std::time::Instant::now();
                    atomic_lib::populate::bootstrap(&store).await.unwrap();
                    total += start.elapsed();
                }
                total
            })
        })
    });

    // Second bootstrap on a DB that's already been bootstrapped — this is
    // the real-world path when an existing server restarts. Every resource
    // already exists, so add_resource_opts takes the remove-old-atoms +
    // add-new-atoms branch.
    group.bench_function("already_bootstrapped", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let mut total = std::time::Duration::ZERO;
                for i in 0..iters {
                    let store = atomic_lib::Db::init_temp(&format!("bs2_{i}"))
                        .await
                        .unwrap();
                    // init_temp already runs bootstrap once; run it again to
                    // simulate a restart of an already-populated server.
                    let start = std::time::Instant::now();
                    atomic_lib::populate::bootstrap(&store).await.unwrap();
                    total += start.elapsed();
                }
                total
            })
        })
    });

    for &watches in &[100usize, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("after_watches", watches),
            &watches,
            |b, &n| {
                b.iter_custom(|iters| {
                    rt.block_on(async {
                        let mut total = std::time::Duration::ZERO;
                        for i in 0..iters {
                            let store = atomic_lib::Db::init_temp(&format!("wq_{n}_{i}"))
                                .await
                                .unwrap();
                            // Seed the WatchedQueries tree to simulate a
                            // server that's been running for a while.
                            seed_watched_queries(&store, n).await;
                            let start = std::time::Instant::now();
                            atomic_lib::populate::bootstrap(&store).await.unwrap();
                            total += start.elapsed();
                        }
                        total
                    })
                })
            },
        );
    }

    // Production-shaped scenario: the server has accumulated many watched
    // queries all scoped to its own drive (http://localhost:9883), but
    // populate only adds resources under https://atomicdata.dev/. In the
    // pre-cache code every atom still msgpack-decodes every watched query
    // before the drive-prefix guard rejects it. With the cache the
    // `by_drive` HashMap lookup returns None and no filters are scanned at
    // all — this should stay flat regardless of N.
    for &watches in &[100usize, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("after_watches_different_drive", watches),
            &watches,
            |b, &n| {
                b.iter_custom(|iters| {
                    rt.block_on(async {
                        let mut total = std::time::Duration::ZERO;
                        for i in 0..iters {
                            let store = atomic_lib::Db::init_temp(&format!("wqdd_{n}_{i}"))
                                .await
                                .unwrap();
                            seed_watched_queries_with_drive(&store, n, "http://localhost:9883")
                                .await;
                            let start = std::time::Instant::now();
                            atomic_lib::populate::bootstrap(&store).await.unwrap();
                            total += start.elapsed();
                        }
                        total
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_populate);
criterion_main!(benches);
