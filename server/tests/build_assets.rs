#[path = "../build_assets.rs"]
mod build_assets;

use build_assets::compress_cached;

#[test]
fn compression_reuses_content_and_settings_but_recovers_from_corruption() {
    let cache = tempfile::tempdir().unwrap();
    let source = b"unchanged wasm payload ".repeat(100);
    let (first, hit) = compress_cached(&source, cache.path(), 1, 22).unwrap();
    assert!(!hit);
    assert_eq!(
        compress_cached(&source, cache.path(), 1, 22).unwrap(),
        (first.clone(), true)
    );

    let entry = std::fs::read_dir(cache.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(entry, b"truncated cache").unwrap();
    assert_eq!(
        compress_cached(&source, cache.path(), 1, 22).unwrap(),
        (first, false)
    );
    assert!(
        !compress_cached(b"changed input", cache.path(), 1, 22)
            .unwrap()
            .1
    );
    assert!(!compress_cached(&source, cache.path(), 2, 22).unwrap().1);
}

#[test]
fn concurrent_equal_assets_publish_complete_cache_entries() {
    let cache = tempfile::tempdir().unwrap();
    let source = b"shared bytes from separate asset paths ".repeat(100);
    let outputs = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| compress_cached(&source, cache.path(), 1, 22).unwrap().0))
            .collect();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(outputs.iter().all(|output| output == &outputs[0]));
    assert!(compress_cached(&source, cache.path(), 1, 22).unwrap().1);
    assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 1);
}
