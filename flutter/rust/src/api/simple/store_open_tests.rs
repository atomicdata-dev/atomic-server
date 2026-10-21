//! `open_db` on a store that is already open, damaged, or not a store.

use super::*;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "atomic-bridge-open-{name}-{}-{}",
        std::process::id(),
        state::now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Android runs `main` again in the same process when it recreates the
/// activity. The second `open_db` must keep the open store: a second
/// handle on the file is what damaged stores.
#[tokio::test]
async fn a_second_open_db_keeps_the_store_that_is_open() {
    tests::shared_drive().await;
    let before = db().unwrap().clone();
    let elsewhere = temp_dir("second");
    open_db(elsewhere.to_string_lossy().into_owned())
        .await
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&before, db().unwrap()));
    assert!(
        !elsewhere.join("atomic.redb").exists(),
        "no second store is opened"
    );
    std::fs::remove_dir_all(elsewhere).ok();
}

/// The damage seen on Android: the file ends before its header says. The
/// file is kept under a new name and a repaired copy (or an empty store)
/// opens in its place, never a panic.
#[tokio::test]
async fn a_store_shorter_than_its_header_is_kept_and_replaced() {
    let dir = temp_dir("short");
    {
        let (store, recovery) = open_native_store(&dir).await.unwrap();
        assert_eq!(recovery, None);
        store
            .kv
            .insert(
                atomic_lib::db::trees::Tree::PluginMeta,
                b"k",
                &[1u8; 50_000],
            )
            .unwrap();
        store.flush().unwrap();
    }
    // Let the store close (its flush thread holds only a weak reference).
    std::thread::sleep(std::time::Duration::from_millis(300));
    let path = dir.join("atomic.redb");
    let check = atomic_lib::db::recovery::inspect(&path).unwrap().unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(check.layout_len - 2 * u64::from(check.page_size))
        .unwrap();
    let damaged = std::fs::read(&path).unwrap();

    let (_store, recovery) = open_native_store(&dir).await.unwrap();
    let recovery = recovery.expect("a damaged store is reported");
    assert!(
        atomic_lib::db::recovery::is_damaged_store_error(&recovery.reason),
        "{recovery:?}"
    );
    assert_eq!(
        std::fs::read(&recovery.kept_path).unwrap(),
        damaged,
        "the broken file is kept as it was"
    );
    assert!(path.exists());
    std::fs::remove_dir_all(dir).ok();
}

/// Something that is not a store at all: set aside, and the app starts on
/// an empty store.
#[tokio::test]
async fn a_file_that_is_not_a_store_is_kept_and_an_empty_store_opens() {
    let dir = temp_dir("garbage");
    std::fs::write(dir.join("atomic.redb"), vec![0x42u8; 9000]).unwrap();
    let (store, recovery) = open_native_store(&dir).await.unwrap();
    let recovery = recovery.expect("a file that is not a store is reported");
    assert!(!recovery.repaired, "{recovery:?}");
    assert_eq!(
        std::fs::read(&recovery.kept_path).unwrap(),
        vec![0x42u8; 9000]
    );
    assert!(store.get_active_drive().is_none());
    std::fs::remove_dir_all(dir).ok();
}
