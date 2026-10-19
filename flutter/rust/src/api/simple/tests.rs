//! Shared harness for the bridge's unit tests: one process-global store that
//! every test in the binary runs against.

use super::*;

/// One database for the whole test binary — `state::DB` is a `OnceLock` and
/// cannot be re-set. Tests isolate by resource, not by store.
/// Tests run in parallel against one store, and `create_drive` and the home
/// lists (favorites, conversations) are all read-modify-write on the private
/// drive: without this one-at-a-time lock one test's save overwrites another's.
pub(crate) static PRIVATE_DRIVE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) async fn shared_drive() -> &'static str {
    static SETUP: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

    SETUP
        .get_or_init(|| async {
            let dir =
                std::env::temp_dir().join(format!("atomic-bridge-tests-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            open_db(dir.to_string_lossy().into_owned()).await.unwrap();
            setup("Test device".to_string())
                .await
                .unwrap()
                .drive_subject
        })
        .await
        .as_str()
}
