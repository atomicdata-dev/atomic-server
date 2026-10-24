//! Signing in again after a restart. The store keeps the active drive but NOT
//! the agent: `Db::default_agent` lives in memory only, so the secret is the
//! app's to keep (Flutter: `AtomicSession` in secure storage) and to hand back
//! on every start. Without that, every start looked like a first run and made
//! a new agent.

use crate::error::CoreResult;
use atomic_lib::Storelike;

/// Load the agent a secret holds and pick the drive to work on: `drive_hint`
/// (what the app remembered) when given, else the agent's private drive, which
/// follows from the key alone. Returns whether the drive is in this store;
/// `false` means it still has to arrive from a server or a paired device.
pub(crate) async fn resume(
    store: &atomic_lib::Db,
    secret: &str,
    drive_hint: Option<&str>,
) -> CoreResult<bool> {
    store.load_agent_from_secret(secret).await?;
    match drive_hint.filter(|s| !s.is_empty()) {
        Some(drive) => {
            let _ = store.set_active_drive(drive);
        }
        // A secret holds an identity and nothing else, but the one drive that
        // follows from the key alone is the private drive. Work on that, not
        // on whatever a previous agent left active.
        None => {
            if let Ok(home) = store.private_drive_subject() {
                let _ = store.set_active_drive(&home);
            }
        }
    }
    Ok(drive_exists(store).await)
}

/// Whether the active drive is stored on this device.
pub(crate) async fn drive_exists(store: &atomic_lib::Db) -> bool {
    let Some(drive) = store.get_active_drive() else {
        return false;
    };
    let subject = atomic_lib::Subject::from_raw(&drive, store.get_base_domain().as_deref());
    store.get_resource(&subject).await.is_ok()
}
