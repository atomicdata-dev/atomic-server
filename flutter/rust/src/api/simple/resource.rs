//! Generic resource access: create, set/get a property, history, watches.

use super::*;

// ── 4. Resource ────────────────────────────────────────────────────────────

pub async fn create_resource(parent_subject: String, name: String) -> Result<String, String> {
    db()?
        .create_resource(atomic_lib::urls::CLASS, &parent_subject, &name, None)
        .await
        .map_err(err)
}

pub async fn set_property(subject: String, property: String, value: String) -> Result<(), String> {
    let store = db()?;
    let mut resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    resource.set_unsafe(property, atomic_lib::Value::String(value));
    save_and_push(&mut resource, store.as_ref()).await
}

pub async fn get_property(subject: String, property: String) -> Result<String, String> {
    let store = db()?;
    let resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    Ok(resource
        .get(&property)
        .map(|v| v.to_string())
        .unwrap_or_default())
}

// ── 6. History ─────────────────────────────────────────────────────────────

/// Load versioned state for history operations.
pub async fn warm_resource_history(subject: String) -> Result<(), String> {
    let store = db()?;
    let mut resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    resource.warm_history().map_err(|e| e.to_string())
}

/// Get the edit history of a resource.
pub async fn get_resource_history(subject: String) -> Result<Vec<VersionMetadata>, String> {
    let store = db()?;
    let mut resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    resource.warm_history().map_err(|e| e.to_string())?;
    Ok(resource
        .get_history()
        .into_iter()
        .map(|m| VersionMetadata {
            id: m.id.bytes().to_vec(),
            timestamp: m.timestamp,
            peer_id: m.peer_id,
            lamport: m.lamport,
            len: m.len as i32,
            message: m.message,
        })
        .collect())
}

pub async fn watch_resource(subject: String) -> Result<String, String> {
    let store = db()?;
    let mut rx = store.subscribe_events();
    let target = atomic_lib::Subject::from_raw(&subject, store.get_base_domain().as_deref())
        .without_params();
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(atomic_lib::DbEvent::Changed { subject, .. }) if subject == target => {
                    return subject.to_string();
                }
                Ok(atomic_lib::DbEvent::Destroyed { subject, .. }) if subject == target => {
                    return format!("!{}", subject);
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    rx = store.subscribe_events();
                }
            }
        }
    })
    .await;
    match result {
        Ok(s) => Ok(s),
        Err(_) => Ok("timeout".into()),
    }
}

pub async fn watch_children(parent: String) -> Result<String, String> {
    let store = db()?;
    let mut rx = store.subscribe_events();
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(atomic_lib::DbEvent::Destroyed { subject, .. }) => {
                    return format!("!{}", subject);
                }
                Ok(atomic_lib::DbEvent::Changed { subject, .. }) => {
                    if let Ok(r) = store.get_resource(&subject).await {
                        if let Ok(p) = r.get(atomic_lib::urls::PARENT) {
                            if p.to_string() == parent {
                                return subject.to_string();
                            }
                        }
                    }
                }
                Ok(atomic_lib::DbEvent::QueryMembershipChanged { .. }) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    rx = store.subscribe_events();
                }
            }
        }
    })
    .await;

    match result {
        Ok(subject) => Ok(subject),
        Err(_) => Ok("timeout".into()),
    }
}
