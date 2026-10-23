//! The signed-in agent: setup, secrets, profile, device name.

use super::*;

// ── 2. Agent ───────────────────────────────────────────────────────────────

/// Create an agent and a personal drive in one call (the default store's
/// [`AtomicStore::setup`]). Pure local — no networking.
/// Call `start_peer()` + `peer_announce()` afterwards if you want to be discoverable.
pub async fn setup(name: String) -> Result<SetupResult, String> {
    let made = state::default_store()?
        .setup(name)
        .await
        .map_err(|e| e.message)?;
    Ok(SetupResult {
        agent_secret: made.agent_secret,
        agent_subject: made.agent_subject,
        drive_subject: made.drive,
    })
}

/// Load an existing agent from a secret. Pure local — no networking.
/// If the secret contains a drive DID, it becomes the active drive.
///
/// Returns "needs_sync" if the drive doesn't exist locally (needs QR pairing).
/// Returns the agent subject if everything is available.
pub async fn load_agent(secret: String) -> Result<String, String> {
    // A new sign-in: drives a server refused before are asked again.
    state::default_store()?.sync.clear_denied();
    let loaded = state::default_store()?
        .load_agent(secret)
        .await
        .map_err(|e| e.message)?;
    if loaded.needs_sync {
        Ok("needs_sync".to_string())
    } else {
        Ok(loaded.agent_subject)
    }
}

/// Get the currently active agent, if any.
pub async fn get_active_agent() -> Result<Option<AgentInfo>, String> {
    let store = db()?;
    match store.get_default_agent() {
        Ok(agent) => {
            let secret = agent.build_secret().map_err(err)?;
            Ok(Some(AgentInfo {
                secret,
                subject: agent.subject.to_string(),
                public_key: agent.public_key.clone(),
                name: agent.name.clone(),
            }))
        }
        Err(_) => Ok(None),
    }
}

/// Clear the active agent.
pub fn clear_agent() -> Result<(), String> {
    if let Ok(store) = db() {
        store.clear_default_agent();
    }
    Ok(())
}

#[frb(sync)]
pub fn create_agent(name: String) -> Result<AgentInfo, String> {
    let agent = atomic_lib::agents::Agent::new(Some(&name)).map_err(err)?;
    let secret = agent.build_secret().map_err(err)?;
    if let Ok(store) = db() {
        store.set_default_agent(agent.clone());
    }
    Ok(AgentInfo {
        secret,
        subject: agent.subject.to_string(),
        public_key: agent.public_key.clone(),
        name: agent.name.clone(),
    })
}

#[frb(sync)]
pub fn agent_from_secret(secret: String) -> Result<AgentInfo, String> {
    let agent = atomic_lib::agents::Agent::from_secret(&secret).map_err(err)?;
    Ok(AgentInfo {
        secret,
        subject: agent.subject.to_string(),
        public_key: agent.public_key.clone(),
        name: agent.name.clone(),
    })
}

/// The profile of this device's agent as JSON `{subject, name, description,
/// emoji?, imageUrl?}`: what the store holds, else what the connected server
/// has (`atomic_lib::host::own_profile`).
pub async fn get_own_profile() -> Result<String, String> {
    let profile = atomic_lib::host::own_profile::own_profile(db()?, &crate::host::profiles())
        .await
        .map_err(err)?;
    crate::host::to_json(&profile)
}

/// Keep a picked picture as a File in the active drive (bytes in the local
/// store, the File queued for sync like the web app's upload) and return the
/// File's subject, to pass as `icon` to `set_agent_profile`.
pub async fn upload_agent_picture(
    filename: String,
    mimetype: String,
    bytes: Vec<u8>,
) -> Result<String, String> {
    let drive = db()?
        .get_active_drive()
        .ok_or("No workspace to keep the picture in")?;
    let origin = state::connected_server();
    let _busy = busy(Kind::Upload);
    atomic_lib::host::own_profile::upload_own_picture(
        &node()?,
        crate::host::pusher().as_ref(),
        &drive,
        origin.as_deref(),
        &filename,
        &mimetype,
        &bytes,
    )
    .await
    .map_err(err)
}

/// Save this device's agent's profile: a commit by the agent on its own
/// resource, stored here and synced like any other edit. An empty
/// `description` removes it; `icon` is the subject of a File for the picture
/// (empty removes it, `None` leaves it as it is).
pub async fn set_agent_profile(
    name: String,
    description: String,
    icon: Option<String>,
) -> Result<(), String> {
    atomic_lib::host::own_profile::set_own_profile(
        &node()?,
        crate::host::pusher().as_ref(),
        &name,
        &description,
        icon.as_deref(),
    )
    .await
    .map_err(err)
}

// ── 11. New Typed FFI Exports ──────────────────────────────────────────────

#[frb(sync)]
pub fn get_device_name() -> Result<String, String> {
    let store = db()?;
    Ok(atomic_lib::sync::peer::get_device_name(store.as_ref()))
}

#[frb(sync)]
pub fn set_device_name(name: String) -> Result<(), String> {
    let store = db()?;
    atomic_lib::sync::peer::set_device_name(store.as_ref(), &name);
    Ok(())
}
