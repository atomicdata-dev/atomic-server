//! This device's own agent as the person sees and edits it: the name,
//! description and picture of their profile.
//!
//! Reading prefers what the store holds (a profile saved here, or synced in);
//! an agent the store only knows by its key falls back to the profile the
//! connected server has ([`AgentProfiles`]). Saving is a commit by the agent on
//! its own resource, applied locally, queued in the outbox and handed to the
//! host's [`LocalWritePusher`], like every other local edit. It builds on the
//! stored state, so the Loro history the resource has here is kept.

use super::{profiles::AgentProfiles, LocalWritePusher};
use crate::{errors::AtomicResult, runtime::AtomicNode, urls, Db, Resource, Storelike, Value};
use serde_json::{json, Map, Value as Json};

/// The agent's picture: a File resource (what the web app's profile editor
/// writes).
pub const ICON: &str = "https://atomicdata.dev/properties/icon";

/// The profile of this device's agent as JSON `{subject, name, description,
/// emoji?, imageUrl?}`. `imageUrl` is the download URL of the `icon` File when
/// this store has that File, else the agent's `imageUrl`.
pub async fn own_profile(store: &Db, profiles: &AgentProfiles) -> AtomicResult<Json> {
    let agent = store.get_default_agent()?;
    let subject = agent.subject.to_string();
    let local = store
        .get_resource_shallow(&agent.subject)
        .ok()
        .filter(|r| r.get(urls::NAME).is_ok())
        .and_then(|r| r.to_json_ad(None).ok());
    let json_ad = match local {
        Some(ad) => Some(ad),
        None => profiles.get(&subject).await,
    };
    let props: Map<String, Json> = json_ad
        .and_then(|ad| serde_json::from_str(&ad).ok())
        .unwrap_or_default();
    let text = |p: &str| {
        props
            .get(p)
            .and_then(Json::as_str)
            .map(str::trim)
            .unwrap_or_default()
            .to_string()
    };
    let name = match text(urls::NAME) {
        n if n.is_empty() => agent.name.clone().unwrap_or_default(),
        n => n,
    };
    let mut out = json!({
        "subject": subject,
        "name": name,
        "description": text(urls::DESCRIPTION),
    });
    let emoji = text(urls::EMOJI);
    if !emoji.is_empty() {
        out["emoji"] = json!(emoji);
    }
    let icon = text(ICON);
    let from_icon = (!icon.is_empty())
        .then(|| store.get_resource_shallow(&icon.as_str().into()).ok())
        .flatten()
        .and_then(|file| file.get(urls::DOWNLOAD_URL).ok().map(|v| v.to_string()))
        .filter(|u| u.starts_with("http"));
    let image = from_icon.unwrap_or_else(|| text(urls::IMAGE_URL));
    if image.starts_with("http") {
        out["imageUrl"] = json!(image);
    }
    Ok(out)
}

/// Save the agent's own profile: `name` (required), `description` (empty
/// removes it) and, when given, `icon`, the subject of a File (empty removes
/// the picture; `None` leaves it). Signed by the agent, synced like any edit.
pub async fn set_own_profile(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    name: &str,
    description: &str,
    icon: Option<&str>,
) -> AtomicResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err("A profile needs a name".into());
    }
    let store = node.db();
    let mut agent = store.get_default_agent()?;
    // The stored resource (with its Loro state) when there is one; else the
    // one the store derives from the key, which this commit then makes real.
    let mut resource: Resource = store.get_resource(&agent.subject).await?;
    resource.set_string(urls::NAME.into(), name, store).await?;
    match description.trim() {
        "" => {
            if resource.get(urls::DESCRIPTION).is_ok() {
                resource.remove_propval(urls::DESCRIPTION)?;
            }
        }
        d => {
            resource
                .set_string(urls::DESCRIPTION.into(), d, store)
                .await?;
        }
    }
    match icon.map(str::trim) {
        None => {}
        Some("") => {
            if resource.get(ICON).is_ok() {
                resource.remove_propval(ICON)?;
            }
        }
        Some(file) => {
            resource.set_unsafe(ICON.into(), Value::AtomicUrl(file.into()))?;
        }
    }
    let response = node.save_locally(&mut resource).await?;
    pusher.push(&response).await;
    // The agent in memory carries the name too (what the app shows for "you").
    agent.name = Some(name.to_string());
    store.set_default_agent(agent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{embed::EmbedHost, test_support::Device, NoPush};
    use std::sync::Arc;

    #[tokio::test]
    async fn a_saved_profile_is_read_back_and_kept() {
        let d = Device::new().await;
        set_own_profile(&d.node, &NoPush, " Pelican ", "Likes fish", None)
            .await
            .unwrap();

        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["name"], "Pelican");
        assert_eq!(p["description"], "Likes fish");
        assert!(p.get("imageUrl").is_none());
        assert_eq!(
            d.store.get_default_agent().unwrap().name.as_deref(),
            Some("Pelican")
        );

        // Signing in again with the secret (every app start) keeps it.
        let secret = d.store.get_default_agent().unwrap().build_secret().unwrap();
        let loaded = d.store.load_agent_from_secret(&secret).await.unwrap();
        assert_eq!(loaded.agent.name.as_deref(), Some("Pelican"));

        // An empty description removes it; an empty name is refused.
        set_own_profile(&d.node, &NoPush, "Pelican", "", None)
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["description"], "");
        assert!(set_own_profile(&d.node, &NoPush, "  ", "", None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_saved_profile_is_a_commit_the_page_reads_with_its_state() {
        let d = Device::new().await;
        let agent = d.store.get_default_agent().unwrap().subject.to_string();
        set_own_profile(&d.node, &NoPush, "Pelican", "", None)
            .await
            .unwrap();
        assert!(d.node.outbox().has_pending(&agent), "queued for sync");

        let host = EmbedHost::new(d.node.clone(), Arc::new(NoPush), AgentProfiles::none());
        let rows: Json = serde_json::from_str(
            &host
                .call("getResourcesWithSnapshots", &json!([[agent]]).to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(rows[0]["jsonAd"].as_str().unwrap().contains("Pelican"));
        // The page edits on top of the stored Loro state, not a blank one.
        assert!(rows[0]["snapshot"].is_string());
    }

    #[tokio::test]
    async fn the_picture_is_the_icon_files_download_url() {
        let d = Device::new().await;
        let file = d
            .store
            .create_resource(urls::FILE, &d.drive, "me.png", None)
            .await
            .unwrap();
        let mut f = d.store.get_resource(&file.as_str().into()).await.unwrap();
        f.set_unsafe(
            urls::DOWNLOAD_URL.into(),
            Value::String("https://example.test/download/me.png".into()),
        )
        .unwrap();
        d.node.save_locally(&mut f).await.unwrap();

        set_own_profile(&d.node, &NoPush, "Pelican", "", Some(&file))
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["imageUrl"], "https://example.test/download/me.png");

        set_own_profile(&d.node, &NoPush, "Pelican", "", Some(""))
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert!(p.get("imageUrl").is_none());
    }

    /// Signed in with a secret on a new device: the store knows the agent only
    /// by its key. Saving makes the profile real here, and the page then
    /// reads it from the store instead of the server's copy.
    #[tokio::test]
    async fn a_profile_saved_by_an_agent_known_only_by_its_key() {
        let store = Db::init_redb(None).await.unwrap();
        let secret = crate::agents::Agent::new(None)
            .unwrap()
            .build_secret()
            .unwrap();
        store.load_agent_from_secret(&secret).await.unwrap();
        let node = AtomicNode::from_db(store.clone());
        let agent = store.get_default_agent().unwrap().subject.to_string();

        set_own_profile(&node, &NoPush, "Pelican", "From the app", None)
            .await
            .unwrap();

        let p = own_profile(&store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["name"], "Pelican");
        let host = EmbedHost::new(node.clone(), Arc::new(NoPush), AgentProfiles::none());
        let rows: Json = serde_json::from_str(
            &host
                .call("getResourcesWithSnapshots", &json!([[agent]]).to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(rows[0]["jsonAd"].as_str().unwrap().contains("From the app"));
        assert!(rows[0]["snapshot"].is_string());
    }
}
