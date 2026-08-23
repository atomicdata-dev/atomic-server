//! The key an app signs its own writes with.
//!
//! Kept in a tree of its own, apart from [`super::plugin_secret`], and that
//! separation is the point rather than tidiness. A plugin secret is spent by
//! substituting `secret:<name>` into an HTTP header. If an app's signing key
//! lived in the same store under a name, a plugin could write
//! `Authorization: secret:app-key` and post its own identity to any origin it
//! is allowed to reach. The two are different kinds of thing and the type
//! system should not let them be confused.
//!
//! Stored wrapped by the node key, like every other secret at rest, so that a
//! store which leaves the machine leaves without the ability to write as
//! anyone.

use serde::{Deserialize, Serialize};

/// One app, on one drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppAgentKey {
    pub drive: String,
    pub app: String,
}

impl AppAgentKey {
    pub fn new(drive: &str, app: &str) -> Self {
        Self {
            drive: drive.to_string(),
            app: app.to_string(),
        }
    }
}

/// What a caller may see: that a key exists, and whose it is. Never the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppAgentInfo {
    /// The DID this app writes as.
    pub agent: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAgent {
    /// The agent's own subject, kept beside the secret so a caller can learn
    /// which DID an app writes as without opening anything.
    pub agent: String,
    /// The Ed25519 secret, as `Agent::buildSecret` produces it.
    pub secret: String,
    pub created_at: i64,
}

impl AppAgent {
    pub fn new(agent: String, secret: String, created_at: i64) -> Self {
        Self {
            agent,
            secret,
            created_at,
        }
    }

    pub fn info(&self) -> AppAgentInfo {
        AppAgentInfo {
            agent: self.agent.clone(),
            created_at: self.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_cannot_carry_the_key() {
        let stored = AppAgent::new("did:ad:agent:pub".into(), "the-secret".into(), 0);

        let json = serde_json::to_string(&stored.info()).unwrap();

        assert!(!json.contains("the-secret"), "{json}");
        assert!(json.contains("did:ad:agent:pub"));
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod store_tests {
    use super::*;
    use crate::agents::Agent;
    use crate::db::Db;

    const NODE_KEY: [u8; crate::vault::keys::KEK_LEN] = [3u8; crate::vault::keys::KEK_LEN];

    async fn db(name: &str) -> Db {
        Db::init_temp(&format!("app_agent_{name}"))
            .await
            .expect("temp db")
    }

    fn key() -> AppAgentKey {
        AppAgentKey::new("did:ad:drive", "did:ad:app")
    }

    #[tokio::test]
    async fn an_app_can_sign_as_itself() {
        let db = db("sign").await;
        db.set_node_key(NODE_KEY);

        let agent = Agent::new(Some("test app")).expect("agent");
        db.set_app_agent(
            &key(),
            &AppAgent::new(
                agent.subject.to_string(),
                agent.build_secret().expect("secret"),
                0,
            ),
        )
        .expect("stored");

        let signed_as = db
            .with_app_agent(&key(), |a| a.subject.to_string())
            .expect("read")
            .expect("present");

        assert_eq!(signed_as, agent.subject.to_string());
    }

    #[tokio::test]
    async fn the_key_is_not_in_the_clear_on_disk() {
        let db = db("at_rest").await;
        db.set_node_key(NODE_KEY);

        let agent = Agent::new(Some("test app")).expect("agent");
        let secret = agent.build_secret().expect("secret");
        db.set_app_agent(
            &key(),
            &AppAgent::new(agent.subject.to_string(), secret.clone(), 0),
        )
        .expect("stored");

        let raw = db
            .kv
            .get(crate::db::trees::Tree::AppAgent, &key().encode().unwrap())
            .expect("read")
            .expect("present");

        assert!(
            !String::from_utf8_lossy(&raw).contains(&secret),
            "an app's signing key was written to disk in the clear",
        );
    }

    #[tokio::test]
    async fn asking_which_did_does_not_open_the_key() {
        let db = db("info").await;
        db.set_node_key(NODE_KEY);

        let agent = Agent::new(Some("test app")).expect("agent");
        let secret = agent.build_secret().expect("secret");
        db.set_app_agent(
            &key(),
            &AppAgent::new(agent.subject.to_string(), secret.clone(), 0),
        )
        .expect("stored");

        let info = db
            .get_app_agent_info(&key())
            .expect("read")
            .expect("present");
        let json = serde_json::to_string(&info).expect("serializes");

        assert!(!json.contains(&secret), "{json}");
        assert_eq!(info.agent, agent.subject.to_string());
    }

    #[tokio::test]
    async fn revoking_leaves_nothing_to_sign_with() {
        let db = db("revoke").await;
        db.set_node_key(NODE_KEY);

        let agent = Agent::new(Some("test app")).expect("agent");
        db.set_app_agent(
            &key(),
            &AppAgent::new(agent.subject.to_string(), agent.build_secret().unwrap(), 0),
        )
        .expect("stored");

        db.delete_app_agent(&key()).expect("deleted");

        assert!(db
            .with_app_agent(&key(), |a| a.subject.to_string())
            .expect("read")
            .is_none());
    }

    #[tokio::test]
    async fn apps_do_not_share_a_key() {
        let db = db("distinct").await;
        db.set_node_key(NODE_KEY);

        let one = Agent::new(Some("one")).expect("agent");
        let two = Agent::new(Some("two")).expect("agent");

        db.set_app_agent(
            &AppAgentKey::new("did:ad:drive", "did:ad:one"),
            &AppAgent::new(one.subject.to_string(), one.build_secret().unwrap(), 0),
        )
        .unwrap();
        db.set_app_agent(
            &AppAgentKey::new("did:ad:drive", "did:ad:two"),
            &AppAgent::new(two.subject.to_string(), two.build_secret().unwrap(), 0),
        )
        .unwrap();

        let first = db
            .with_app_agent(&AppAgentKey::new("did:ad:drive", "did:ad:one"), |a| {
                a.subject.to_string()
            })
            .unwrap()
            .unwrap();

        assert_eq!(first, one.subject.to_string());
        assert_ne!(first, two.subject.to_string());
    }
}
