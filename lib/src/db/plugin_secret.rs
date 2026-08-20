//! Credentials a plugin may spend but never read.
//!
//! Deliberately not resources. A resource is committed, synced, indexed and
//! rendered; a credential must be none of those. `PluginMeta` already keeps a
//! plugin's `agent_secret` in its own table for exactly that reason, and this
//! follows it.
//!
//! Stored in plaintext at rest, as `agent_secret` is. That is a deliberate
//! deferral, not an oversight: see `planning/encryption.md` for the key
//! hierarchy this should eventually sit under.

use serde::{Deserialize, Serialize};

use crate::AtomicError;

/// Identifies a secret. Scoped per plugin: revoking one is then obviously
/// about one plugin, rather than a question of what else was using it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSecretKey {
    pub drive: String,
    /// Subject of the plugin this secret belongs to.
    pub plugin: String,
    /// What the plugin calls it: the `name` in `secret:<name>`.
    pub name: String,
}

impl PluginSecretKey {
    pub fn new(drive: &str, plugin: &str, name: &str) -> Self {
        Self {
            drive: drive.to_string(),
            plugin: plugin.to_string(),
            name: name.to_string(),
        }
    }

    /// A secret's name is what a plugin writes into a header, so it is kept to
    /// a shape that cannot be confused with a value or smuggle a separator.
    pub fn validate_name(name: &str) -> Result<(), AtomicError> {
        if name.is_empty() {
            return Err("A secret needs a name".into());
        }

        if name.len() > 64 {
            return Err("A secret's name is at most 64 characters".into());
        }

        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("A secret's name may only contain letters, digits, '-' and '_'".into());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSecret {
    /// The credential. Never leaves the host.
    pub value: String,
    /// Origins this secret may be sent to, e.g. `https://api.notion.com`.
    /// Empty means the secret is unusable, not that it is usable anywhere.
    pub origins: Vec<String>,
    /// Milliseconds since the epoch.
    pub created_at: i64,
    /// When the host last substituted it into a request, and how often. "Used
    /// 0 times in 90 days" is the answer that makes revoking easy; a date alone
    /// leaves you guessing.
    pub last_used_at: Option<i64>,
    pub use_count: u64,
}

impl PluginSecret {
    pub fn new(value: String, origins: Vec<String>, created_at: i64) -> Self {
        Self {
            value,
            origins,
            created_at,
            last_used_at: None,
            use_count: 0,
        }
    }

    /// Whether this secret may be sent to `origin`.
    ///
    /// Exact match on scheme and authority. No wildcards: `*.example.com` is
    /// one typo away from `evil-example.com`, and a credential is the wrong
    /// place to be generous.
    pub fn allows(&self, origin: &str) -> bool {
        self.origins.iter().any(|allowed| allowed == origin)
    }

    pub fn record_use(&mut self, at: i64) {
        self.last_used_at = Some(at);
        self.use_count = self.use_count.saturating_add(1);
    }
}

/// What a caller may be told about a secret. Never includes the value — there
/// is no method that returns one, so no endpoint can accidentally serve it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSecretInfo {
    pub name: String,
    pub origins: Vec<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub use_count: u64,
}

impl PluginSecretInfo {
    pub fn of(name: &str, secret: &PluginSecret) -> Self {
        Self {
            name: name.to_string(),
            origins: secret.origins.clone(),
            created_at: secret.created_at,
            last_used_at: secret.last_used_at,
            use_count: secret.use_count,
        }
    }
}

/// The prefix a plugin uses to refer to a secret it cannot read.
pub const SECRET_HANDLE_PREFIX: &str = "secret:";

/// The secret name inside a handle, if the string is one.
pub fn handle_name(value: &str) -> Option<&str> {
    value.strip_prefix(SECRET_HANDLE_PREFIX)
}

/// Whether any part of this string mentions a handle.
///
/// Used to refuse handles where they must not be substituted — a URL, a query
/// parameter, a body. A credential in a URL ends up in access logs and
/// `Referer` headers by design, so sending one there would be worse than
/// refusing.
pub fn mentions_handle(value: &str) -> bool {
    value.contains(SECRET_HANDLE_PREFIX)
}

#[cfg(all(test, feature = "db-redb"))]
mod store_tests {
    use super::*;
    use crate::db::Db;

    /// One store per test: `init_temp` takes a lock on the file, so a shared
    /// name makes the suite fail on whichever test happens to run second.
    async fn db(name: &str) -> Db {
        Db::init_temp(&format!("plugin_secrets_{name}"))
            .await
            .expect("temp db")
    }

    fn key() -> PluginSecretKey {
        PluginSecretKey::new("did:ad:drive", "did:ad:plugin", "notion")
    }

    fn secret() -> PluginSecret {
        PluginSecret::new(
            "tok-abc".to_string(),
            vec!["https://api.notion.com".to_string()],
            1_700_000_000_000,
        )
    }

    #[tokio::test]
    async fn a_secret_is_spendable_but_not_readable() {
        let db = db("spendable").await;
        db.set_plugin_secret(&key(), &secret()).expect("stored");

        let seen = db
            .use_plugin_secret(&key(), "https://api.notion.com", 1, |value| {
                value.to_string()
            })
            .expect("read")
            .expect("allowed");

        assert_eq!(seen, "tok-abc");

        // The only other read path describes it, and cannot carry the value.
        let info = db
            .get_plugin_secret_info(&key())
            .expect("info")
            .expect("exists");
        let json = serde_json::to_string(&info).expect("serializes");

        assert!(!json.contains("tok-abc"));
    }

    #[tokio::test]
    async fn a_secret_is_not_spent_on_an_origin_it_is_not_scoped_to() {
        let db = db("origin_scope").await;
        db.set_plugin_secret(&key(), &secret()).expect("stored");

        let used = db
            .use_plugin_secret(&key(), "https://evil.test", 1, |_| ())
            .expect("read");

        assert!(used.is_none());

        // And the refusal is not counted as a use.
        let info = db.get_plugin_secret_info(&key()).unwrap().unwrap();
        assert_eq!(info.use_count, 0);
    }

    #[tokio::test]
    async fn use_is_recorded_so_a_dead_credential_shows_up() {
        let db = db("use_recorded").await;
        db.set_plugin_secret(&key(), &secret()).expect("stored");

        for at in [10, 20, 30] {
            db.use_plugin_secret(&key(), "https://api.notion.com", at, |_| ())
                .expect("read")
                .expect("allowed");
        }

        let info = db.get_plugin_secret_info(&key()).unwrap().unwrap();
        assert_eq!(info.use_count, 3);
        assert_eq!(info.last_used_at, Some(30));
    }

    #[tokio::test]
    async fn a_missing_or_deleted_secret_is_simply_absent() {
        let db = db("absent").await;

        assert!(db.get_plugin_secret_info(&key()).unwrap().is_none());
        assert!(db
            .use_plugin_secret(&key(), "https://api.notion.com", 1, |_| ())
            .unwrap()
            .is_none());

        db.set_plugin_secret(&key(), &secret()).expect("stored");
        db.delete_plugin_secret(&key()).expect("deleted");

        assert!(db.get_plugin_secret_info(&key()).unwrap().is_none());
    }

    #[tokio::test]
    async fn secrets_of_different_plugins_do_not_collide() {
        let db = db("per_plugin").await;
        let other = PluginSecretKey::new("did:ad:drive", "did:ad:other-plugin", "notion");

        db.set_plugin_secret(&key(), &secret()).expect("stored");
        db.set_plugin_secret(
            &other,
            &PluginSecret::new("tok-other".to_string(), vec!["https://x".to_string()], 0),
        )
        .expect("stored");

        let first = db
            .use_plugin_secret(&key(), "https://api.notion.com", 1, |v| v.to_string())
            .unwrap()
            .unwrap();

        assert_eq!(first, "tok-abc");
    }

    #[tokio::test]
    async fn listing_describes_a_plugin_s_own_secrets_only() {
        let db = db("listing").await;

        db.set_plugin_secret(&key(), &secret()).unwrap();
        db.set_plugin_secret(
            &PluginSecretKey::new("did:ad:drive", "did:ad:plugin", "airtable"),
            &PluginSecret::new("tok-2".to_string(), vec!["https://x".to_string()], 0),
        )
        .unwrap();
        // Another plugin on the same drive, and the same plugin name on another.
        db.set_plugin_secret(
            &PluginSecretKey::new("did:ad:drive", "did:ad:other", "notion"),
            &PluginSecret::new("nope".to_string(), vec![], 0),
        )
        .unwrap();
        db.set_plugin_secret(
            &PluginSecretKey::new("did:ad:other-drive", "did:ad:plugin", "notion"),
            &PluginSecret::new("nope".to_string(), vec![], 0),
        )
        .unwrap();

        let listed = db
            .list_plugin_secrets("did:ad:drive", "did:ad:plugin")
            .expect("listed");

        assert_eq!(
            listed.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            vec!["airtable", "notion"],
        );

        // And still no values anywhere in it.
        let json = serde_json::to_string(&listed).unwrap();
        assert!(!json.contains("tok-abc"));
        assert!(!json.contains("tok-2"));
    }

    #[tokio::test]
    async fn a_key_round_trips_through_its_encoding() {
        let encoded = key().encode().expect("encodes");

        assert_eq!(
            PluginSecretKey::name_from_key(&encoded).expect("name"),
            "notion",
        );
        assert!(encoded.starts_with(&PluginSecretKey::plugin_prefix(
            "did:ad:drive",
            "did:ad:plugin"
        )));
    }

    #[tokio::test]
    async fn a_name_that_could_smuggle_a_separator_is_refused() {
        let db = db("bad_name").await;
        let bad = PluginSecretKey::new("did:ad:drive", "did:ad:plugin", "has:colon");

        assert!(db.set_plugin_secret(&bad, &secret()).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> PluginSecret {
        PluginSecret::new(
            "tok".to_string(),
            vec!["https://api.notion.com".to_string()],
            0,
        )
    }

    #[test]
    fn origins_match_exactly() {
        let s = secret();

        assert!(s.allows("https://api.notion.com"));
        // Scheme, host and port all count.
        assert!(!s.allows("http://api.notion.com"));
        assert!(!s.allows("https://api.notion.com:8443"));
        assert!(!s.allows("https://api.notion.com.evil.test"));
        assert!(!s.allows("https://notion.com"));
    }

    #[test]
    fn a_secret_with_no_origins_goes_nowhere() {
        let s = PluginSecret::new("tok".to_string(), vec![], 0);

        assert!(!s.allows("https://api.notion.com"));
        assert!(!s.allows(""));
    }

    #[test]
    fn use_is_counted_so_a_dead_credential_is_visible() {
        let mut s = secret();
        assert_eq!(s.use_count, 0);
        assert_eq!(s.last_used_at, None);

        s.record_use(1_700_000_000_000);
        s.record_use(1_700_000_000_001);

        assert_eq!(s.use_count, 2);
        assert_eq!(s.last_used_at, Some(1_700_000_000_001));
    }

    #[test]
    fn info_cannot_carry_a_value() {
        let info = PluginSecretInfo::of("notion", &secret());
        let json = serde_json::to_string(&info).expect("serializes");

        assert!(!json.contains("tok"));
        assert!(json.contains("notion"));
        assert!(json.contains("api.notion.com"));
    }

    #[test]
    fn handles_are_recognised() {
        assert_eq!(handle_name("secret:notion"), Some("notion"));
        assert_eq!(handle_name("Bearer secret:notion"), None);
        assert_eq!(handle_name("notion"), None);

        assert!(mentions_handle("Bearer secret:notion"));
        assert!(mentions_handle("https://x/?t=secret:notion"));
        assert!(!mentions_handle("Bearer abc"));
    }

    #[test]
    fn names_stay_to_a_shape_that_cannot_smuggle_anything() {
        assert!(PluginSecretKey::validate_name("notion").is_ok());
        assert!(PluginSecretKey::validate_name("notion-api_2").is_ok());

        assert!(PluginSecretKey::validate_name("").is_err());
        assert!(PluginSecretKey::validate_name("has space").is_err());
        assert!(PluginSecretKey::validate_name("has:colon").is_err());
        assert!(PluginSecretKey::validate_name(&"x".repeat(65)).is_err());
    }
}
