//! Single-use outbound credential retrieval. The initiating server keeps `proof`
//! private; browsers receive only the public attempt ID. Transport must authenticate
//! the server and derive the binding, never trust a browser-supplied binding.
use atomic_lib::{
    db::{
        plugin_secret::{PluginSecret, PluginSecretKey},
        trees::Tree,
    },
    Db,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, String>;
const PREFIX: &str = "oauth-handoff/v1/";
const ORIGIN: &str = "https://atomic.invalid/oauth-handoff";
const TTL: i64 = 600_000;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub server: String,
    pub actor: String,
    pub drive: String,
    pub provider: String,
    pub attempt: String,
}
#[derive(Serialize, Deserialize)]
struct Record {
    binding: Binding,
    proof_hash: String,
    expires: i64,
    ready: bool,
    consumed: bool,
    #[serde(default)]
    exchange_started: bool,
}
/// Deliberately not Debug or Serialize: proof belongs only on the initiating host.
pub struct Ticket {
    pub id: String,
    pub proof: String,
}
fn random() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn key(id: &str) -> String {
    format!("{PREFIX}{id}")
}
fn secret_key(id: &str) -> PluginSecretKey {
    PluginSecretKey::new("oauth-handoff", id, "credentials")
}
fn read(db: &Db, id: &str) -> Result<Record> {
    let bytes = db
        .kv
        .get(Tree::PluginMeta, key(id).as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("Authorization handoff not found")?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid handoff record".into())
}
fn write(db: &Db, id: &str, r: &Record) -> Result<()> {
    db.kv
        .insert(
            Tree::PluginMeta,
            key(id).as_bytes(),
            &serde_json::to_vec(r).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())
}
fn active(r: &Record, at: i64) -> Result<()> {
    if r.consumed {
        return Err("Authorization handoff already consumed".into());
    }
    if at >= r.expires {
        return Err("Authorization handoff expired".into());
    }
    Ok(())
}
/// Called only after authenticating the initiating server. Limits/quota belong
/// to the transport adapter. No callback URL is accepted, avoiding callback SSRF.
pub fn begin(db: &Db, binding: Binding, at: i64) -> Result<Ticket> {
    if [
        &binding.server,
        &binding.actor,
        &binding.drive,
        &binding.provider,
        &binding.attempt,
    ]
    .iter()
    .any(|s| s.is_empty() || s.len() > 2048)
    {
        return Err("Invalid authorization binding".into());
    }
    if !db.has_node_key() {
        return Err("Authorization handoff requires encrypted secret storage".into());
    }
    let ticket = Ticket {
        id: random(),
        proof: random(),
    };
    let record = Record {
        binding,
        proof_hash: blake3::hash(ticket.proof.as_bytes()).to_hex().to_string(),
        expires: at.checked_add(TTL).ok_or("Invalid handoff time")?,
        ready: false,
        consumed: false,
        exchange_started: false,
    };
    write(db, &ticket.id, &record)?;
    Ok(ticket)
}
/// Claim a provider callback exactly once before exchanging its code.
/// The random ID is the OAuth state; this reveals no retrieval proof.
pub async fn claim_callback(db: &Db, id: &str, at: i64) -> Result<Binding> {
    let _lock = db.lock_plugin(&key(id)).await;
    let mut record = read(db, id)?;
    active(&record, at)?;
    if record.exchange_started || record.ready {
        return Err("Authorization callback already handled".into());
    }
    record.exchange_started = true;
    write(db, id, &record)?;
    Ok(record.binding)
}
/// Called by the authorization service after validating provider state and
/// exchanging the code. Credentials are wrapped at rest, never stored in metadata.
pub async fn complete(
    db: &Db,
    id: &str,
    binding: &Binding,
    credentials: &str,
    at: i64,
) -> Result<()> {
    let _lock = db.lock_plugin(&key(id)).await;
    let mut record = read(db, id)?;
    active(&record, at)?;
    if &record.binding != binding {
        return Err("Authorization binding mismatch".into());
    }
    if record.ready {
        return Err("Authorization handoff already completed".into());
    }
    if credentials.is_empty() || credentials.len() > 65536 {
        return Err("Invalid credential payload".into());
    }
    db.set_plugin_secret(
        &secret_key(id),
        &PluginSecret::new(credentials.into(), vec![ORIGIN.into()], at),
    )
    .map_err(|e| e.to_string())?;
    record.ready = true;
    write(db, id, &record)
}
/// Consume before handing bytes to transport. If delivery is lost, require a
/// fresh authorization; replay must never deliver credentials a second time.
/// None means still waiting, and does not consume the ticket.
pub async fn redeem(
    db: &Db,
    id: &str,
    proof: &str,
    binding: &Binding,
    at: i64,
) -> Result<Option<String>> {
    let _lock = db.lock_plugin(&key(id)).await;
    let mut record = read(db, id)?;
    if record.binding != *binding
        || blake3::hash(proof.as_bytes()).to_hex().as_str() != record.proof_hash
    {
        return Err("Authorization binding or retrieval proof mismatch".into());
    }
    active(&record, at)?;
    if !record.ready {
        return Ok(None);
    }
    let payload = db
        .use_plugin_secret(&secret_key(id), ORIGIN, at, |v| v.to_owned())
        .map_err(|e| e.to_string())?
        .ok_or("Authorization credentials unavailable")?;
    record.consumed = true;
    write(db, id, &record)?;
    db.delete_plugin_secret(&secret_key(id))
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    Ok(Some(payload))
}
/// Remove expired credentials and records. A service deployment must schedule
/// this; it is also useful after restart. Iteration is bounded per invocation.
pub struct CleanupPage {
    pub removed: usize,
    pub next: Option<String>,
}
pub async fn cleanup(db: &Db, at: i64, limit: usize, after: Option<&str>) -> Result<CleanupPage> {
    if limit == 0 || limit > 1000 {
        return Err("Cleanup limit must be 1..1000".into());
    }
    let mut start = PREFIX.as_bytes().to_vec();
    if let Some(id) = after {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid cleanup cursor".into());
        }
        start = key(id).into_bytes();
        start.push(0);
    }
    let entries = db
        .kv
        .range_page(
            Tree::PluginMeta,
            start,
            format!("{PREFIX}~").into_bytes(),
            limit + 1,
        )
        .map_err(|e| e.to_string())?;
    let more = entries.len() > limit;
    let mut next = None;
    let mut removed = 0;
    for (k, _) in entries.into_iter().take(limit) {
        let full = String::from_utf8(k).map_err(|_| "Invalid handoff key")?;
        let id = full.strip_prefix(PREFIX).ok_or("Invalid handoff key")?;
        if more {
            next = Some(id.to_string());
        }
        let _lock = db.lock_plugin(&key(id)).await;
        // Another cleanup can remove an entry between the page read and lock.
        if !db
            .kv
            .contains_key(Tree::PluginMeta, key(id).as_bytes())
            .map_err(|e| e.to_string())?
        {
            continue;
        }
        let r = read(db, id)?;
        if r.expires <= at || r.consumed {
            db.delete_plugin_secret(&secret_key(id))
                .map_err(|e| e.to_string())?;
            db.kv
                .remove(Tree::PluginMeta, key(id).as_bytes())
                .map_err(|e| e.to_string())?;
            removed += 1;
        }
    }
    db.flush().map_err(|e| e.to_string())?;
    Ok(CleanupPage { removed, next })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            server: "server-key".into(),
            actor: "alice".into(),
            drive: "drive".into(),
            provider: "notion".into(),
            attempt: "login".into(),
        }
    }
    async fn db(name: &str) -> Db {
        let d = Db::init_temp(name).await.unwrap();
        d.set_node_key([8; 32]);
        d
    }
    #[tokio::test]
    async fn retrieval_is_bound_private_and_single_use() {
        let db = db("handoff_single").await;
        let b = binding();
        let t = begin(&db, b.clone(), 0).unwrap();
        assert_eq!(redeem(&db, &t.id, &t.proof, &b, 1).await.unwrap(), None);
        complete(&db, &t.id, &b, "private-token", 2).await.unwrap();
        for field in 0..5 {
            let mut wrong = b.clone();
            match field {
                0 => wrong.server.push('x'),
                1 => wrong.actor.push('x'),
                2 => wrong.drive.push('x'),
                3 => wrong.provider.push('x'),
                _ => wrong.attempt.push('x'),
            };
            assert!(redeem(&db, &t.id, &t.proof, &wrong, 3).await.is_err());
        }
        assert!(redeem(&db, &t.id, "wrong", &b, 3).await.is_err());
        let meta = db
            .kv
            .get(Tree::PluginMeta, key(&t.id).as_bytes())
            .unwrap()
            .unwrap();
        let text = String::from_utf8(meta).unwrap();
        assert!(!text.contains("private-token"));
        assert!(!text.contains(&t.proof));
        assert_eq!(
            redeem(&db, &t.id, &t.proof, &b, 3).await.unwrap(),
            Some("private-token".into())
        );
        assert!(redeem(&db, &t.id, &t.proof, &b, 4).await.is_err());
        assert!(db
            .get_plugin_secret_info(&secret_key(&t.id))
            .unwrap()
            .is_none());
    }
    #[tokio::test]
    async fn expiry_cleanup_and_duplicate_completion() {
        let db = db("handoff_expiry").await;
        let b = binding();
        let t = begin(&db, b.clone(), 0).unwrap();
        complete(&db, &t.id, &b, "token", 1).await.unwrap();
        assert!(complete(&db, &t.id, &b, "replacement", 2).await.is_err());
        assert!(redeem(&db, &t.id, &t.proof, &b, TTL).await.is_err());
        assert_eq!(cleanup(&db, TTL, 100, None).await.unwrap().removed, 1);
        assert!(db
            .get_plugin_secret_info(&secret_key(&t.id))
            .unwrap()
            .is_none());
    }
    #[tokio::test]
    async fn cleanup_pages_past_active_entries() {
        let db = db("handoff_cleanup_page").await;
        for _ in 0..5 {
            begin(&db, binding(), 0).unwrap();
        }
        let mut cursor = None;
        let mut visits = 0;
        loop {
            let page = cleanup(&db, 1, 2, cursor.as_deref()).await.unwrap();
            assert_eq!(page.removed, 0);
            visits += 1;
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
            assert!(visits < 4);
        }
        assert_eq!(visits, 3);
    }
    #[tokio::test]
    async fn concurrent_redeemers_have_one_winner() {
        let db = db("handoff_race").await;
        let b = binding();
        let t = begin(&db, b.clone(), 0).unwrap();
        complete(&db, &t.id, &b, "token", 1).await.unwrap();
        let (a, c) = tokio::join!(
            redeem(&db, &t.id, &t.proof, &b, 2),
            redeem(&db, &t.id, &t.proof, &b, 2)
        );
        assert_ne!(a.is_ok(), c.is_ok());
    }
}
