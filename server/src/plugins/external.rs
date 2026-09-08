//! Durable external writes. Preview has no access to this executor.
use atomic_lib::{db::trees::Tree, Db};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIntent {
    pub id: String,
    pub operation: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub status: u16,
    pub body: String,
}
#[derive(Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived: Option<JournalArchive>,
    pub intent: ExternalIntent,
    pub receipt: Option<Receipt>,
    #[serde(default)]
    pub resolution: Option<Resolution>,
}

#[derive(Serialize, Deserialize)]
pub struct JournalArchive {
    pub at: i64,
    pub payload_hash: String,
}

/// An operator assertion after checking the provider, not automatic verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub actor: String,
    pub evidence: String,
    pub at: i64,
}

pub(super) fn key(connection: &str, release: &str, run: &str, intent: &str) -> String {
    let identity = serde_json::json!([connection, release, run, intent]).to_string();
    format!("plugin-external/v1/{identity}")
}

pub fn inspect(
    db: &Db,
    connection: &str,
    release: &str,
    run: &str,
    intent: &str,
) -> Result<Option<Entry>, String> {
    db.kv
        .get(
            Tree::PluginMeta,
            key(connection, release, run, intent).as_bytes(),
        )
        .map_err(|e| e.to_string())?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
        .transpose()
}

/// Only a missing receipt can be resolved. This never authorizes another send.
pub async fn confirm_applied(
    db: &Db,
    connection: &str,
    release: &str,
    run: &str,
    intent: &str,
    receipt: Receipt,
    resolution: Resolution,
) -> Result<(), String> {
    successful(receipt.clone())?;
    if resolution.evidence.trim().is_empty() || resolution.evidence.len() > 8192 {
        return Err("provider evidence must be nonempty and at most 8192 bytes".into());
    }
    if receipt.body.len() > 1024 * 1024 {
        return Err("receipt exceeds one MiB".into());
    }
    let _execution = db.lock_plugin(&format!("external:{connection}")).await;
    let mut entry =
        inspect(db, connection, release, run, intent)?.ok_or("operation does not exist")?;
    if entry.receipt.is_some() {
        return Err("operation already has a receipt; it cannot be overwritten".into());
    }
    entry.settled_at = Some(atomic_lib::utils::now());
    entry.receipt = Some(receipt);
    entry.resolution = Some(resolution);
    db.kv
        .insert(
            Tree::PluginMeta,
            key(connection, release, run, intent).as_bytes(),
            &serde_json::to_vec(&entry).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())
}

#[async_trait::async_trait]
pub trait ExternalHost: Send {
    async fn execute(&mut self, intent: &ExternalIntent) -> Result<Receipt, String>;
}
#[async_trait::async_trait]
impl ExternalHost for super::js_runtime::StoreHost {
    async fn execute(&mut self, intent: &ExternalIntent) -> Result<Receipt, String> {
        let response = self
            .request(
                serde_json::to_string(intent).map_err(|e| e.to_string())?,
                "write",
            )
            .await?;
        serde_json::from_str(&response).map_err(|e| e.to_string())
    }
}

// One in-process executor; no distributed worker or queue service is required.

pub async fn execute(
    db: &Db,
    connection: &str,
    release: &str,
    run: &str,
    intent: &ExternalIntent,
    host: &mut impl ExternalHost,
) -> Result<Receipt, String> {
    if intent.id.is_empty() || run.is_empty() {
        return Err("run and intent IDs must be nonempty".into());
    }
    let _execution = db.lock_plugin(&format!("external:{connection}")).await;
    let key = key(connection, release, run, &intent.id);
    if let Some(bytes) = db
        .kv
        .get(Tree::PluginMeta, key.as_bytes())
        .map_err(|e| e.to_string())?
    {
        let entry: Entry = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if entry.archived.is_some() {
            return Err(
                "operation receipt was archived; its identity remains permanently reserved".into(),
            );
        }
        if entry.intent != *intent {
            return Err(
                "an existing operation identity cannot be reused for another request".into(),
            );
        }
        let receipt = entry
            .receipt
            .ok_or_else(|| "remote outcome is uncertain; reconcile before retrying".to_string())?;
        return successful(receipt);
    }
    let mut entry = Entry {
        settled_at: None,
        archived: None,
        intent: intent.clone(),
        receipt: None,
        resolution: None,
    };
    db.kv
        .insert(
            Tree::PluginMeta,
            key.as_bytes(),
            &serde_json::to_vec(&entry).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    let receipt = host.execute(intent).await?;
    entry.settled_at = Some(atomic_lib::utils::now());
    entry.receipt = Some(receipt.clone());
    db.kv
        .insert(
            Tree::PluginMeta,
            key.as_bytes(),
            &serde_json::to_vec(&entry).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    successful(receipt)
}

fn successful(receipt: Receipt) -> Result<Receipt, String> {
    if !(200..300).contains(&receipt.status) {
        return Err(format!(
            "remote returned {}; reconcile before retrying",
            receipt.status
        ));
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Provider {
        writes: usize,
        lose_response: bool,
    }
    #[async_trait::async_trait]
    impl ExternalHost for Provider {
        async fn execute(&mut self, _: &ExternalIntent) -> Result<Receipt, String> {
            self.writes += 1;
            if self.lose_response {
                return Err("connection closed after write".into());
            }
            Ok(Receipt {
                status: 201,
                body: "created".into(),
            })
        }
    }
    fn intent() -> ExternalIntent {
        ExternalIntent {
            id: "record-1".into(),
            operation: "create".into(),
            method: "POST".into(),
            url: "https://provider.test/records".into(),
            headers: BTreeMap::new(),
            body: Some("{}".into()),
        }
    }
    #[tokio::test]
    async fn repeated_delivery_reuses_the_receipt() {
        let db = Db::init_temp("external_receipt").await.unwrap();
        let mut host = Provider {
            writes: 0,
            lose_response: false,
        };
        execute(&db, "connection", "release", "run", &intent(), &mut host)
            .await
            .unwrap();
        execute(&db, "connection", "release", "run", &intent(), &mut host)
            .await
            .unwrap();
        assert_eq!(host.writes, 1);
        let mut changed = intent();
        changed.body = Some("changed".into());
        assert!(
            execute(&db, "connection", "release", "run", &changed, &mut host)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn a_lost_response_does_not_repeat_the_remote_write() {
        let db = Db::init_temp("external_uncertain").await.unwrap();
        let mut host = Provider {
            writes: 0,
            lose_response: true,
        };
        assert!(
            execute(&db, "connection", "release", "run", &intent(), &mut host)
                .await
                .is_err()
        );
        assert!(
            execute(&db, "connection", "release", "run", &intent(), &mut host)
                .await
                .unwrap_err()
                .contains("uncertain")
        );
        assert_eq!(host.writes, 1);
    }
    #[tokio::test]
    async fn confirmed_provider_result_recovers_without_resending() {
        let db = Db::init_temp("external_resolve").await.unwrap();
        let mut host = Provider {
            writes: 0,
            lose_response: true,
        };
        assert!(execute(&db, "c", "v", "r", &intent(), &mut host)
            .await
            .is_err());
        let resolution = Resolution {
            actor: "operator".into(),
            evidence: "Provider audit record 123".into(),
            at: 42,
        };
        let receipt = Receipt {
            status: 201,
            body: "record-123".into(),
        };
        assert!(inspect(&db, "other", "v", "r", "record-1")
            .unwrap()
            .is_none());
        let mut empty = resolution.clone();
        empty.evidence.clear();
        assert!(
            confirm_applied(&db, "c", "v", "r", "record-1", receipt.clone(), empty)
                .await
                .is_err()
        );
        confirm_applied(
            &db,
            "c",
            "v",
            "r",
            "record-1",
            receipt.clone(),
            resolution.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            execute(&db, "c", "v", "r", &intent(), &mut host)
                .await
                .unwrap()
                .body,
            "record-123"
        );
        assert_eq!(host.writes, 1);
        assert_eq!(
            inspect(&db, "c", "v", "r", "record-1")
                .unwrap()
                .unwrap()
                .resolution
                .unwrap()
                .actor,
            "operator"
        );
        assert!(
            confirm_applied(&db, "c", "v", "r", "record-1", receipt, resolution)
                .await
                .is_err()
        );
    }
}
