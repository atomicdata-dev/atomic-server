//! A durable plan and per-effect receipts. An attempted effect with no receipt
//! is uncertain and cannot be repeated until reconciled.
use super::{apply::ChangeOutcome, plan::RunPlan};
use atomic_lib::{db::trees::Tree, Db};

pub struct Journal {
    db: Db,
    prefix: String,
}
impl Journal {
    pub fn new(db: &Db, drive: &str, plugin: &str, run: &str) -> Self {
        let identity = serde_json::json!([drive, plugin, run]).to_string();
        // JSON tuple encoding makes namespace boundaries unambiguous.
        Self {
            db: db.clone(),
            prefix: format!("plugin-journal/v1/{identity}/"),
        }
    }
    /// A terminal receipt is written only after every effect and the run log
    /// succeeded. Queue/schedule acknowledgement may safely be retried after it.
    pub fn finished(&self) -> Result<Option<serde_json::Value>, String> {
        self.db
            .kv
            .get(
                Tree::PluginMeta,
                format!("{}finished", self.prefix).as_bytes(),
            )
            .map_err(|e| e.to_string())?
            .map(|v| serde_json::from_slice(&v).map_err(|e| e.to_string()))
            .transpose()
    }
    pub fn abandoned(&self) -> Result<Option<serde_json::Value>, String> {
        self.db
            .kv
            .get(
                Tree::PluginMeta,
                format!("{}abandoned", self.prefix).as_bytes(),
            )
            .map_err(|e| e.to_string())?
            .map(|v| serde_json::from_slice(&v).map_err(|e| e.to_string()))
            .transpose()
    }
    pub fn terminal(&self) -> Result<Option<serde_json::Value>, String> {
        match self.finished()? {
            Some(v) => Ok(Some(v)),
            None => self.abandoned(),
        }
    }
    /// Caller serializes with the worker before making a run terminal.
    pub fn abandon(&self, actor: &str, reason: &str) -> Result<(), String> {
        if reason.trim().is_empty() || reason.len() > 8192 {
            return Err("a reason of 1 to 8192 bytes is required".into());
        }
        if self.finished()?.is_some() {
            return Err("run already completed successfully".into());
        }
        if self.abandoned()?.is_some() {
            return Ok(());
        }
        self.db.kv.insert(Tree::PluginMeta, format!("{}abandoned", self.prefix).as_bytes(),
            &serde_json::to_vec(&serde_json::json!({"at":atomic_lib::utils::now(),"actor":actor,"reason":reason,"state":"abandoned"})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        self.db.flush().map_err(|e| e.to_string())
    }
    fn refuse_abandoned(&self) -> Result<(), String> {
        if self.abandoned()?.is_some() {
            return Err("automation run was explicitly abandoned; it cannot resume".into());
        }
        Ok(())
    }
    pub fn finish(&self, summary: &str) -> Result<(), String> {
        self.refuse_abandoned()?;
        if self.finished()?.is_some() {
            return Ok(());
        }
        if !self
            .db
            .kv
            .contains_key(Tree::PluginMeta, format!("{}plan", self.prefix).as_bytes())
            .map_err(|e| e.to_string())?
        {
            return Err("cannot finish a run without its durable plan".into());
        }
        self.db
            .kv
            .insert(
                Tree::PluginMeta,
                format!("{}finished", self.prefix).as_bytes(),
                &serde_json::to_vec(
                    &serde_json::json!({"at":atomic_lib::utils::now(),"summary":summary}),
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.db.flush().map_err(|e| e.to_string())
    }
    pub fn plan(&self, candidate: &RunPlan) -> Result<RunPlan, String> {
        self.refuse_abandoned()?;
        let key = format!("{}plan", self.prefix);
        if let Some(bytes) = self
            .db
            .kv
            .get(Tree::PluginMeta, key.as_bytes())
            .map_err(|e| e.to_string())?
        {
            return serde_json::from_slice(&bytes).map_err(|e| e.to_string());
        }
        self.db
            .kv
            .insert(
                Tree::PluginMeta,
                key.as_bytes(),
                &serde_json::to_vec(candidate).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.db.flush().map_err(|e| e.to_string())?;
        Ok(candidate.clone())
    }
    pub fn begin(&self, index: usize) -> Result<Option<ChangeOutcome>, String> {
        self.refuse_abandoned()?;
        let key = format!("{}effect/{index}", self.prefix);
        if let Some(bytes) = self
            .db
            .kv
            .get(Tree::PluginMeta, key.as_bytes())
            .map_err(|e| e.to_string())?
        {
            if bytes == b"uncertain" {
                return Err(format!(
                    "effect {index} may already have been applied; reconcile before retrying"
                ));
            }
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| e.to_string());
        }
        self.db
            .kv
            .insert(Tree::PluginMeta, key.as_bytes(), b"uncertain")
            .map_err(|e| e.to_string())?;
        self.db.flush().map_err(|e| e.to_string())?;
        Ok(None)
    }
    pub fn complete(&self, index: usize, outcome: &ChangeOutcome) -> Result<(), String> {
        let key = format!("{}effect/{index}", self.prefix);
        self.db
            .kv
            .insert(
                Tree::PluginMeta,
                key.as_bytes(),
                &serde_json::to_vec(outcome).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.db.flush().map_err(|e| e.to_string())
    }
}
