//! Durable continuations for read-only sandbox programs. Only the host applies effects.
use super::{
    connection_state::{self, Acknowledgement, Checkpoint, State},
    external::{self, ExternalHost, ExternalIntent},
    js_runtime::{embedded_runtime, PluginHost},
    plan::{Problem, Severity},
};
use atomic_lib::{db::trees::Tree, Db};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Effect {
    External {
        id: String,
        request: ExternalIntent,
    },
    Atomic {
        id: String,
        verdict: Value,
    },
    Checkpoint {
        id: String,
        records: Vec<Acknowledgement>,
    },
}
impl Effect {
    fn id(&self) -> &str {
        match self {
            Self::External { id, .. } | Self::Atomic { id, .. } | Self::Checkpoint { id, .. } => id,
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Output {
    Preview {
        proposal: Value,
        problems: Vec<Problem>,
    },
    Effect {
        effect: Effect,
        cursor: Value,
    },
    Continue {
        cursor: Value,
    },
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Pending {
    pub effect: Effect,
    pub cursor: Value,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub run: String,
    pub started_at: i64,
    pub release: String,
    pub config: Value,
    #[serde(default)]
    pub binding_required: bool,
    pub connection: State,
    pub proposal: Value,
    pub problems: Vec<Problem>,
    pub cursor: Value,
    pub result: Value,
    pub pending: Option<Pending>,
    pub completed: BTreeSet<String>,
    pub approved_by: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub checkpointed: bool,
}

fn key(drive: &str, plugin: &str) -> String {
    format!("plugin-sync/v1/{}", json!([drive, plugin]))
}
pub fn read(db: &Db, drive: &str, plugin: &str) -> Result<Option<Session>, String> {
    db.kv
        .get(Tree::PluginMeta, key(drive, plugin).as_bytes())
        .map_err(|e| e.to_string())?
        .map(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        .transpose()
}
fn save(db: &Db, drive: &str, plugin: &str, session: &Session) -> Result<(), String> {
    let bytes = serde_json::to_vec(session).map_err(|e| e.to_string())?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("sync session exceeds eight MiB".into());
    }
    db.kv
        .insert(Tree::PluginMeta, key(drive, plugin).as_bytes(), &bytes)
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())
}
async fn invoke<H: PluginHost>(
    source: &str,
    session: &Session,
    phase: &str,
    host: H,
) -> Result<Output, String> {
    let input = json!({"trigger":{"kind":"manual","at":session.started_at},"phase":phase,"config":session.config,"connection":session.connection,"proposal":session.proposal,"cursor":session.cursor,"result":session.result});
    let raw = embedded_runtime()
        .map_err(|e| e.to_string())?
        .run(source, &input.to_string(), host)
        .await
        .map_err(|e| e.to_string())??;
    serde_json::from_str(&raw).map_err(|e| format!("invalid sync output: {e}"))
}
pub async fn preview<H: PluginHost>(
    db: &Db,
    drive: &str,
    plugin: &str,
    release: &str,
    config: Value,
    host: H,
) -> Result<Session, String> {
    let _guard = db.lock_plugin(&key(drive, plugin)).await;
    if read(db, drive, plugin)?.is_some_and(|s| s.approved_by.is_some() && s.status != "complete") {
        return Err("resume the existing approved sync first".into());
    }
    let binding_required =
        super::release_binding::require_current(db, drive, plugin, release, &config, false).await?;
    let package = db.get_plugin_release(release).map_err(|e| e.to_string())?;
    let mut session = Session {
        started_at: atomic_lib::utils::now(),
        run: atomic_lib::utils::random_string(40),
        release: release.into(),
        config,
        binding_required,
        connection: connection_state::read_resolved(db, drive, plugin).await?,
        proposal: Value::Null,
        problems: vec![],
        cursor: Value::Null,
        result: Value::Null,
        pending: None,
        completed: BTreeSet::new(),
        approved_by: None,
        status: "preview".into(),
        error: None,
        checkpointed: false,
    };
    match invoke(&package.source, &session, "preview", host).await? {
        Output::Preview { proposal, problems } => {
            session.proposal = proposal;
            session.problems = problems;
        }
        _ => return Err("preview must not propose an executable effect".into()),
    }
    save(db, drive, plugin, &session)?;
    Ok(session)
}
/// Caller supplies the already-authorized account and an Atomic host with that
/// account's write scope. Provider logic cannot access either mutation host.
pub async fn advance<H, A>(
    db: &Db,
    drive: &str,
    plugin: &str,
    run: &str,
    actor: &str,
    mut host: H,
    atomic: &mut A,
) -> Result<Session, String>
where
    H: PluginHost + ExternalHost + Clone,
    A: super::plan::PlanHost + super::apply::ApplyHost,
{
    let _guard = db.lock_plugin(&key(drive, plugin)).await;
    let mut session = read(db, drive, plugin)?.ok_or("no preview exists")?;
    if session.run != run {
        return Err("preview was replaced; review the current run".into());
    }
    if session
        .problems
        .iter()
        .any(|p| p.severity == Severity::Error)
    {
        return Err("resolve preview errors before approval".into());
    }
    if session.approved_by.as_deref().is_some_and(|a| a != actor) {
        return Err("resume requires the original approving account".into());
    }
    if session.status == "complete" {
        return Ok(session);
    }
    if session.approved_by.is_none() {
        session.binding_required = super::release_binding::require_current(
            db,
            drive,
            plugin,
            &session.release,
            &session.config,
            session.binding_required,
        )
        .await?;
    }
    session.approved_by = Some(actor.into());
    session.status = "running".into();
    session.error = None;
    save(db, drive, plugin, &session)?;
    let package = db
        .get_plugin_release(&session.release)
        .map_err(|e| e.to_string())?;
    let connection = json!([drive, plugin]).to_string();
    let execution: Result<(), String> = async {
        for _ in 0..32 {
            if let Some(pending) = session.pending.clone() {
                let id = pending.effect.id();
                let result = match &pending.effect {
                    Effect::External { request, .. } => {
                        if connection_state::read_resolved(db, drive, plugin)
                            .await?
                            .revision
                            != session.connection.revision
                        {
                            return Err("connection changed during sync".into());
                        }
                        serde_json::to_value(
                            external::execute(
                                db,
                                &connection,
                                &session.release,
                                run,
                                request,
                                &mut host,
                            )
                            .await?,
                        )
                        .map_err(|e| e.to_string())?
                    }
                    Effect::Atomic { verdict, .. } => {
                        if connection_state::read_resolved(db, drive, plugin)
                            .await?
                            .revision
                            != session.connection.revision
                        {
                            return Err("connection changed during sync".into());
                        }
                        let journal = super::journal::Journal::new(
                            db,
                            drive,
                            plugin,
                            &json!([run, id]).to_string(),
                        );
                        let plan =
                            journal.plan(&super::plan::plan_verdict(verdict, atomic).await)?;
                        let report = super::apply::apply_plan_recorded(
                            &plan,
                            atomic,
                            Default::default(),
                            Some(&journal),
                        )
                        .await?;
                        if report.failed > 0 || report.stopped_early {
                            return Err(
                                "Atomic effect failed; inspect its durable journal before recovery"
                                    .into(),
                            );
                        }
                        serde_json::to_value(report).map_err(|e| e.to_string())?
                    }
                    Effect::Checkpoint { records, .. } => {
                        let state = connection_state::checkpoint_once(
                            db,
                            drive,
                            plugin,
                            Checkpoint {
                                revision: session.connection.revision,
                                records: records.clone(),
                                cursor: None,
                            },
                            Some(&json!([run, id]).to_string()),
                        )
                        .await?;
                        session.checkpointed = true;
                        serde_json::to_value(state).map_err(|e| e.to_string())?
                    }
                };
                session.result = result;
                session.cursor = pending.cursor;
                session.completed.insert(id.into());
                session.pending = None;
                save(db, drive, plugin, &session)?;
            } else {
                match invoke(&package.source, &session, "step", host.clone()).await? {
                    Output::Effect { effect, cursor } => {
                        if session.checkpointed
                            || effect.id().is_empty()
                            || effect.id().len() > 256
                            || session.completed.contains(effect.id())
                        {
                            return Err("invalid or repeated effect identity".into());
                        }
                        if let Effect::External { id, request } = &effect {
                            if id != &request.id {
                                return Err("external identity mismatch".into());
                            }
                        }
                        session.pending = Some(Pending { effect, cursor });
                    }
                    Output::Continue { cursor } => session.cursor = cursor,
                    Output::Complete => {
                        if !session.checkpointed {
                            return Err("completion requires an acknowledged checkpoint".into());
                        }
                        session.status = "complete".into();
                        save(db, drive, plugin, &session)?;
                        return Ok(());
                    }
                    Output::Preview { .. } => {
                        return Err("unexpected preview during an approved sync".into())
                    }
                }
                save(db, drive, plugin, &session)?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = execution {
        session.status = "error".into();
        session.error = Some(error);
        save(db, drive, plugin, &session)?;
    }
    Ok(session)
}
