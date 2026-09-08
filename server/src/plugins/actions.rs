//! Named integration actions. All callers share validation, release pinning and journals.
use super::{
    external::{self, ExternalIntent, Receipt},
    js_runtime::{embedded_runtime, NoCapabilities, StoreHost},
    manifest::Manifest,
    scheduler::drive_terms,
};
use atomic_lib::{
    db::trees::{Method, Operation, Tree},
    Storelike,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Action {
    pub name: String,
    pub title: String,
    pub description: String,
    pub operation: String,
    pub input_schema: InputSchema,
}
/// Deliberately bounded JSON Schema subset; unsupported keywords are rejected.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputSchema {
    pub r#type: String,
    pub properties: BTreeMap<String, Field>,
    #[serde(default)]
    pub required: Vec<String>,
    pub additional_properties: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub r#type: String,
    pub description: String,
}
impl InputSchema {
    pub fn validate(&self, args: &Value) -> Result<(), String> {
        let args = args
            .as_object()
            .ok_or("action arguments must be an object")?;
        if serde_json::to_vec(args).map_err(|e| e.to_string())?.len() > 65536 {
            return Err("action arguments exceed 64 KiB".into());
        }
        if self.required.iter().any(|p| !args.contains_key(p)) {
            return Err("missing required action argument".into());
        }
        for (name, value) in args {
            let field = self.properties.get(name).ok_or("unknown action argument")?;
            let valid = match field.r#type.as_str() {
                "string" => value.is_string(),
                "integer" => value.is_i64() || value.is_u64(),
                "boolean" => value.is_boolean(),
                _ => false,
            };
            if !valid {
                return Err(format!("invalid type for action argument {name}"));
            }
        }
        Ok(())
    }
}
pub fn validate_actions(manifest: &Manifest) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    if manifest.actions.len() > 64 {
        return Err("at most 64 actions per release".into());
    }
    for a in &manifest.actions {
        if a.name.is_empty()
            || a.name.len() > 128
            || !a
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !seen.insert(&a.name)
            || a.title.is_empty()
            || a.description.len() > 8192
        {
            return Err("invalid or duplicate action name/description".into());
        }
        if !manifest.operations.iter().any(|o| o.id == a.operation) {
            return Err("action references an undeclared operation".into());
        }
        let s = &a.input_schema;
        if s.r#type != "object"
            || s.additional_properties
            || s.properties.len() > 32
            || s.required.iter().any(|p| !s.properties.contains_key(p))
            || s.properties
                .values()
                .any(|p| !matches!(p.r#type.as_str(), "string" | "integer" | "boolean"))
        {
            return Err("unsupported action input schema".into());
        }
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub action: String,
    pub arguments: Value,
    /// Stable per logical call; retry with the same ID, never after an uncertain write.
    pub id: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Proposal {
    #[serde(default)]
    pub consumers_tracked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived: Option<Archive>,
    #[serde(default)]
    pub origin: Option<Origin>,
    pub id: String,
    pub action: String,
    pub title: String,
    pub arguments: Value,
    pub actor: String,
    pub release: String,
    pub config: Value,
    pub created_at: i64,
    pub intent: ExternalIntent,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Archive {
    pub at: i64,
    pub state: String,
    pub payload_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Binding {
    pub release: String,
    pub config: Value,
}
pub async fn binding(host: &StoreHost) -> Result<Binding, String> {
    host.validate_binding().await?;
    let terms = drive_terms(&host.db, &host.drive)
        .await
        .ok_or("drive schema unavailable")?;
    let property = terms
        .property("plugin-connection")
        .ok_or("not an integration connection")?;
    let resource = host
        .db
        .get_resource(&host.plugin.as_str().into())
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_str(
        &resource
            .get(property)
            .map_err(|e| e.to_string())?
            .to_string(),
    )
    .map_err(|e| format!("invalid connection: {e}"))
}
fn prefix(host: &StoreHost) -> String {
    format!(
        "integration-action/v1/{}/",
        json!([host.drive, host.plugin])
    )
}
fn key(host: &StoreHost, id: &str) -> String {
    format!("{}{id}", prefix(host))
}
fn saved(host: &StoreHost, id: &str) -> Result<Option<Proposal>, String> {
    host.db
        .kv
        .get(Tree::PluginMeta, key(host, id).as_bytes())
        .map_err(|e| e.to_string())?
        .map(|v| serde_json::from_slice(&v).map_err(|e| e.to_string()))
        .transpose()
}
pub async fn list(host: &StoreHost) -> Result<Value, String> {
    let bound = binding(host).await?;
    let package = host
        .db
        .get_plugin_release(&bound.release)
        .map_err(|e| e.to_string())?;
    let manifest = Manifest::parse(package.manifest)?.ok_or("versioned release required")?;
    let tools=manifest.actions.iter().map(|a|json!({"name":a.name,"title":a.title,"description":a.description,"inputSchema":a.input_schema,"annotations":{"readOnlyHint":manifest.operations.iter().find(|o|o.id==a.operation).unwrap().effect=="read","openWorldHint":true}})).collect::<Vec<_>>();
    Ok(json!({"release":bound.release,"tools":tools}))
}
fn review(p: &Proposal) -> Value {
    json!({"status":"needs_review","proposal":p})
}
pub async fn invoke(host: StoreHost, call: Call) -> Result<Value, String> {
    invoke_scoped(host, call, None, false).await
}
async fn invoke_scoped(
    host: StoreHost,
    call: Call,
    origin: Option<Origin>,
    automatic: bool,
) -> Result<Value, String> {
    invoke_consumed(host, call, origin, automatic, None).await
}
async fn invoke_consumed(
    mut host: StoreHost,
    call: Call,
    origin: Option<Origin>,
    _automatic: bool,
    consumer: Option<&str>,
) -> Result<Value, String> {
    if call.id.is_empty()
        || call.id.len() > 128
        || !call
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err("invalid call ID".into());
    }
    let lock_db = host.db.clone();
    let _lock = lock_db
        .lock_plugin(&format!("actions:{}", prefix(&host)))
        .await;
    let bound = binding(&host).await?;
    let automatic = if let Some(origin) = &origin {
        let grant = valid_grant(&host, origin, &call.action, &bound).await?;
        if super::store_host::app_signing_for(&host.db, &host.drive, &origin.caller)
            .await?
            .is_some()
            && grant.is_none()
        {
            return Err("app-scoped caller needs an explicit integration action grant".into());
        }
        _automatic && grant.is_some_and(|g| g.mode == "automatic")
    } else {
        false
    };

    if let Some(mut p) = saved(&host, &call.id)? {
        if p.archived.is_some() {
            return Err(
                "call ID is permanently reserved by an archived action; use a new ID".into(),
            );
        }
        if p.actor != host.for_agent.to_string()
            || p.action != call.action
            || p.arguments != call.arguments
            || p.origin != origin
        {
            return Err("call ID already used for different arguments or actor".into());
        }
        track_consumer(&host, &mut p, consumer)?;
        let state = state(&host, &p, &bound)?;
        return match state["state"].as_str() {
            Some("completed") => Ok(json!({"status":"completed","result":state["receipt"]})),
            Some("pending") => Ok(review(&p)),
            _ => Err(format!(
                "action is {}; inspect its history before continuing",
                state["state"]
            )),
        };
    }
    admit(&host)?;
    let package = host
        .db
        .get_plugin_release(&bound.release)
        .map_err(|e| e.to_string())?;
    let manifest = Manifest::parse(package.manifest)?.ok_or("versioned release required")?;
    let a = manifest
        .actions
        .iter()
        .find(|a| a.name == call.action)
        .ok_or("unknown integration action")?;
    a.input_schema.validate(&call.arguments)?;
    let operation = manifest
        .operations
        .iter()
        .find(|o| o.id == a.operation)
        .unwrap();
    let input = json!({"phase":"action","action":call.action,"arguments":call.arguments,"config":bound.config,"trigger":{"kind":"manual","at":atomic_lib::utils::now()}});
    let output = embedded_runtime()
        .map_err(|e| e.to_string())?
        .run(&package.source, &input.to_string(), NoCapabilities)
        .await
        .map_err(|e| e.to_string())??;
    if output.len() > 131072 {
        return Err("action request exceeds 128 KiB".into());
    }
    let mut intent: ExternalIntent = serde_json::from_str(&output).map_err(|e| e.to_string())?;
    intent.id = "action".into();
    if intent.operation != a.operation
        || !manifest.allows_effect(
            Some(&intent.operation),
            &intent.method,
            &url::Url::parse(&intent.url).map_err(|e| e.to_string())?,
            &operation.effect,
        )
    {
        return Err("action exceeded its declared operation".into());
    }
    if operation.effect == "read" {
        host.manifest = Some(manifest.clone());
        let receipt = host
            .request(serde_json::to_string(&intent).unwrap(), "read")
            .await?;
        return Ok(
            json!({"status":"read","result":serde_json::from_str::<Value>(&receipt).map_err(|e|e.to_string())?}),
        );
    }
    if pending_proposals(&host, &bound)?.len() >= 100 {
        return Err("too many pending actions; review existing proposals first".into());
    }
    let mut p = Proposal {
        consumers_tracked: origin.is_some() && consumer.is_some(),
        archived: None,
        origin,
        id: call.id,
        action: call.action,
        title: a.title.clone(),
        arguments: call.arguments,
        actor: host.for_agent.to_string(),
        release: bound.release.clone(),
        config: bound.config.clone(),
        created_at: atomic_lib::utils::now(),
        intent,
    };
    track_consumer(&host, &mut p, consumer)?;
    save_proposal(&host, &p)?;
    if automatic {
        host.manifest = Some(manifest);
        let receipt = execute_approved(
            &lock_db,
            &json!([host.drive, host.plugin]).to_string(),
            &p.actor,
            &bound,
            &p,
            &mut host,
        )
        .await?;
        return Ok(json!({"status":"completed","result":receipt}));
    }
    Ok(review(&p))
}
pub async fn proposals(host: &StoreHost) -> Result<Vec<Proposal>, String> {
    let bound = binding(host).await?;
    let _lock = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    pending_proposals(host, &bound)
}
fn pending_proposals(host: &StoreHost, bound: &Binding) -> Result<Vec<Proposal>, String> {
    ensure_history_index(host)?;
    let prefix = history_prefix(host);
    let cutoff = atomic_lib::utils::now() - 15 * 60 * 1000;
    let end = format!(
        "{prefix}{:016x}/~",
        u64::MAX - (cutoff as u64 ^ (1u64 << 63))
    )
    .into_bytes();
    let mut start = prefix.as_bytes().to_vec();
    let mut pending = Vec::new();
    loop {
        let rows = host
            .db
            .kv
            .range_page(Tree::PluginMeta, start, end.clone(), 100)
            .map_err(|e| e.to_string())?;
        if rows.is_empty() {
            break;
        }
        start = rows.last().unwrap().0.clone();
        start.push(0);
        for (_, id) in rows {
            let p = owned(host, std::str::from_utf8(&id).map_err(|e| e.to_string())?)?;
            if state(host, &p, bound)?["state"] == "pending" {
                pending.push(p);
                if pending.len() == 100 {
                    return Ok(pending);
                }
            }
        }
    }
    Ok(pending)
}
pub async fn approve(mut host: StoreHost, id: &str) -> Result<Receipt, String> {
    let lock_db = host.db.clone();
    let _lock = lock_db
        .lock_plugin(&format!("actions:{}", prefix(&host)))
        .await;
    let bound = binding(&host).await?;
    let p = owned(&host, id)?;
    if p.consumers_tracked
        && p.origin.is_some()
        && external::inspect(
            &host.db,
            &json!([host.drive, host.plugin]).to_string(),
            &p.release,
            id,
            "action",
        )?
        .is_none()
    {
        let runs: Vec<String> = marker(&host, "consumers", id)?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let mut all_abandoned = !runs.is_empty();
        for run in runs {
            if super::journal::Journal::new(
                &host.db,
                &host.drive,
                &p.origin.as_ref().unwrap().caller,
                &run,
            )
            .abandoned()?
            .is_none()
            {
                all_abandoned = false;
                break;
            }
        }
        if all_abandoned {
            return Err("all consuming runs were abandoned; prepare a new action instead".into());
        }
    }
    if marker(&host, "cancelled", id)?.is_some() {
        return Err("action was cancelled".into());
    }
    host.manifest = Manifest::parse(
        host.db
            .get_plugin_release(&p.release)
            .map_err(|e| e.to_string())?
            .manifest,
    )?;
    let db = host.db.clone();
    execute_approved(
        &db,
        &json!([host.drive, host.plugin]).to_string(),
        &host.for_agent.to_string(),
        &bound,
        &p,
        &mut host,
    )
    .await
}
async fn execute_approved<H: external::ExternalHost>(
    db: &atomic_lib::Db,
    connection: &str,
    actor: &str,
    bound: &Binding,
    p: &Proposal,
    host: &mut H,
) -> Result<Receipt, String> {
    if p.archived.is_some() {
        return Err("archived actions cannot be approved".into());
    }
    if p.actor != actor {
        return Err("proposal belongs to another actor".into());
    }
    if p.release != bound.release || p.config != bound.config {
        return Err("connection changed; prepare a new proposal".into());
    }
    if let Some(entry) = external::inspect(db, connection, &p.release, &p.id, "action")? {
        let receipt = entry
            .receipt
            .ok_or("previous write is uncertain; inspect provider before recovery")?;
        if !(200..300).contains(&receipt.status) {
            return Err(format!(
                "previous write failed with status {}",
                receipt.status
            ));
        }
        return Ok(receipt);
    }
    if atomic_lib::utils::now() - p.created_at > 15 * 60 * 1000 {
        return Err("proposal expired; prepare a new proposal".into());
    }
    external::execute(db, connection, &p.release, &p.id, &p.intent, host).await
}

/// The caller's connection list grants no target authority: both instances are
/// checked independently as the effective actor and the target release is pinned.
pub async fn invoke_from_plugin(
    caller: &StoreHost,
    request: &str,
    source_hash: &str,
    allow_automatic: bool,
) -> Result<String, String> {
    invoke_from_plugin_run(caller, request, source_hash, allow_automatic, None).await
}
pub async fn invoke_from_plugin_run(
    caller: &StoreHost,
    request: &str,
    source_hash: &str,
    allow_automatic: bool,
    consumer: Option<&str>,
) -> Result<String, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        connection: String,
        release: String,
        call: Call,
    }
    if request.len() > 65536 {
        return Err("integration call exceeds 64 KiB".into());
    }
    let mut r: Request = serde_json::from_str(request).map_err(|e| e.to_string())?;
    caller.validate_binding().await?;
    check_reference(caller, &r.connection).await?;
    let target = StoreHost {
        plugin: r.connection,
        manifest: None,
        ..caller.clone()
    };
    let bound = binding(&target).await?;
    if bound.release != r.release {
        return Err("integration release changed; review the caller before upgrading".into());
    }
    let origin = Origin {
        caller: caller.plugin.clone(),
        source_hash: source_hash.into(),
    };
    let grant = valid_grant(&target, &origin, &r.call.action, &bound).await?;
    if super::store_host::app_signing_for(&caller.db, &caller.drive, &caller.plugin)
        .await?
        .is_some()
        && grant.is_none()
    {
        return Err("app-scoped caller needs an explicit integration action grant".into());
    }
    r.call.id = format!(
        "plugin-{}",
        blake3::hash(
            json!([caller.plugin, source_hash, r.call.id])
                .to_string()
                .as_bytes()
        )
        .to_hex()
    );
    let mut result = invoke_consumed(
        target.clone(),
        r.call,
        Some(origin),
        allow_automatic && grant.as_ref().is_some_and(|g| g.mode == "automatic"),
        consumer,
    )
    .await?;
    if result["status"] == "needs_review" {
        result["connection"] = json!(target.plugin);
    }
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Origin {
    pub caller: String,
    pub source_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Grant {
    pub origin: Origin,
    pub action: String,
    pub mode: String,
    pub actor: String,
    pub release: String,
    pub config: Value,
    pub expires_at: i64,
}
fn meta_key(host: &StoreHost, kind: &str, id: &str) -> String {
    format!(
        "integration-action-{kind}/v1/{}",
        json!([host.drive, host.plugin, id])
    )
}
fn marker(host: &StoreHost, kind: &str, id: &str) -> Result<Option<Value>, String> {
    host.db
        .kv
        .get(Tree::PluginMeta, meta_key(host, kind, id).as_bytes())
        .map_err(|e| e.to_string())?
        .map(|v| serde_json::from_slice(&v).map_err(|e| e.to_string()))
        .transpose()
}
fn put(host: &StoreHost, kind: &str, id: &str, value: Value) -> Result<(), String> {
    host.db
        .kv
        .insert(
            Tree::PluginMeta,
            meta_key(host, kind, id).as_bytes(),
            &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    host.db.flush().map_err(|e| e.to_string())
}
fn owned(host: &StoreHost, id: &str) -> Result<Proposal, String> {
    let p = saved(host, id)?.ok_or("proposal not found")?;
    if p.actor != host.for_agent.to_string() {
        return Err("proposal belongs to another actor".into());
    }
    Ok(p)
}
fn state(host: &StoreHost, p: &Proposal, bound: &Binding) -> Result<Value, String> {
    let entry = external::inspect(
        &host.db,
        &json!([host.drive, host.plugin]).to_string(),
        &p.release,
        &p.id,
        "action",
    )?;
    if let Some(archive) = &p.archived {
        return Ok(
            json!({"proposal":p,"state":archive.state,"receipt":null,"resolution":entry.as_ref().and_then(|e|e.resolution.as_ref())}),
        );
    }
    let status = if let Some(e) = &entry {
        match &e.receipt {
            Some(r) if (200..300).contains(&r.status) => "completed",
            Some(_) => "failed",
            None => "uncertain",
        }
    } else if marker(host, "cancelled", &p.id)?.is_some() {
        "cancelled"
    } else if p.release != bound.release || p.config != bound.config {
        "stale"
    } else if atomic_lib::utils::now() - p.created_at > 15 * 60 * 1000 {
        "expired"
    } else {
        "pending"
    };
    Ok(
        json!({"proposal":p,"state":status,"receipt":entry.as_ref().and_then(|e|e.receipt.as_ref()),"resolution":entry.as_ref().and_then(|e|e.resolution.as_ref())}),
    )
}
fn history_prefix(host: &StoreHost) -> String {
    format!(
        "integration-action-history/v1/{}/",
        json!([host.drive, host.plugin, host.for_agent.to_string()])
    )
}
fn history_suffix(p: &Proposal) -> String {
    // Fixed-width descending timestamp with ID as a deterministic tie-breaker.
    format!(
        "{:016x}/{}",
        u64::MAX - (p.created_at as u64 ^ (1u64 << 63)),
        p.id
    )
}
fn insert_op(key: String, val: Vec<u8>) -> Operation {
    Operation {
        tree: Tree::PluginMeta,
        method: Method::Insert,
        key: key.into_bytes(),
        val: Some(val),
    }
}
fn index_op(host: &StoreHost, p: &Proposal) -> Operation {
    let prefix = format!(
        "integration-action-history/v1/{}/",
        json!([host.drive, host.plugin, p.actor])
    );
    insert_op(
        format!("{prefix}{}", history_suffix(p)),
        p.id.as_bytes().to_vec(),
    )
}
fn save_proposal(host: &StoreHost, p: &Proposal) -> Result<(), String> {
    host.db
        .kv
        .apply_batch(&[
            insert_op(
                key(host, &p.id),
                serde_json::to_vec(p).map_err(|e| e.to_string())?,
            ),
            index_op(host, p),
        ])
        .map_err(|e| e.to_string())?;
    host.db.flush().map_err(|e| e.to_string())
}
/// One-time, crash-resumable migration. Caller holds the connection action lock.
fn ensure_history_index(host: &StoreHost) -> Result<(), String> {
    let marker = format!(
        "integration-action-history-ready/v1/{}",
        json!([host.drive, host.plugin])
    );
    if host
        .db
        .kv
        .contains_key(Tree::PluginMeta, marker.as_bytes())
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }
    let prefix = prefix(host);
    let mut start = prefix.as_bytes().to_vec();
    let end = format!("{prefix}~").into_bytes();
    loop {
        let rows = host
            .db
            .kv
            .range_page(Tree::PluginMeta, start, end.clone(), 128)
            .map_err(|e| e.to_string())?;
        if rows.is_empty() {
            break;
        }
        start = rows.last().unwrap().0.clone();
        start.push(0);
        let ops = rows
            .into_iter()
            .map(|(_, v)| {
                let p: Proposal = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
                Ok(index_op(host, &p))
            })
            .collect::<Result<Vec<_>, String>>()?;
        host.db.kv.apply_batch(&ops).map_err(|e| e.to_string())?;
    }
    host.db
        .kv
        .insert(Tree::PluginMeta, marker.as_bytes(), b"1")
        .map_err(|e| e.to_string())?;
    host.db.flush().map_err(|e| e.to_string())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    pub entries: Vec<Value>,
    pub next_cursor: Option<String>,
}
pub async fn history_page(
    host: &StoreHost,
    cursor: Option<&str>,
    limit: usize,
) -> Result<HistoryPage, String> {
    if !(1..=100).contains(&limit) {
        return Err("history limit must be between 1 and 100".into());
    }
    let bound = binding(host).await?;
    let _lock = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    ensure_history_index(host)?;
    let prefix = history_prefix(host);
    let mut start = prefix.as_bytes().to_vec();
    if let Some(cursor) = cursor {
        // Cursor carries no authority: it can only seek within this actor's index.
        let (timestamp, id) = cursor.split_once('/').ok_or("invalid history cursor")?;
        if timestamp.len() != 16
            || !timestamp.bytes().all(|b| b.is_ascii_hexdigit())
            || id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err("invalid history cursor".into());
        }
        start.extend_from_slice(cursor.as_bytes());
        start.push(0);
    }
    let rows = host
        .db
        .kv
        .range_page(
            Tree::PluginMeta,
            start,
            format!("{prefix}~").into_bytes(),
            limit + 1,
        )
        .map_err(|e| e.to_string())?;
    let more = rows.len() > limit;
    let mut entries = Vec::new();
    let mut next_cursor = None;
    for (k, v) in rows.into_iter().take(limit) {
        let id = std::str::from_utf8(&v).map_err(|e| e.to_string())?;
        let p = owned(host, id)?;
        entries.push(state(host, &p, &bound)?);
        if more {
            next_cursor =
                Some(String::from_utf8(k[prefix.len()..].to_vec()).map_err(|e| e.to_string())?);
        }
    }
    Ok(HistoryPage {
        entries,
        next_cursor,
    })
}
pub async fn history(host: &StoreHost) -> Result<Vec<Value>, String> {
    Ok(history_page(host, None, 100).await?.entries)
}
/// Explicit, bounded cleanup of manual actions. Automation receipts stay intact.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactPage {
    pub scanned: usize,
    pub eligible: usize,
    pub compacted: usize,
    pub reclaimable_bytes: usize,
    pub next_cursor: Option<String>,
}
pub async fn compact_history(
    host: &StoreHost,
    cursor: Option<&str>,
    apply: bool,
) -> Result<CompactPage, String> {
    compact_history_with_completed(host, cursor, apply, false).await
}
pub async fn compact_history_with_completed(
    host: &StoreHost,
    cursor: Option<&str>,
    apply: bool,
    include_completed: bool,
) -> Result<CompactPage, String> {
    compact_history_policy(host, cursor, apply, include_completed, false).await
}
pub async fn compact_history_policy(
    host: &StoreHost,
    cursor: Option<&str>,
    apply: bool,
    include_completed: bool,
    include_automation: bool,
) -> Result<CompactPage, String> {
    // Seek directly to old history instead of paging past recent activity.
    let cutoff = atomic_lib::utils::now() - 30 * 24 * 60 * 60 * 1000;
    let initial_cursor = format!("{:016x}/-", u64::MAX - ((cutoff + 1) as u64 ^ (1u64 << 63)));
    let page = history_page(host, Some(cursor.unwrap_or(&initial_cursor)), 100).await?;
    let _lock = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    let bound = binding(host).await?;
    let connection = json!([host.drive, host.plugin]).to_string();
    let _external_lock = host.db.lock_plugin(&format!("external:{connection}")).await;
    let now = atomic_lib::utils::now();
    let mut result = CompactPage {
        scanned: page.entries.len(),
        eligible: 0,
        compacted: 0,
        reclaimable_bytes: 0,
        next_cursor: page.next_cursor,
    };
    let mut ops = Vec::new();
    for row in page.entries {
        let id = row["proposal"]["id"]
            .as_str()
            .ok_or("invalid history entry")?;
        let mut p = owned(host, id)?;
        if p.archived.is_some()
            || (p.origin.is_some() && (!include_automation || !consumers_finished(host, &p, now)?))
            || now.saturating_sub(p.created_at) < 30 * 24 * 60 * 60 * 1000
        {
            continue;
        }
        let connection = json!([host.drive, host.plugin]).to_string();
        let mut journal = external::inspect(&host.db, &connection, &p.release, &p.id, "action")?;
        if let Some(entry) = &journal {
            // Unknown settlement ages (legacy records), uncertain results and
            // failures remain available for reconciliation. Proposal age alone
            // must never cause a freshly recovered receipt to be removed.
            if !include_completed
                || entry.archived.is_some()
                || entry
                    .settled_at
                    .is_none_or(|at| now.saturating_sub(at) < 30 * 24 * 60 * 60 * 1000)
                || !entry
                    .receipt
                    .as_ref()
                    .is_some_and(|r| (200..300).contains(&r.status))
            {
                continue;
            }
        }
        let status = state(host, &p, &bound)?["state"]
            .as_str()
            .ok_or("invalid action state")?
            .to_string();
        if !matches!(
            status.as_str(),
            "expired" | "cancelled" | "stale" | "completed"
        ) {
            continue;
        }
        let before = serde_json::to_vec(&p).map_err(|e| e.to_string())?;
        p.archived = Some(Archive {
            at: now,
            state: status,
            payload_hash: blake3::hash(&before).to_hex().to_string(),
        });
        p.arguments = json!({});
        p.config = json!(null);
        p.intent.headers.clear();
        p.intent.body = None;
        p.intent.url.clear();
        let after = serde_json::to_vec(&p).map_err(|e| e.to_string())?;
        result.eligible += 1;
        result.reclaimable_bytes += before.len().saturating_sub(after.len());
        ops.push(insert_op(key(host, id), after));
        if let Some(entry) = &mut journal {
            let before = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
            entry.archived = Some(external::JournalArchive {
                at: now,
                payload_hash: blake3::hash(&before).to_hex().to_string(),
            });
            entry.intent.url.clear();
            entry.intent.headers.clear();
            entry.intent.body = None;
            if let Some(receipt) = &mut entry.receipt {
                receipt.body.clear();
            }
            let after = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
            result.reclaimable_bytes += before.len().saturating_sub(after.len());
            ops.push(insert_op(
                external::key(&connection, &p.release, id, "action"),
                after,
            ));
            // Confirmed recovery leaves a second copy of the receipt here.
            let recovery_key = meta_key(host, "recovery", id);
            if let Some(bytes) = host
                .db
                .kv
                .get(Tree::PluginMeta, recovery_key.as_bytes())
                .map_err(|e| e.to_string())?
            {
                result.reclaimable_bytes += bytes.len();
                ops.push(Operation {
                    tree: Tree::PluginMeta,
                    method: Method::Delete,
                    key: recovery_key.into_bytes(),
                    val: None,
                });
            }
        }
    }
    if apply && !ops.is_empty() {
        host.db.kv.apply_batch(&ops).map_err(|e| e.to_string())?;
        host.db.flush().map_err(|e| e.to_string())?;
        result.compacted = result.eligible;
    }
    Ok(result)
}
/// Caller holds the action lock, also used by cleanup. Missing historical
/// ownership is never retroactively treated as complete.
fn track_consumer(host: &StoreHost, p: &mut Proposal, run: Option<&str>) -> Result<(), String> {
    let Some(origin) = &p.origin else {
        return Ok(());
    };
    let Some(run) = run else {
        if p.consumers_tracked {
            p.consumers_tracked = false;
            save_proposal(host, p)?;
        }
        return Ok(());
    };
    if run.len() > 256 || !(run.starts_with("query:") || run.starts_with("cron:")) {
        return Err("invalid host run identity".into());
    }
    let journal = super::journal::Journal::new(&host.db, &host.drive, &origin.caller, run);
    if journal.terminal()?.is_some() {
        return Err("this automation run is terminal; its receipt cannot be consumed again".into());
    }
    let mut consumers: Vec<String> = marker(host, "consumers", &p.id)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if !consumers.iter().any(|c| c == run) {
        if consumers.len() >= 1000 {
            return Err(
                "action has too many consuming runs; use a distinct call ID for new work".into(),
            );
        }
        consumers.push(run.into());
        put(host, "consumers", &p.id, json!(consumers))?;
    }
    Ok(())
}
fn consumers_finished(host: &StoreHost, p: &Proposal, now: i64) -> Result<bool, String> {
    let Some(origin) = &p.origin else {
        return Ok(true);
    };
    if !p.consumers_tracked {
        return Ok(false);
    }
    let consumers: Vec<String> = marker(host, "consumers", &p.id)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if consumers.is_empty() {
        return Ok(false);
    }
    for run in consumers {
        let done =
            super::journal::Journal::new(&host.db, &host.drive, &origin.caller, &run).terminal()?;
        if done
            .and_then(|v| v["at"].as_i64())
            .is_none_or(|at| now.saturating_sub(at) < 30 * 24 * 60 * 60 * 1000)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
pub async fn consumers(host: &StoreHost, id: &str) -> Result<Vec<Value>, String> {
    binding(host).await?;
    let p = owned(host, id)?;
    let Some(origin) = p.origin else {
        return Ok(Vec::new());
    };
    let runs: Vec<String> = marker(host, "consumers", id)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    runs.into_iter().map(|run| {
        let journal = super::journal::Journal::new(&host.db, &host.drive, &origin.caller, &run);
        let terminal = journal.terminal()?;
        Ok(json!({"run":run,"state":terminal.as_ref().map(|v|v["state"].as_str().unwrap_or("completed")).unwrap_or("unfinished"),"audit":terminal}))
    }).collect()
}
pub async fn abandon_consumer(
    host: &StoreHost,
    id: &str,
    run: &str,
    reason: &str,
) -> Result<(), String> {
    // Same order as workers: worker exclusion, then connection exclusion.
    // Refuse a busy worker instead of interrupting a request already in flight.
    let _cron = if run.starts_with("cron:") {
        Some(
            super::scheduler::EXECUTION_LOCK
                .try_lock()
                .map_err(|_| "scheduler is busy; try again after the active run finishes")?,
        )
    } else {
        None
    };
    let _query = if run.starts_with("query:") {
        Some(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                host.db.lock_plugin("trigger-delivery"),
            )
            .await
            .map_err(|_| "event worker is busy; try again after the active run finishes")?,
        )
    } else {
        None
    };
    let _action = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    binding(host).await?;
    let p = owned(host, id)?;
    let origin = p.origin.ok_or("action has no automation consumer")?;
    let caller = StoreHost {
        plugin: origin.caller.clone(),
        ..host.clone()
    };
    caller.validate_binding().await?;
    let runs: Vec<String> = marker(host, "consumers", id)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if !runs.iter().any(|r| r == run) || !(run.starts_with("cron:") || run.starts_with("query:")) {
        return Err("run is not a recorded consumer of this action".into());
    }
    super::journal::Journal::new(&host.db, &host.drive, &origin.caller, run)
        .abandon(&host.for_agent.to_string(), reason)
}
pub async fn cancel(host: &StoreHost, id: &str) -> Result<(), String> {
    let _lock = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    let bound = binding(host).await?;
    let p = owned(host, id)?;
    if !matches!(
        state(host, &p, &bound)?["state"].as_str(),
        Some("pending" | "expired" | "stale" | "cancelled")
    ) {
        return Err("an attempted write cannot be cancelled".into());
    }
    put(
        host,
        "cancelled",
        id,
        json!({"actor":p.actor,"at":atomic_lib::utils::now()}),
    )
}
fn admit(host: &StoreHost) -> Result<(), String> {
    let now = atomic_lib::utils::now();
    let actor = host.for_agent.to_string();
    let mut window = marker(host, "rate", &actor)?.unwrap_or(json!({"at":now,"count":0}));
    if now - window["at"].as_i64().unwrap_or(0) >= 60000 {
        window = json!({"at":now,"count":0});
    }
    let count = window["count"].as_u64().unwrap_or(0);
    if count >= 60 {
        return Err("integration action rate limit reached; wait a minute".into());
    }
    window["count"] = json!(count + 1);
    put(host, "rate", &actor, window)
}
async fn check_reference(caller: &StoreHost, target: &str) -> Result<(), String> {
    let terms = drive_terms(&caller.db, &caller.drive)
        .await
        .ok_or("drive schema unavailable")?;
    let property = terms
        .property("automation-integrations")
        .ok_or("no declared integration references")?;
    let r = caller
        .db
        .get_resource(&caller.plugin.as_str().into())
        .await
        .map_err(|e| e.to_string())?;
    if !r
        .get(property)
        .map_err(|e| e.to_string())?
        .to_subjects(None)
        .map_err(|e| e.to_string())?
        .iter()
        .any(|s| s == target)
    {
        return Err("integration must be explicitly referenced by the calling plugin".into());
    }
    Ok(())
}
fn grant_id(caller: &str, action: &str, actor: &str) -> String {
    json!([caller, action, actor]).to_string()
}
pub async fn set_grant(
    host: &StoreHost,
    caller: &str,
    action: &str,
    mode: &str,
) -> Result<(), String> {
    let _lock = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    let bound = binding(host).await?;
    let c = StoreHost {
        plugin: caller.into(),
        ..host.clone()
    };
    c.validate_binding().await?;
    let id = grant_id(caller, action, &host.for_agent.to_string());
    if mode == "revoke" {
        return put(host, "grant", &id, Value::Null);
    }
    if !matches!(mode, "review" | "automatic") {
        return Err("unsupported action grant mode".into());
    }
    check_reference(&c, &host.plugin).await?;
    if !list(host).await?["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == action)
    {
        return Err("unknown action".into());
    }
    let source = super::scheduler::plugin_source(&host.db, &host.drive, caller)
        .await
        .ok_or("caller source unavailable")?;
    put(
        host,
        "grant",
        &id,
        json!(Grant {
            origin: Origin {
                caller: caller.into(),
                source_hash: blake3::hash(source.as_bytes()).to_hex().to_string()
            },
            action: action.into(),
            mode: mode.into(),
            actor: host.for_agent.to_string(),
            release: bound.release,
            config: bound.config,
            expires_at: atomic_lib::utils::now() + 30 * 24 * 60 * 60 * 1000
        }),
    )
}
async fn valid_grant(
    host: &StoreHost,
    origin: &Origin,
    action: &str,
    bound: &Binding,
) -> Result<Option<Grant>, String> {
    let Some(value) = marker(
        host,
        "grant",
        &grant_id(&origin.caller, action, &host.for_agent.to_string()),
    )?
    else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let g: Grant = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if g.origin != *origin
        || g.release != bound.release
        || g.config != bound.config
        || g.expires_at <= atomic_lib::utils::now()
    {
        return Err(
            "integration action grant expired or its code/connection changed; review it again"
                .into(),
        );
    }
    Ok(Some(g))
}
pub async fn grants(host: &StoreHost) -> Result<Vec<Grant>, String> {
    binding(host).await?;
    let prefix = format!(
        "integration-action-grant/v1/[{},{}",
        json!(host.drive),
        json!(host.plugin)
    );
    host.db
        .kv
        .scan_prefix(Tree::PluginMeta, prefix.as_bytes())
        .map(|e| {
            e.map_err(|e| e.to_string()).and_then(|(_, v)| {
                serde_json::from_slice::<Option<Grant>>(&v).map_err(|e| e.to_string())
            })
        })
        .filter_map(|g| match g {
            Ok(Some(g)) if g.actor == host.for_agent.to_string() => Some(Ok(g)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect()
}

/// Recovery reads through a declared action. The operator confirms that the
/// returned provider record is the result of this write; it is never resent.
pub async fn inspect_recovery(
    host: StoreHost,
    id: &str,
    call: Call,
    evidence: &str,
) -> Result<Value, String> {
    let bound = binding(&host).await?;
    let p = owned(&host, id)?;
    if p.release != bound.release || p.config != bound.config {
        return Err(
            "connection changed; restore its reviewed configuration before recovery".into(),
        );
    }
    if state(&host, &p, &bound)?["state"] != "uncertain" {
        return Err("only an uncertain action needs recovery".into());
    }
    if evidence.trim().is_empty() || evidence.len() > 8192 {
        return Err("describe how this provider record matches the action".into());
    }
    let catalog = list(&host).await?;
    if !catalog["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == call.action && t["annotations"]["readOnlyHint"] == true)
    {
        return Err("recovery requires a declared read action".into());
    }
    let result = invoke(host.clone(), call).await?;
    let receipt: Receipt =
        serde_json::from_value(result["result"].clone()).map_err(|e| e.to_string())?;
    if !(200..300).contains(&receipt.status) {
        return Err("provider lookup failed".into());
    }
    let candidate = json!({"receipt":receipt,"evidence":evidence,"at":atomic_lib::utils::now(),"release":bound.release,"config":bound.config});
    put(&host, "recovery", id, candidate.clone())?;
    Ok(candidate)
}
pub async fn confirm_recovery(host: &StoreHost, id: &str) -> Result<(), String> {
    let _lock = host
        .db
        .lock_plugin(&format!("actions:{}", prefix(host)))
        .await;
    let bound = binding(host).await?;
    let p = owned(host, id)?;
    if p.release != bound.release || p.config != bound.config {
        return Err(
            "connection changed; restore its reviewed configuration before recovery".into(),
        );
    }
    let c = marker(host, "recovery", id)?.ok_or("look up the provider result first")?;
    if atomic_lib::utils::now() - c["at"].as_i64().unwrap_or(0) > 5 * 60 * 1000
        || c["release"] != bound.release
        || c["config"] != bound.config
    {
        return Err("recovery lookup expired or connection changed".into());
    }
    external::confirm_applied(
        &host.db,
        &json!([host.drive, host.plugin]).to_string(),
        &p.release,
        id,
        "action",
        serde_json::from_value(c["receipt"].clone()).map_err(|e| e.to_string())?,
        external::Resolution {
            actor: host.for_agent.to_string(),
            evidence: c["evidence"].as_str().unwrap_or_default().into(),
            at: atomic_lib::utils::now(),
        },
    )
    .await
}

pub fn waits(verdict: &str) -> Option<Vec<Value>> {
    serde_json::from_str::<Value>(verdict)
        .ok()?
        .get("integrationWaits")?
        .as_array()
        .filter(|a| !a.is_empty())
        .cloned()
}
pub async fn waits_ready(
    db: std::sync::Arc<atomic_lib::Db>,
    drive: &str,
    actor: &str,
    waits: &[Value],
) -> Result<bool, String> {
    for w in waits {
        let host = StoreHost {
            db: db.clone(),
            drive: drive.into(),
            plugin: w["connection"]
                .as_str()
                .ok_or("invalid action wait")?
                .into(),
            for_agent: atomic_lib::agents::ForAgent::AgentSubject(actor.into()),
            manifest: None,
        };
        let bound = binding(&host).await?;
        let p = owned(&host, w["id"].as_str().ok_or("invalid action wait")?)?;
        match state(&host, &p, &bound)?["state"].as_str() {
            Some("completed") => {}
            Some("pending" | "uncertain") => return Ok(false),
            _ => return Err(
                "integration action was cancelled, expired, failed or changed; inspect its history"
                    .into(),
            ),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::super::test_fixture::fixture;
    use super::*;
    use atomic_lib::{agents::ForAgent, db::plugin_release::PluginRelease, Value as AtomicValue};
    struct Provider {
        writes: usize,
        lose: bool,
    }
    #[async_trait::async_trait]
    impl external::ExternalHost for Provider {
        async fn execute(&mut self, _: &ExternalIntent) -> Result<Receipt, String> {
            self.writes += 1;
            if self.lose {
                Err("lost response".into())
            } else {
                Ok(Receipt {
                    status: 201,
                    body: "{\"number\":1}".into(),
                })
            }
        }
    }
    async fn setup() -> StoreHost {
        let mut f = fixture("integration-actions").await;
        super::super::test_fixture::write_plugin(&mut f, "fixture").await;
        let db = std::sync::Arc::new(f.appstate.store.clone());
        let release = db
            .publish_plugin_release(&PluginRelease {
                source: include_str!("../../../integrations/github-issues/plugin.js").into(),
                manifest: serde_json::from_str(include_str!(
                    "../../../integrations/github-issues/manifest.fixture.json"
                ))
                .unwrap(),
                runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
                schemas: Default::default(),
            })
            .unwrap();
        let mut plugin = db.get_resource(&f.plugin.as_str().into()).await.unwrap();
        plugin
            .set_unsafe(
                f.terms.property("plugin-connection").unwrap().into(),
                AtomicValue::Json(
                    json!({"release":release,"config":{"repository":"atomic-fixtures/issues"}}),
                ),
            )
            .unwrap();
        plugin.save(&*db).await.unwrap();
        StoreHost {
            for_agent: ForAgent::AgentSubject(db.get_default_agent().unwrap().subject.clone()),
            db,
            drive: f.drive,
            plugin: f.plugin,
            manifest: None,
        }
    }
    fn call(id: &str) -> Call {
        Call {
            id: id.into(),
            action: "create_issue".into(),
            arguments: json!({"title":"Review this issue","body":"Synthetic"}),
        }
    }
    #[actix_web::test]
    async fn abandoning_a_consumer_is_audited_busy_safe_and_preserves_uncertainty() {
        let host = setup().await;
        invoke(host.clone(), call("abandoned")).await.unwrap();
        let mut p = saved(&host, "abandoned").unwrap().unwrap();
        p.origin = Some(Origin {
            caller: host.plugin.clone(),
            source_hash: "source".into(),
        });
        p.consumers_tracked = true;
        track_consumer(&host, &mut p, Some("query:abandoned")).unwrap();
        save_proposal(&host, &p).unwrap();
        let mut pending = p.clone();
        pending.id = "pending-abandoned".into();
        track_consumer(&host, &mut pending, Some("query:abandoned")).unwrap();
        save_proposal(&host, &pending).unwrap();
        let busy = host.db.lock_plugin("trigger-delivery").await;
        assert!(
            abandon_consumer(&host, &p.id, "query:abandoned", "Stopped by operator")
                .await
                .unwrap_err()
                .contains("busy")
        );
        drop(busy);
        assert!(abandon_consumer(&host, &p.id, "query:unrelated", "Stopped")
            .await
            .is_err());
        assert!(abandon_consumer(&host, &p.id, "query:abandoned", " ")
            .await
            .is_err());
        let mut other = host.clone();
        other.for_agent = ForAgent::AgentSubject("did:ad:agent:other".into());
        assert!(
            abandon_consumer(&other, &p.id, "query:abandoned", "Stopped")
                .await
                .is_err()
        );
        let mut provider = Provider {
            writes: 0,
            lose: true,
        };
        let connection = json!([host.drive, host.plugin]).to_string();
        assert!(external::execute(
            &host.db,
            &connection,
            &p.release,
            &p.id,
            &p.intent,
            &mut provider
        )
        .await
        .is_err());
        abandon_consumer(
            &host,
            &p.id,
            "query:abandoned",
            "Operator checked the provider; stopping this run",
        )
        .await
        .unwrap();
        assert!(approve(host.clone(), &pending.id)
            .await
            .unwrap_err()
            .contains("abandoned"));
        let rows = consumers(&host, &p.id).await.unwrap();
        assert_eq!(rows[0]["state"], "abandoned");
        assert_eq!(rows[0]["audit"]["actor"], host.for_agent.to_string());
        abandon_consumer(&host, &p.id, "query:abandoned", "Different reason")
            .await
            .unwrap();
        assert_eq!(consumers(&host, &p.id).await.unwrap(), rows);
        let journal = super::super::journal::Journal::new(
            &host.db,
            &host.drive,
            &host.plugin,
            "query:abandoned",
        );
        assert!(journal.finished().unwrap().is_none());
        assert!(journal.plan(&Default::default()).is_err());
        assert!(journal.begin(0).is_err());
        assert!(journal.finish("success").is_err());
        assert!(track_consumer(&host, &mut p, Some("query:abandoned")).is_err());
        assert!(!consumers_finished(&host, &p, atomic_lib::utils::now()).unwrap());
        assert!(consumers_finished(
            &host,
            &p,
            atomic_lib::utils::now() + 31 * 24 * 60 * 60 * 1000
        )
        .unwrap());
        assert_eq!(
            state(&host, &p, &binding(&host).await.unwrap()).unwrap()["state"],
            "uncertain"
        );
        assert_eq!(provider.writes, 1);
    }

    #[actix_web::test]
    async fn automation_retention_waits_for_every_consumer_and_preserves_untracked_calls() {
        let host = setup().await;
        invoke(host.clone(), call("seed")).await.unwrap();
        let mut p = saved(&host, "seed").unwrap().unwrap();
        p.id = "shared".into();
        p.origin = Some(Origin {
            caller: "automation".into(),
            source_hash: "source".into(),
        });
        p.consumers_tracked = true;
        p.created_at = atomic_lib::utils::now() - 31 * 24 * 60 * 60 * 1000;
        track_consumer(&host, &mut p, Some("query:first")).unwrap();
        track_consumer(&host, &mut p, Some("cron:second")).unwrap();
        save_proposal(&host, &p).unwrap();
        let connection = json!([host.drive, host.plugin]).to_string();
        let mut provider = Provider {
            writes: 0,
            lose: false,
        };
        external::execute(
            &host.db,
            &connection,
            &p.release,
            &p.id,
            &p.intent,
            &mut provider,
        )
        .await
        .unwrap();
        let mut entry = external::inspect(&host.db, &connection, &p.release, &p.id, "action")
            .unwrap()
            .unwrap();
        entry.settled_at = Some(p.created_at);
        host.db
            .kv
            .insert(
                Tree::PluginMeta,
                external::key(&connection, &p.release, &p.id, "action").as_bytes(),
                &serde_json::to_vec(&entry).unwrap(),
            )
            .unwrap();
        let finish = |run: &str, at: i64| {
            let j = super::super::journal::Journal::new(&host.db, &host.drive, "automation", run);
            j.plan(&Default::default()).unwrap();
            j.finish("finished").unwrap();
            let k = format!(
                "plugin-journal/v1/{}/finished",
                json!([host.drive, "automation", run])
            );
            host.db
                .kv
                .insert(
                    Tree::PluginMeta,
                    k.as_bytes(),
                    &serde_json::to_vec(&json!({"at":at,"summary":"finished"})).unwrap(),
                )
                .unwrap();
        };
        finish("query:first", p.created_at);
        assert!(!consumers_finished(&host, &p, atomic_lib::utils::now()).unwrap());
        finish("cron:second", atomic_lib::utils::now());
        assert!(!consumers_finished(&host, &p, atomic_lib::utils::now()).unwrap());
        finish("cron:second", p.created_at);
        assert!(consumers_finished(&host, &p, atomic_lib::utils::now()).unwrap());
        assert_eq!(
            compact_history_with_completed(&host, None, false, true)
                .await
                .unwrap()
                .eligible,
            0
        );
        assert_eq!(
            compact_history_policy(&host, None, false, true, true)
                .await
                .unwrap()
                .eligible,
            1
        );
        assert!(track_consumer(&host, &mut p, Some("query:first")).is_err());
        track_consumer(&host, &mut p, Some("query:third")).unwrap();
        assert_eq!(
            compact_history_policy(&host, None, true, true, true)
                .await
                .unwrap()
                .compacted,
            0
        );
        finish("query:third", p.created_at);
        // A manual replay invalidates completeness rather than inventing ownership.
        let mut legacy = p.clone();
        legacy.id = "legacy".into();
        save_proposal(&host, &legacy).unwrap();
        track_consumer(&host, &mut legacy, None).unwrap();
        assert!(!saved(&host, "legacy").unwrap().unwrap().consumers_tracked);
        assert!(!consumers_finished(&host, &legacy, atomic_lib::utils::now()).unwrap());
        assert_eq!(
            compact_history_policy(&host, None, true, true, true)
                .await
                .unwrap()
                .compacted,
            1
        );
        assert!(saved(&host, "shared").unwrap().unwrap().archived.is_some());
        assert!(saved(&host, "legacy").unwrap().unwrap().archived.is_none());
    }

    #[actix_web::test]
    async fn completed_manual_retention_preserves_journal_tombstones_and_recent_recovery() {
        let host = setup().await;
        invoke(host.clone(), call("template")).await.unwrap();
        let template = saved(&host, "template").unwrap().unwrap();
        let connection = json!([host.drive, host.plugin]).to_string();
        let mut provider = Provider {
            writes: 0,
            lose: false,
        };
        for id in [
            "old",
            "recent",
            "legacy",
            "failed",
            "automation",
            "recovered",
        ] {
            let mut p = template.clone();
            p.id = id.into();
            p.created_at = atomic_lib::utils::now() - 31 * 24 * 60 * 60 * 1000;
            p.intent.body = Some("old input".repeat(1000));
            if id == "automation" {
                p.origin = Some(Origin {
                    caller: "caller".into(),
                    source_hash: "source".into(),
                });
            }
            save_proposal(&host, &p).unwrap();
            external::execute(
                &host.db,
                &connection,
                &p.release,
                id,
                &p.intent,
                &mut provider,
            )
            .await
            .unwrap();
            let mut entry = external::inspect(&host.db, &connection, &p.release, id, "action")
                .unwrap()
                .unwrap();
            entry.receipt.as_mut().unwrap().body = "provider response".repeat(1000);
            if !matches!(id, "recent" | "recovered") {
                entry.settled_at = Some(p.created_at);
            }
            if id == "legacy" {
                entry.settled_at = None;
            }
            if id == "failed" {
                entry.receipt.as_mut().unwrap().status = 500;
            }
            host.db
                .kv
                .insert(
                    Tree::PluginMeta,
                    external::key(&connection, &p.release, id, "action").as_bytes(),
                    &serde_json::to_vec(&entry).unwrap(),
                )
                .unwrap();
            put(
                &host,
                "recovery",
                id,
                json!({"receipt":"duplicate response".repeat(1000)}),
            )
            .unwrap();
        }
        assert_eq!(
            compact_history(&host, None, false).await.unwrap().eligible,
            0
        );
        assert_eq!(
            compact_history_with_completed(&host, None, false, true)
                .await
                .unwrap()
                .eligible,
            1
        );
        assert_eq!(
            compact_history_with_completed(&host, None, true, true)
                .await
                .unwrap()
                .compacted,
            1
        );
        let p = saved(&host, "old").unwrap().unwrap();
        let entry = external::inspect(&host.db, &connection, &p.release, &p.id, "action")
            .unwrap()
            .unwrap();
        assert!(entry.archived.is_some());
        assert_eq!(entry.receipt.as_ref().unwrap().status, 201);
        assert!(entry.receipt.as_ref().unwrap().body.is_empty());
        assert!(marker(&host, "recovery", "old").unwrap().is_none());
        let writes = provider.writes;
        // Even a direct executor retry using the stripped intent cannot resend.
        assert!(external::execute(
            &host.db,
            &connection,
            &p.release,
            &p.id,
            &entry.intent,
            &mut provider
        )
        .await
        .unwrap_err()
        .contains("reserved"));
        assert_eq!(provider.writes, writes);
        assert!(invoke(host.clone(), call("old")).await.is_err());
        for id in ["recent", "legacy", "failed", "automation", "recovered"] {
            assert!(saved(&host, id).unwrap().unwrap().archived.is_none());
            assert!(marker(&host, "recovery", id).unwrap().is_some());
        }
        assert_eq!(
            compact_history_with_completed(&host, None, true, true)
                .await
                .unwrap()
                .compacted,
            0
        );
    }

    #[actix_web::test]
    async fn compaction_preserves_ids_and_skips_provider_and_automation_records() {
        let host = setup().await;
        invoke(host.clone(), call("recent")).await.unwrap();
        let template = saved(&host, "recent").unwrap().unwrap();
        for id in [
            "expired",
            "cancelled",
            "automation",
            "uncertain",
            "completed",
        ] {
            let mut p = template.clone();
            p.id = id.into();
            p.created_at = atomic_lib::utils::now() - 31 * 24 * 60 * 60 * 1000;
            p.arguments = json!({"title":"private".repeat(2000)});
            p.intent.body = Some("private request".repeat(2000));
            if id == "automation" {
                p.origin = Some(Origin {
                    caller: "caller".into(),
                    source_hash: "hash".into(),
                });
            }
            save_proposal(&host, &p).unwrap();
            if id == "cancelled" {
                cancel(&host, id).await.unwrap();
            }
            if matches!(id, "uncertain" | "completed") {
                let mut provider = Provider {
                    writes: 0,
                    lose: id == "uncertain",
                };
                let _ = external::execute(
                    &host.db,
                    &json!([host.drive, host.plugin]).to_string(),
                    &p.release,
                    id,
                    &p.intent,
                    &mut provider,
                )
                .await;
                assert_eq!(provider.writes, 1);
            }
        }
        let preview = compact_history(&host, None, false).await.unwrap();
        assert_eq!(preview.eligible, 2);
        assert_eq!(preview.compacted, 0);
        assert!(preview.reclaimable_bytes > 40000);
        assert!(saved(&host, "expired").unwrap().unwrap().archived.is_none());
        let applied = compact_history(&host, None, true).await.unwrap();
        assert_eq!(applied.compacted, 2);
        for id in ["expired", "cancelled"] {
            let p = saved(&host, id).unwrap().unwrap();
            assert!(p.archived.is_some());
            assert_eq!(p.arguments, json!({}));
            assert!(p.intent.body.is_none());
            assert!(p.intent.url.is_empty());
            assert!(invoke(host.clone(), call(id))
                .await
                .unwrap_err()
                .contains("reserved"));
            assert!(approve(host.clone(), id).await.is_err());
        }
        for id in ["recent", "automation", "uncertain", "completed"] {
            assert!(saved(&host, id).unwrap().unwrap().archived.is_none());
        }
        assert_eq!(
            compact_history(&host, None, true).await.unwrap().compacted,
            0
        );
        let rows = history(&host).await.unwrap();
        assert!(rows.iter().any(|row| row["state"] == "uncertain"));
        assert!(rows.iter().any(|row| row["state"] == "completed"));
        assert!(rows
            .iter()
            .any(|row| row["state"] == "expired" && row["proposal"]["archived"].is_object()));
    }

    #[actix_web::test]
    async fn history_pages_migrate_ties_and_isolate_actors_under_load() {
        let host = setup().await;
        invoke(host.clone(), call("seed")).await.unwrap();
        let mut p = saved(&host, "seed").unwrap().unwrap();
        let mut ops = Vec::new();
        for i in 0..2000 {
            p.id = format!("old-{i:05}");
            p.created_at = 1; // Every row has the same timestamp.
            ops.push(insert_op(
                key(&host, &p.id),
                serde_json::to_vec(&p).unwrap(),
            ));
        }
        p.id = "private".into();
        p.actor = "another-actor".into();
        ops.push(insert_op(
            key(&host, &p.id),
            serde_json::to_vec(&p).unwrap(),
        ));
        host.db.kv.apply_batch(&ops).unwrap();
        host.db
            .kv
            .remove(
                Tree::PluginMeta,
                format!(
                    "integration-action-history-ready/v1/{}",
                    json!([host.drive, host.plugin])
                )
                .as_bytes(),
            )
            .unwrap();
        let started = std::time::Instant::now();
        let first = history_page(&host, None, 37).await.unwrap();
        assert_eq!(first.entries.len(), 37);
        let mut ids = first
            .entries
            .iter()
            .map(|v| v["proposal"]["id"].as_str().unwrap().to_string())
            .collect::<std::collections::HashSet<_>>();
        // A new first-page entry must not shift the continuation cursor.
        invoke(host.clone(), call("newer")).await.unwrap();
        let mut cursor = first.next_cursor;
        while let Some(c) = cursor {
            let page = history_page(&host, Some(&c), 37).await.unwrap();
            for entry in page.entries {
                assert!(ids.insert(entry["proposal"]["id"].as_str().unwrap().to_string()));
            }
            cursor = page.next_cursor;
        }
        assert_eq!(ids.len(), 2001);
        assert_eq!(proposals(&host).await.unwrap().len(), 2);
        assert!(!ids.contains("private"));
        assert!(!ids.contains("newer"));
        assert!(history_page(&host, Some("../../private"), 10)
            .await
            .is_err());
        assert!(history_page(&host, None, 101).await.is_err());
        assert!(history_page(&host, None, 0).await.is_err());
        eprintln!(
            "history: migrated and paginated 2001 records in {:?}",
            started.elapsed()
        );
    }

    #[actix_web::test]
    async fn sandbox_actions_prepare_validate_and_pin_without_writing() {
        let host = setup().await;
        let catalog = list(&host).await.unwrap();
        assert_eq!(catalog["tools"][0]["name"], "get_issue");
        assert_eq!(catalog["tools"][0]["annotations"]["readOnlyHint"], true);
        assert!(invoke(
            host.clone(),
            Call {
                arguments: json!({"title":12}),
                ..call("bad")
            }
        )
        .await
        .is_err());
        assert!(invoke(
            host.clone(),
            Call {
                arguments: json!({"title":"x","url":"https://evil.test"}),
                ..call("bad2")
            }
        )
        .await
        .is_err());
        let prepared = invoke(host.clone(), call("one")).await.unwrap();
        assert_eq!(prepared["status"], "needs_review");
        let p = saved(&host, "one").unwrap().unwrap();
        assert_eq!(
            p.intent.url,
            "https://api.github.com/repos/atomic-fixtures/issues/issues"
        );
        assert!(external::inspect(
            &host.db,
            &json!([host.drive, host.plugin]).to_string(),
            &p.release,
            &p.id,
            "action"
        )
        .unwrap()
        .is_none());
        assert_eq!(
            invoke(host.clone(), call("one")).await.unwrap()["proposal"]["id"],
            "one"
        );
        assert!(invoke(
            host.clone(),
            Call {
                arguments: json!({"title":"changed"}),
                ..call("one")
            }
        )
        .await
        .is_err());
        let mut other = host.clone();
        other.for_agent = ForAgent::Public;
        assert!(invoke(other, call("private")).await.is_err());
    }
    #[actix_web::test]
    async fn sandbox_automation_action_requires_reference_and_release_pin() {
        let host = setup().await;
        let bound = binding(&host).await.unwrap();
        let request = json!({"connection":host.plugin,"release":bound.release,"call":call("automation-event-1")});
        assert!(
            invoke_from_plugin(&host, &request.to_string(), "fixture", false)
                .await
                .is_err()
        );
        let terms = drive_terms(&host.db, &host.drive).await.unwrap();
        let mut plugin = host
            .db
            .get_resource(&host.plugin.as_str().into())
            .await
            .unwrap();
        plugin
            .set_unsafe(
                terms.property("automation-integrations").unwrap().into(),
                AtomicValue::ResourceArray(vec![host.plugin.as_str().into()]),
            )
            .unwrap();
        plugin.save(&*host.db).await.unwrap();
        let mut stale = request.clone();
        stale["release"] = json!("stale");
        assert!(
            invoke_from_plugin(&host, &stale.to_string(), "fixture", false)
                .await
                .is_err()
        );
        let source = format!("export function run(ctx) {{ return ctx.integration({request}); }}");
        let output = embedded_runtime()
            .unwrap()
            .run(
                &source,
                r#"{"trigger":{"kind":"manual","at":1}}"#,
                host.clone(),
            )
            .await
            .unwrap()
            .unwrap();
        let result: Value = serde_json::from_str(&output).unwrap();
        assert!(result["integrationWaits"].is_array());
        assert!(result["integrationWaits"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("plugin-"));
        let again = embedded_runtime()
            .unwrap()
            .run(
                &source,
                r#"{"trigger":{"kind":"manual","at":1}}"#,
                host.clone(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&again).unwrap(), result);
        assert_eq!(proposals(&host).await.unwrap().len(), 1);
    }
    #[actix_web::test]
    async fn recovery_requires_fresh_read_evidence_and_never_resends() {
        let host = setup().await;
        let bound = binding(&host).await.unwrap();
        invoke(host.clone(), call("lost")).await.unwrap();
        let p = owned(&host, "lost").unwrap();
        let mut provider = Provider {
            writes: 0,
            lose: true,
        };
        assert!(execute_approved(
            &host.db,
            &json!([host.drive, host.plugin]).to_string(),
            &p.actor,
            &bound,
            &p,
            &mut provider
        )
        .await
        .is_err());
        assert!(confirm_recovery(&host, "lost").await.is_err());
        assert!(
            inspect_recovery(host.clone(), "lost", call("not-a-read"), "check")
                .await
                .is_err()
        );
        let candidate = json!({"receipt":{"status":200,"body":"{\"number\":1}"},"evidence":"Matching provider audit record","at":0,"release":bound.release,"config":bound.config});
        put(&host, "recovery", "lost", candidate.clone()).unwrap();
        assert!(confirm_recovery(&host, "lost").await.is_err());
        let mut candidate = candidate;
        candidate["at"] = json!(atomic_lib::utils::now());
        put(&host, "recovery", "lost", candidate).unwrap();
        confirm_recovery(&host, "lost").await.unwrap();
        assert_eq!(
            invoke(host.clone(), call("lost")).await.unwrap()["status"],
            "completed"
        );
        assert_eq!(provider.writes, 1);
        assert!(confirm_recovery(&host, "lost").await.is_err());
        assert_eq!(
            history(&host).await.unwrap()[0]["resolution"]["evidence"],
            "Matching provider audit record"
        );
    }

    #[actix_web::test]
    async fn grants_pin_actor_source_release_config_and_can_be_revoked() {
        let host = setup().await;
        let bound = binding(&host).await.unwrap();
        let terms = drive_terms(&host.db, &host.drive).await.unwrap();
        let mut p = host
            .db
            .get_resource(&host.plugin.as_str().into())
            .await
            .unwrap();
        p.set_unsafe(
            terms.property("automation-integrations").unwrap().into(),
            AtomicValue::ResourceArray(vec![host.plugin.as_str().into()]),
        )
        .unwrap();
        p.save(&*host.db).await.unwrap();
        let source = super::super::scheduler::plugin_source(&host.db, &host.drive, &host.plugin)
            .await
            .unwrap();
        let origin = Origin {
            caller: host.plugin.clone(),
            source_hash: blake3::hash(source.as_bytes()).to_hex().to_string(),
        };
        assert!(valid_grant(&host, &origin, "create_issue", &bound)
            .await
            .unwrap()
            .is_none());
        set_grant(&host, &host.plugin, "create_issue", "automatic")
            .await
            .unwrap();
        assert_eq!(
            valid_grant(&host, &origin, "create_issue", &bound)
                .await
                .unwrap()
                .unwrap()
                .mode,
            "automatic"
        );
        assert_eq!(grants(&host).await.unwrap().len(), 1);
        assert!(valid_grant(
            &host,
            &Origin {
                source_hash: "edited".into(),
                ..origin.clone()
            },
            "create_issue",
            &bound
        )
        .await
        .is_err());
        assert!(valid_grant(
            &host,
            &origin,
            "create_issue",
            &Binding {
                config: json!({}),
                ..bound.clone()
            }
        )
        .await
        .is_err());
        assert!(valid_grant(&host, &origin, "get_issue", &bound)
            .await
            .unwrap()
            .is_none());
        let mut other = host.clone();
        other.for_agent = ForAgent::Public;
        assert!(set_grant(&other, &host.plugin, "create_issue", "automatic")
            .await
            .is_err());
        assert!(valid_grant(&other, &origin, "create_issue", &bound)
            .await
            .unwrap()
            .is_none());
        host.db.set_node_key([7; atomic_lib::vault::keys::KEK_LEN]);
        let app = atomic_lib::agents::Agent::new(Some("fixture app")).unwrap();
        host.db
            .set_app_agent(
                &atomic_lib::db::app_agent::AppAgentKey::new(&host.drive, &host.plugin),
                &atomic_lib::db::app_agent::AppAgent::new(
                    app.subject.to_string(),
                    app.build_secret().unwrap(),
                    0,
                ),
            )
            .unwrap();
        set_grant(&host, &host.plugin, "create_issue", "automatic")
            .await
            .unwrap();
        let request =
            json!({"connection":host.plugin,"release":bound.release,"call":call("app-call")});
        assert_eq!(
            serde_json::from_str::<Value>(
                &invoke_from_plugin(&host, &request.to_string(), &origin.source_hash, false)
                    .await
                    .unwrap()
            )
            .unwrap()["status"],
            "needs_review"
        );
        set_grant(&host, &host.plugin, "create_issue", "revoke")
            .await
            .unwrap();
        assert!(valid_grant(&host, &origin, "create_issue", &bound)
            .await
            .unwrap()
            .is_none());
        assert!(grants(&host).await.unwrap().is_empty());
        assert!(
            invoke_from_plugin(&host, &request.to_string(), &origin.source_hash, false)
                .await
                .is_err()
        );
        put(
            &host,
            "rate",
            &host.for_agent.to_string(),
            json!({"at":0,"count":0}),
        )
        .unwrap();

        for _ in 0..60 {
            admit(&host).unwrap();
        }
        assert!(admit(&host).is_err());
    }

    #[actix_web::test]
    async fn history_keeps_uncertainty_and_replay_returns_completed_receipt() {
        let host = setup().await;
        invoke(host.clone(), call("receipt")).await.unwrap();
        let p = saved(&host, "receipt").unwrap().unwrap();
        let connection = json!([host.drive, host.plugin]).to_string();
        let mut provider = Provider {
            writes: 0,
            lose: false,
        };
        execute_approved(
            &host.db,
            &connection,
            &p.actor,
            &binding(&host).await.unwrap(),
            &p,
            &mut provider,
        )
        .await
        .unwrap();
        let replay = invoke(host.clone(), call("receipt")).await.unwrap();
        assert_eq!(replay["status"], "completed");
        assert_eq!(provider.writes, 1);
        assert_eq!(history(&host).await.unwrap()[0]["state"], "completed");
        invoke(host.clone(), call("lost")).await.unwrap();
        let p = saved(&host, "lost").unwrap().unwrap();
        provider.lose = true;
        assert!(execute_approved(
            &host.db,
            &connection,
            &p.actor,
            &binding(&host).await.unwrap(),
            &p,
            &mut provider
        )
        .await
        .is_err());
        assert!(history(&host)
            .await
            .unwrap()
            .iter()
            .any(|v| v["state"] == "uncertain"));
        assert!(invoke(host.clone(), call("lost"))
            .await
            .unwrap_err()
            .contains("uncertain"));
        invoke(host.clone(), call("cancel")).await.unwrap();
        cancel(&host, "cancel").await.unwrap();
        assert!(approve(host.clone(), "cancel").await.is_err());
        assert!(invoke(host.clone(), call("cancel")).await.is_err());
        assert!(history(&host)
            .await
            .unwrap()
            .iter()
            .any(|v| v["state"] == "cancelled"));
    }
    #[actix_web::test]
    async fn action_approval_rejects_stale_actor_and_expiry_and_never_repeats_uncertain_writes() {
        let host = setup().await;
        invoke(host.clone(), call("one")).await.unwrap();
        let p = saved(&host, "one").unwrap().unwrap();
        let bound = binding(&host).await.unwrap();
        let mut provider = Provider {
            writes: 0,
            lose: false,
        };
        assert!(
            execute_approved(&host.db, "fixture", "other", &bound, &p, &mut provider)
                .await
                .is_err()
        );
        assert!(execute_approved(
            &host.db,
            "fixture",
            &p.actor,
            &Binding {
                release: "changed".into(),
                config: bound.config.clone()
            },
            &p,
            &mut provider
        )
        .await
        .is_err());
        assert!(execute_approved(
            &host.db,
            "fixture",
            &p.actor,
            &Binding {
                release: bound.release.clone(),
                config: json!({})
            },
            &p,
            &mut provider
        )
        .await
        .is_err());
        let mut expired = p.clone();
        expired.created_at = 0;
        assert!(execute_approved(
            &host.db,
            "fixture",
            &p.actor,
            &bound,
            &expired,
            &mut provider
        )
        .await
        .is_err());
        assert_eq!(provider.writes, 0);
        execute_approved(&host.db, "fixture", &p.actor, &bound, &p, &mut provider)
            .await
            .unwrap();
        execute_approved(&host.db, "fixture", &p.actor, &bound, &p, &mut provider)
            .await
            .unwrap();
        assert_eq!(provider.writes, 1);
        let mut uncertain = p.clone();
        uncertain.id = "uncertain".into();
        provider.lose = true;
        assert!(execute_approved(
            &host.db,
            "fixture",
            &p.actor,
            &bound,
            &uncertain,
            &mut provider
        )
        .await
        .is_err());
        assert!(execute_approved(
            &host.db,
            "fixture",
            &p.actor,
            &bound,
            &uncertain,
            &mut provider
        )
        .await
        .is_err());
        assert_eq!(provider.writes, 2);
    }
}
