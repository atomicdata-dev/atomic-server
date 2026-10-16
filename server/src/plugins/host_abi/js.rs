//! The host ABI for QuickJS run plugins (`/plugin-run`, triggers, schedules).
//!
//! A run plugin gets the same `store`, `net` and `calls` functions as a
//! component, under the same names and error codes. They are the same host
//! code: each call builds an [`AbiState`] for the plugin's Installation and
//! calls the interface implementation a component would reach, so the rights
//! are the same too. Each hop is bounded by the Installation's agent and the
//! caller of the run; `calls.call` goes through [`call_export`] under one
//! [`CallBudget`] for the whole run.
//!
//! Only the JSON form is new. Values cross as `{tag, val}` (the WIT variant
//! case and payload), fields are camelCase, an error is `{code, message}`.
//!
//! A run plugin proposes writes by returning intents; `store.apply` is
//! therefore `needs-approval` here, and by default the budget allows only
//! `read` exports, as for a frame. Widening it is the approval work of step 2.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value as Json};
use wasmtime::StoreLimitsBuilder;

use super::{
    bindings::atomic::host::{
        calls::{self, AppExport, Effect},
        net::{self, Header, Request},
        store::{self, Filter, FilterOp, Page, QuerySpec},
        types::{Resource, Value},
    },
    code, error,
    registry::HostAbiRegistry,
    run::{build_host, with_deadline, AbiState, CallBudget, ENTRY_TIMEOUT},
    HostError,
};
use crate::plugins::{
    host_core::{PluginHost, ResourceGrants},
    js_runtime::StoreHost,
    manifest::ExportEffect,
};

/// A [`StoreHost`] that also answers the host ABI.
pub struct JsAbi {
    host: StoreHost,
    registry: Arc<HostAbiRegistry>,
    budget: Arc<CallBudget>,
    refreshed: bool,
}

impl JsAbi {
    pub fn new(host: StoreHost, registry: Arc<HostAbiRegistry>) -> Self {
        Self {
            host,
            registry,
            budget: Arc::new(CallBudget::default().only(vec![ExportEffect::Read])),
            refreshed: false,
        }
    }

    /// The budget of the run's calls, instead of reads only.
    pub fn with_budget(mut self, budget: CallBudget) -> Self {
        self.budget = Arc::new(budget);
        self
    }

    async fn dispatch(&mut self, function: &str, args: &str) -> Result<String, HostError> {
        let args: Vec<Json> = serde_json::from_str(args)
            .map_err(|e| invalid(format!("the arguments are not a JSON array: {e}")))?;
        if function.starts_with("calls.") && !self.refreshed {
            self.registry.refresh(&self.host.db, &self.host.drive).await;
            self.refreshed = true;
        }
        // Per call, like `StoreHost::core`: a revocation between two calls of
        // one run takes effect on the second.
        let host = build_host(
            &self.registry,
            &self.host.db,
            (
                &self.host.drive,
                &self.host.plugin,
                self.host.manifest.clone(),
            ),
            self.host.for_agent.clone(),
            0,
            self.budget.clone(),
        )
        .await?;
        let mut state = AbiState::new(host, StoreLimitsBuilder::new().build());
        let text = |i: usize| -> Result<String, HostError> {
            args.get(i)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| invalid(format!("argument {i} of {function} must be a string")))
        };
        let out = match function {
            "store.get" => resource_json(&store::Host::get(&mut state, text(0)?).await?),
            "store.get-many" => {
                let subjects: Vec<String> = serde_json::from_value(arg(&args, 0)?)
                    .map_err(|e| invalid(format!("get-many takes a list of subjects: {e}")))?;
                Json::Array(
                    store::Host::get_many(&mut state, subjects)
                        .await
                        .iter()
                        .map(|r| match r {
                            Ok(resource) => json!({ "ok": resource_json(resource) }),
                            Err(e) => json!({ "error": error_json(e) }),
                        })
                        .collect(),
                )
            }
            "store.query" => {
                let spec = query_spec(arg(&args, 0)?)?;
                page_json(&store::Host::query(&mut state, spec).await?)
            }
            "store.apply" => {
                return Err(error(
                    code::NEEDS_APPROVAL,
                    "a run plugin proposes writes by returning intents; the host plans and applies them after review",
                ))
            }
            "net.fetch" => {
                let request: JsFetch = serde_json::from_value(arg(&args, 0)?)
                    .map_err(|e| invalid(format!("not a net request: {e}")))?;
                let response = net::Host::fetch(&mut state, request.into()).await?;
                json!({
                    "status": response.status,
                    "headers": response.headers.iter().map(|h| json!({"name": h.name, "value": h.value})).collect::<Vec<_>>(),
                    // Text, as the host reads it (`HostCore::fetch`).
                    "body": String::from_utf8_lossy(&response.body),
                })
            }
            "calls.providers" => json!(calls::Host::providers(&mut state, text(0)?).await),
            "calls.describe" => Json::Array(
                calls::Host::describe(&mut state, text(0)?)
                    .await?
                    .iter()
                    .map(export_json)
                    .collect(),
            ),
            "calls.call" => {
                let handles = args.get(3).and_then(Json::as_array).map_or(0, Vec::len);
                if handles > 0 {
                    // The same as for a component: accepted nowhere yet.
                    return Err(error(
                        code::UNSUPPORTED,
                        "handles are not supported yet",
                    ));
                }
                let result = with_deadline(
                    ENTRY_TIMEOUT,
                    calls::Host::call(
                        &mut state,
                        text(0)?,
                        text(1)?,
                        arg(&args, 2)?.to_string(),
                        Vec::new(),
                    ),
                )
                .await?;
                return Ok(result);
            }
            other => {
                return Err(error(
                    code::UNSUPPORTED,
                    format!("{other} is not available to run plugins"),
                ))
            }
        };
        Ok(out.to_string())
    }
}

fn invalid(message: impl Into<String>) -> HostError {
    error(code::INVALID_ARGUMENT, message)
}

fn arg(args: &[Json], i: usize) -> Result<Json, HostError> {
    args.get(i)
        .cloned()
        .ok_or_else(|| invalid(format!("argument {i} is missing")))
}

fn error_json(e: &HostError) -> Json {
    json!({ "code": e.code, "message": e.message })
}

fn value_json(value: &Value) -> Json {
    let (tag, val) = match value {
        Value::Null => ("null", Json::Null),
        Value::Boolean(b) => ("boolean", json!(b)),
        Value::Integer(i) => ("integer", json!(i)),
        Value::Float(f) => ("float", json!(f)),
        Value::String(s) => ("string", json!(s)),
        Value::Link(s) => ("link", json!(s)),
        Value::ResourceArray(items) => ("resource-array", json!(items)),
        Value::Json(text) => ("json", serde_json::from_str(text).unwrap_or(Json::Null)),
    };
    json!({ "tag": tag, "val": val })
}

fn json_value(value: &Json) -> Result<Value, HostError> {
    let tag = value["tag"].as_str().unwrap_or_default();
    let val = &value["val"];
    let bad = || invalid(format!("not a {tag} value: {val}"));
    Ok(match tag {
        "null" => Value::Null,
        "boolean" => Value::Boolean(val.as_bool().ok_or_else(bad)?),
        "integer" => Value::Integer(val.as_i64().ok_or_else(bad)?),
        "float" => Value::Float(val.as_f64().ok_or_else(bad)?),
        "string" => Value::String(val.as_str().ok_or_else(bad)?.into()),
        "link" => Value::Link(val.as_str().ok_or_else(bad)?.into()),
        "resource-array" => {
            Value::ResourceArray(serde_json::from_value(val.clone()).map_err(|_| bad())?)
        }
        "json" => Value::Json(val.to_string()),
        _ => {
            return Err(invalid(
                "a value is {tag, val} with a tag of the WIT variant `value`",
            ))
        }
    })
}

fn resource_json(resource: &Resource) -> Json {
    json!({
        "subject": resource.subject,
        "classes": resource.classes,
        "propvals": resource.propvals.iter().map(|pv| json!({"property": pv.property, "value": value_json(&pv.value)})).collect::<Vec<_>>(),
    })
}

fn page_json(page: &Page) -> Json {
    json!({
        "subjects": page.subjects,
        "resources": page.resources.iter().map(resource_json).collect::<Vec<_>>(),
        "cursor": page.cursor,
        "complete": page.complete,
    })
}

fn export_json(export: &AppExport) -> Json {
    json!({
        "interface": export.interface,
        "function": export.function,
        "description": export.description,
        "inputSchema": serde_json::from_str::<Json>(&export.input_schema).unwrap_or(Json::Null),
        "outputSchema": serde_json::from_str::<Json>(&export.output_schema).unwrap_or(Json::Null),
        "effect": match export.effect {
            Effect::Read => "read",
            Effect::Write => "write",
            Effect::External => "external",
            Effect::Interactive => "interactive",
        },
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsQuery {
    class: Option<String>,
    parent: Option<String>,
    #[serde(default)]
    filters: Vec<JsFilter>,
    sort_by: Option<String>,
    #[serde(default)]
    sort_desc: bool,
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    with_resources: bool,
}

#[derive(Deserialize)]
struct JsFilter {
    property: String,
    op: String,
    value: Option<Json>,
}

fn query_spec(raw: Json) -> Result<QuerySpec, HostError> {
    let q: JsQuery =
        serde_json::from_value(raw).map_err(|e| invalid(format!("not a query: {e}")))?;
    let filters = q
        .filters
        .into_iter()
        .map(|f| {
            Ok(Filter {
                op: match f.op.as_str() {
                    "eq" => FilterOp::Eq,
                    "ne" => FilterOp::Ne,
                    "lt" => FilterOp::Lt,
                    "lte" => FilterOp::Lte,
                    "gt" => FilterOp::Gt,
                    "gte" => FilterOp::Gte,
                    "contains" => FilterOp::Contains,
                    "exists" => FilterOp::Exists,
                    other => return Err(invalid(format!("{other} is not a filter op"))),
                },
                value: f.value.as_ref().map(json_value).transpose()?,
                property: f.property,
            })
        })
        .collect::<Result<_, HostError>>()?;
    Ok(QuerySpec {
        class: q.class,
        parent: q.parent,
        filters,
        sort_by: q.sort_by,
        sort_desc: q.sort_desc,
        limit: q.limit,
        cursor: q.cursor,
        with_resources: q.with_resources,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsFetch {
    operation: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: Vec<(String, String)>,
    #[serde(default)]
    headers: Vec<JsHeader>,
    body: Option<String>,
    if_match: Option<String>,
}

#[derive(Deserialize)]
struct JsHeader {
    name: String,
    value: String,
}

impl From<JsFetch> for Request {
    fn from(f: JsFetch) -> Self {
        Request {
            operation: f.operation,
            path: f.path,
            query: f.query,
            headers: f
                .headers
                .into_iter()
                .map(|h| Header {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: f.body.map(String::into_bytes),
            if_match: f.if_match,
        }
    }
}

/// Everything but the ABI is the wrapped host's.
#[async_trait::async_trait]
impl PluginHost for JsAbi {
    async fn invoke_action(
        &mut self,
        request: String,
        source_hash: &str,
        allow_automatic: bool,
        consumer: Option<&str>,
    ) -> Result<String, String> {
        self.host
            .invoke_action(request, source_hash, allow_automatic, consumer)
            .await
    }
    async fn fetch(&mut self, request: String) -> Result<String, String> {
        self.host.fetch(request).await
    }
    async fn get_resource(&mut self, subject: String) -> Result<String, String> {
        self.host.get_resource(subject).await
    }
    async fn query(&mut self, property: String, value: String) -> Result<String, String> {
        self.host.query(property, value).await
    }
    async fn abi(&mut self, function: &str, args: &str) -> Result<String, HostError> {
        self.dispatch(function, args).await
    }
    async fn resource_grants(&mut self) -> ResourceGrants {
        self.host.resource_grants().await
    }
}
