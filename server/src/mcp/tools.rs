//! The tools of the hosted MCP endpoint. They run as the issued agent behind
//! the bearer token, through the same rights checks as any request. Reading
//! needs nothing more; the write tools exist only when the person allowed
//! editing, and sign their commits as that issued agent (see [`super::write`]).

use std::sync::LazyLock;

use atomic_lib::{agents::ForAgent, client::search::SearchOpts, urls, Storelike, Subject};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    compact::{build_context, coerce_value, describe_class, is_subject, standard_class_alias},
    document_text::document_text,
    schema,
    tokens::Grant,
    write::{classes_on_drive, str_arg, Writer},
};
use crate::appstate::AppState;

const MAX_SUBJECTS: usize = 20;

pub const READ_INSTRUCTIONS: &str = "Tools for reading Atomic Data (a graph of resources, each with a subject such as did:ad:… and properties). This connection is read-only: it can find and read what the person approved, and cannot change it. Start with list_drives or search, then read resources with get_resource. Use find_schema to look up the classes (types) that exist, with their JSON Schema.";

pub const WRITE_INSTRUCTIONS: &str = "Tools for reading and editing Atomic Data (a graph of resources, each with a subject such as did:ad:… and properties). Edits are made as this connection's own identity, within what the person approved. Start with list_drives or search, read resources with get_resource, and call find_schema before creating resources of a custom class. To add a new type, search with find_schema first and reuse an existing class if one fits; only then describe the missing ones as a JSON Schema for ensure_ontology. Property names are shortnames from a class's schema (full property URLs also work); select values take tag names and dates take ISO strings.";

pub fn instructions(write: bool) -> &'static str {
    if write {
        WRITE_INSTRUCTIONS
    } else {
        READ_INSTRUCTIONS
    }
}

/// One built-in tool as data. `tools.json` holds them all, in the order
/// they are listed; `effect` decides read/write gating and the default
/// annotations, and `annotations` only adds hints on top of those.
#[derive(Deserialize)]
struct ActionSpec {
    name: String,
    title: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    effect: Effect,
    #[serde(default)]
    annotations: serde_json::Map<String, Value>,
}

#[derive(Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Effect {
    Read,
    Write,
}

static SPECS: LazyLock<Vec<ActionSpec>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("tools.json")).expect("tools.json is valid")
});

impl ActionSpec {
    fn render(&self) -> Value {
        let mut annotations = match self.effect {
            Effect::Read => json!({"readOnlyHint": true}),
            Effect::Write => json!({"readOnlyHint": false, "destructiveHint": false}),
        };
        annotations
            .as_object_mut()
            .expect("object")
            .extend(self.annotations.clone());

        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": annotations,
        })
    }
}

/// The tools a connection may call: the read tools, and the write tools only
/// when the person allowed editing.
pub fn list(write: bool) -> Value {
    SPECS
        .iter()
        .filter(|spec| write || spec.effect == Effect::Read)
        .map(ActionSpec::render)
        .collect()
}

/// Runs a tool. `Err` becomes a tool error the model reads.
pub async fn call(
    appstate: &AppState,
    origin: &str,
    req: &actix_web::HttpRequest,
    grant: &Grant,
    name: &str,
    args: &Value,
) -> Result<Value, String> {
    let agent = grant.agent.as_str();
    let for_agent = ForAgent::AgentSubject(Subject::from_raw(agent, None));

    match name {
        "list_drives" => Ok(json!(shared_drives(appstate, &for_agent, agent).await?)),
        "get_resource" => get_resource(appstate, origin, &for_agent, args).await,
        "search" => search(appstate, &for_agent, args).await,
        "query" => query(appstate, &for_agent, agent, args).await,
        "find_schema" => schema::find_schema(appstate, &for_agent, agent, args, None).await,
        "get_user_classes" => schema::get_user_classes(appstate, &for_agent, agent, args).await,
        "get_schema" => get_schema(appstate, &for_agent, agent, args).await,
        "edit_resource" | "create_resource" | "delete_resource" | "ensure_ontology" => {
            // Writes are rate limited per agent, like any signed write.
            crate::helpers::enforce_write_rate_limit(appstate, req, &for_agent)
                .map_err(|e| e.to_string())?;
            let writer = Writer::new(appstate, origin, grant)?;

            match name {
                "edit_resource" => writer.edit(args).await,
                "create_resource" => writer.create(args).await,
                "ensure_ontology" => writer.ensure_ontology(args).await,
                _ => writer.delete(args).await,
            }
        }
        // Exports of the drives' apps, named from interface and function.
        other => match super::exports::call(appstate, req, grant, other, args).await {
            Some(outcome) => outcome,
            None => Err(format!("Unknown tool {other}")),
        },
    }
}

/// The drive a tool works in when the call names none: the first shared one.
pub(super) async fn default_drive(
    appstate: &AppState,
    for_agent: &ForAgent,
    agent: &str,
    args: &Value,
) -> Result<String, String> {
    if let Some(drive) = args.get("drive").and_then(Value::as_str) {
        return Ok(drive.to_string());
    }

    shared_drives(appstate, for_agent, agent)
        .await?
        .first()
        .and_then(|d| d["subject"].as_str().map(str::to_string))
        .ok_or_else(|| "No drive has been shared with this connection.".to_string())
}

fn string_list(args: &Value, key: &str) -> Option<Vec<String>> {
    args.get(key).and_then(Value::as_array).map(|list| {
        list.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

/// A class name as a subject: a URL, a built-in, or one defined on the drive.
async fn resolve_class_name(
    appstate: &AppState,
    for_agent: &ForAgent,
    drive: &str,
    name: &str,
) -> Result<String, String> {
    if is_subject(name) {
        return Ok(name.to_string());
    }
    if let Some(standard) = standard_class_alias(name) {
        return Ok(standard.to_string());
    }
    let wanted = name.to_lowercase();
    for subject in classes_on_drive(appstate, drive)? {
        if title(appstate, &subject, for_agent)
            .await
            .is_some_and(|t| t.to_lowercase() == wanted)
        {
            return Ok(subject);
        }
    }

    Err(format!(
        "Unknown class \"{name}\". Use find_schema to look for classes, or pass a full class URL."
    ))
}

async fn get_schema(
    appstate: &AppState,
    for_agent: &ForAgent,
    agent: &str,
    args: &Value,
) -> Result<Value, String> {
    let name = str_arg(args, "subject")?;
    let drive = if is_subject(name) || standard_class_alias(name).is_some() {
        String::new()
    } else {
        default_drive(appstate, for_agent, agent, args).await?
    };
    let class = resolve_class_name(appstate, for_agent, &drive, name).await?;

    describe_class(appstate, &class).await
}

async fn query(
    appstate: &AppState,
    for_agent: &ForAgent,
    agent: &str,
    args: &Value,
) -> Result<Value, String> {
    let conditions = args
        .get("where")
        .and_then(Value::as_array)
        .ok_or("where must be an array")?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .clamp(1, 200) as usize;
    let parents = match string_list(args, "parents") {
        Some(p) if !p.is_empty() => p,
        _ => vec![default_drive(appstate, for_agent, agent, args).await?],
    };

    let class = match args.get("class").and_then(Value::as_str) {
        Some(name) => Some(resolve_class_name(appstate, for_agent, &parents[0], name).await?),
        None => None,
    };
    let ctx = build_context(appstate, class.as_slice()).await;

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut filter_props = Vec::new();
    for condition in conditions {
        let property = str_arg(condition, "property")?;
        let value = condition
            .get("value")
            .ok_or("Each condition needs a value")?;
        if class.is_none() && !is_subject(property) {
            return Err(format!(
                "Invalid property subject in where clause: '{property}'. Pass `class` to use shortnames."
            ));
        }
        let info = ctx.resolve(appstate, property).await?;
        let values = match coerce_value(&info, value)? {
            Value::Array(items) => items,
            other => vec![other],
        };
        for v in values {
            pairs.push((
                info.subject.clone(),
                match v {
                    Value::String(s) => s,
                    other => other.to_string(),
                },
            ));
        }
        filter_props.push(info);
    }
    if let Some(class) = &class {
        pairs.push((urls::IS_A.to_string(), class.clone()));
    }

    let opts = SearchOpts {
        // More than asked for: the agent may not read some of what matches.
        limit: Some((limit * 3) as u32),
        parents: Some(parents),
        filter_pairs: Some(pairs),
        ..Default::default()
    };
    let hits = atomic_lib::search::query(&appstate.store, "", &opts).map_err(|e| e.to_string())?;

    let mut select = Vec::new();
    match string_list(args, "select") {
        Some(keys) => {
            for key in keys {
                select.push(ctx.resolve(appstate, &key).await?);
            }
        }
        None => select.push(ctx.resolve(appstate, urls::NAME).await?),
    }
    select.extend(filter_props);

    let mut out = Vec::new();
    for hit in hits {
        if out.len() >= limit {
            break;
        }
        let subject = hit.subject.to_string();
        let Ok(response) = appstate
            .store
            .get_resource_extended(&subject.as_str().into(), true, for_agent)
            .await
        else {
            continue;
        };
        let resource = response.to_single();
        let mut entry = serde_json::Map::new();
        entry.insert("@id".into(), json!(subject));
        for info in &select {
            if let Ok(value) = resource.get(&info.subject) {
                entry.insert(info.shortname.clone(), json!(value.to_string()));
            }
        }
        out.push(Value::Object(entry));
    }

    Ok(json!(out))
}

async fn title(appstate: &AppState, subject: &str, for_agent: &ForAgent) -> Option<String> {
    let resource = appstate
        .store
        .get_resource_extended(&subject.into(), true, for_agent)
        .await
        .ok()?
        .to_single();

    resource.get(urls::NAME).ok().map(|v| v.to_string())
}

/// What the person shared: resources whose `read` (or `write`) lists this agent.
pub(super) async fn shared_drives(
    appstate: &AppState,
    for_agent: &ForAgent,
    agent: &str,
) -> Result<Vec<Value>, String> {
    let mut found = Vec::new();

    for (property, editable) in [(urls::READ, false), (urls::WRITE, true)] {
        let opts = SearchOpts {
            limit: Some(100),
            filter_pairs: Some(vec![(property.to_string(), agent.to_string())]),
            ..Default::default()
        };
        for hit in
            atomic_lib::search::query(&appstate.store, "", &opts).map_err(|e| e.to_string())?
        {
            found.push((hit.subject.to_string(), editable));
        }
    }

    let mut out: Vec<Value> = Vec::new();
    for (subject, editable) in found {
        if let Some(existing) = out.iter_mut().find(|v| v["subject"] == subject) {
            if editable {
                existing["canEdit"] = json!(true);
            }
            continue;
        }
        let Some(name) = title(appstate, &subject, for_agent).await else {
            continue;
        };
        out.push(json!({"subject": subject, "name": name, "canEdit": editable}));
    }

    Ok(out)
}

async fn get_resource(
    appstate: &AppState,
    origin: &str,
    for_agent: &ForAgent,
    args: &Value,
) -> Result<Value, String> {
    let subjects: Vec<&str> = args
        .get("subjects")
        .and_then(Value::as_array)
        .ok_or("subjects must be an array")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if subjects.is_empty() || subjects.len() > MAX_SUBJECTS {
        return Err(format!("Give between 1 and {MAX_SUBJECTS} subjects"));
    }

    let store = appstate.store.clone_with_url(origin.to_string());
    let mut result = serde_json::Map::new();

    for subject in subjects {
        let entry = match store
            .get_resource_extended(&subject.into(), true, for_agent)
            .await
        {
            Ok(response) => {
                let resource = response.to_single();
                let mut json: Value = resource
                    .to_json(&store, Some(origin))
                    .await
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);

                let is_document = resource.get_classes(&store).await.is_ok_and(|classes| {
                    classes.iter().any(|c| {
                        c.subject.as_str() == "https://atomicdata.dev/classes/DocumentV2"
                            || c.subject.as_str() == "https://atomicdata.dev/classes/Meeting"
                    })
                });
                if is_document {
                    if let (Some(object), Ok(state)) =
                        (json.as_object_mut(), resource.build_state_doc())
                    {
                        let body =
                            serde_json::to_value(state.doc().get_map("doc").get_deep_value())
                                .unwrap_or(Value::Null);
                        object.insert("_documentText".into(), json!(document_text(&body)));
                    }
                }
                json
            }
            // The message is the rights check's or the store's; it says
            // "unauthorized" or "not found" without leaking either way.
            Err(e) => json!(format!("Error: {e}")),
        };
        result.insert(subject.to_string(), entry);
    }

    Ok(Value::Object(result))
}

async fn search(appstate: &AppState, for_agent: &ForAgent, args: &Value) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .ok_or("query must be a string")?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 50) as usize;
    let parents = args.get("parents").and_then(Value::as_array).map(|list| {
        list.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>()
    });

    // More than asked for: the agent may not read some of what matches.
    let opts = SearchOpts {
        limit: Some((limit * 3) as u32),
        parents,
        ..Default::default()
    };
    let hits =
        atomic_lib::search::query(&appstate.store, query, &opts).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for hit in hits {
        if out.len() >= limit {
            break;
        }
        let subject = hit.subject.to_string();
        let Ok(response) = appstate
            .store
            .get_resource_extended(&subject.as_str().into(), true, for_agent)
            .await
        else {
            continue;
        };
        let resource = response.to_single();
        out.push(json!({
            "subject": subject,
            "name": resource.get(urls::NAME).ok().map(|v| v.to_string()),
        }));
    }

    Ok(json!(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: [&str; 7] = [
        "list_drives",
        "get_resource",
        "search",
        "query",
        "find_schema",
        "get_user_classes",
        "get_schema",
    ];
    const WRITE: [&str; 4] = [
        "edit_resource",
        "create_resource",
        "ensure_ontology",
        "delete_resource",
    ];

    fn names(write: bool) -> Vec<String> {
        list(write)
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn tools_json_parses_and_lists_in_order() {
        assert_eq!(SPECS.len(), 11);
        assert_eq!(names(false), READ);
        assert_eq!(names(true), [READ.as_slice(), WRITE.as_slice()].concat());
    }

    #[test]
    fn annotations_follow_effect() {
        let tools = list(true);
        let tool = |name: &str| {
            tools
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == name)
                .unwrap()
                .clone()
        };

        assert_eq!(tool("search")["annotations"], json!({"readOnlyHint": true}));
        assert_eq!(
            tool("edit_resource")["annotations"],
            json!({"readOnlyHint": false, "destructiveHint": false})
        );
        assert_eq!(
            tool("delete_resource")["annotations"],
            json!({"readOnlyHint": false, "destructiveHint": true})
        );
        assert_eq!(
            tool("ensure_ontology")["annotations"],
            json!({"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true})
        );
    }

    #[test]
    fn schema_limit_matches_constant() {
        let tools = list(false);
        let get = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "get_resource")
            .unwrap();

        assert_eq!(
            get["inputSchema"]["properties"]["subjects"]["maxItems"],
            json!(MAX_SUBJECTS)
        );
    }
}
