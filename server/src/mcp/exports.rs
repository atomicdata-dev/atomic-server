//! Exports of installed `sandboxed-app`s as MCP tools.
//!
//! Every export a drive's apps declare (`planning/host-abi.md`, step 5) is a
//! tool named from its interface and function, with the export's description
//! and `inputSchema`. A call goes through [`host_abi::call_for_agent`], the
//! same path as `POST /host/call`: the issued agent must read the drive, and
//! write it for a `write` export or an app that declares secrets. The person's
//! own say applies on top: a read-only connection is offered only `read`
//! exports of apps without secrets.
//!
//! `external` and `interactive` exports are not offered: the first reaches out
//! to the world and the second needs a person present, and neither has an
//! approval step over MCP yet.

use std::sync::Arc;

use atomic_lib::{agents::ForAgent, Storelike};
use serde_json::{json, Value};

use super::tokens::Grant;
use crate::{
    appstate::AppState,
    plugins::{
        host_abi::{self, CallBudget, LoadedApp},
        manifest::{Export, ExportEffect},
    },
};

const MAX_NAME: usize = 64;

/// A stable tool name: `atomic:example/counter@1` `increment` becomes
/// `atomic_example_counter_1__increment`. Anything outside `[a-z0-9_]` becomes
/// `_`; a name over 64 characters keeps its tail and a hash of the whole.
pub fn tool_name(interface: &str, function: &str) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| {
                let c = c.to_ascii_lowercase();
                if c.is_ascii_alphanumeric() {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string()
    };
    let name = format!("{}__{}", clean(interface), clean(function));
    if name.len() <= MAX_NAME {
        return name;
    }
    let hash = blake3::hash(format!("{interface} {function}").as_bytes()).to_hex();
    let tail: String = name.chars().skip(name.len() - (MAX_NAME - 9)).collect();
    format!("{}_{}", &hash.as_str()[..8], tail)
}

/// Whether a connection may be offered this export.
fn offered(app: &LoadedApp, export: &Export, may_write: bool) -> bool {
    let secrets = !app.manifest.secrets.is_empty();
    match export.effect {
        ExportEffect::Read => may_write || !secrets,
        ExportEffect::Write => may_write,
        ExportEffect::External | ExportEffect::Interactive => false,
    }
}

struct Found {
    drive: String,
    export: Export,
}

/// The exports of every drive shared with the connection, by tool name. The
/// first drive that provides a name is the default for it.
async fn gather(appstate: &AppState, grant: &Grant) -> Vec<(String, Found)> {
    let for_agent = ForAgent::AgentSubject(atomic_lib::Subject::from_raw(&grant.agent, None));
    let Ok(drives) = super::tools::shared_drives(appstate, &for_agent, &grant.agent).await else {
        return Vec::new();
    };
    let db = Arc::new(appstate.store.clone());
    let mut found = Vec::new();
    for drive in drives {
        let Some(drive) = drive["subject"].as_str() else {
            continue;
        };
        // What is shared may be a folder or a resource; apps are installed in
        // drives, which have no parent.
        let is_drive = appstate
            .store
            .get_resource(&drive.into())
            .await
            .is_ok_and(|r| r.get(atomic_lib::urls::PARENT).is_err());
        if !is_drive {
            continue;
        }
        appstate.host_abi.refresh(&db, drive).await;
        for app in appstate.host_abi.apps_in(drive) {
            for export in &app.manifest.exports {
                if offered(&app, export, grant.write) {
                    found.push((
                        tool_name(&export.interface, &export.function),
                        Found {
                            drive: drive.to_string(),
                            export: export.clone(),
                        },
                    ));
                }
            }
        }
    }
    found
}

/// The MCP tool definitions for the connection's exports.
pub async fn list(appstate: &AppState, grant: &Grant) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut tools = Vec::new();
    for (name, found) in gather(appstate, grant).await {
        if !seen.insert(name.clone()) {
            continue;
        }
        let export = &found.export;
        let mut schema = serde_json::to_value(&export.input_schema).unwrap_or(json!({}));
        // The drive is not part of the export; it says where to call it.
        if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            properties.insert(
                "drive".into(),
                json!({
                    "type": "string",
                    "description": format!("The drive whose app to call. Defaults to {}.", found.drive),
                }),
            );
        }
        let read = export.effect == ExportEffect::Read;
        tools.push(json!({
            "name": name,
            "title": format!("{} {}", export.interface, export.function),
            "description": export.description,
            "inputSchema": schema,
            "annotations": {"readOnlyHint": read, "destructiveHint": false},
        }));
    }
    tools
}

/// Calls an export tool, or `None` when `name` is not one the connection has.
pub async fn call(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    grant: &Grant,
    name: &str,
    args: &Value,
) -> Option<Result<Value, String>> {
    let candidates: Vec<Found> = gather(appstate, grant)
        .await
        .into_iter()
        .filter(|(n, _)| n == name)
        .map(|(_, f)| f)
        .collect();
    let asked = args.get("drive").and_then(Value::as_str);
    let found = match asked {
        Some(drive) => candidates.into_iter().find(|f| f.drive == drive),
        None => candidates.into_iter().next(),
    }?;

    Some(run(appstate, req, grant, found, args).await)
}

async fn run(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    grant: &Grant,
    found: Found,
    args: &Value,
) -> Result<Value, String> {
    let agent = ForAgent::AgentSubject(atomic_lib::Subject::from_raw(&grant.agent, None));
    if found.export.effect != ExportEffect::Read {
        crate::helpers::enforce_write_rate_limit(appstate, req, &agent)
            .map_err(|e| e.to_string())?;
    }
    let mut args = args.clone();
    if let Some(object) = args.as_object_mut() {
        object.remove("drive");
    }
    let db = Arc::new(appstate.store.clone());
    // Only the effect the connection was offered: a chain it causes may not
    // write when the export reads.
    let budget = match found.export.effect {
        ExportEffect::Read => CallBudget::default().only(vec![ExportEffect::Read]),
        _ => CallBudget::default(),
    };
    let result = host_abi::call_for_agent(
        &appstate.host_abi,
        &db,
        &found.drive,
        &found.export.interface,
        &found.export.function,
        &args.to_string(),
        agent,
        Arc::new(budget),
    )
    .await
    .map_err(|e| format!("{}: {}", e.code, e.message))?;

    serde_json::from_str(&result).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_interface_and_function() {
        assert_eq!(
            tool_name("atomic:example/counter@1", "increment"),
            "atomic_example_counter_1__increment"
        );
        assert_eq!(tool_name("a:b/c@2", "bump-twice"), "a_b_c_2__bump_twice");
        let long = tool_name(&format!("atomic:example/{}@1", "x".repeat(80)), "go");
        assert!(long.len() <= MAX_NAME, "{long}");
        assert!(long.ends_with("__go"));
    }

    use crate::plugins::{
        host_abi::tests::{
            count_of, counter_resource, install, share, COUNTER_MANIFEST, COUNTER_WASM,
        },
        test_fixture::fixture,
    };

    /// An issued agent that was given the drive, as the app does on approval.
    async fn grant_for(f: &crate::plugins::test_fixture::Fixture, write: bool) -> Grant {
        let agent = atomic_lib::agents::Agent::new(None).unwrap().subject;
        share(
            &f.appstate.store,
            &f.drive,
            &[&agent.to_string()],
            &[&agent.to_string()],
        )
        .await;
        Grant {
            agent: agent.to_string(),
            client_id: "test".into(),
            person: "test".into(),
            nonce: "test".into(),
            write,
        }
    }

    #[actix_rt::test]
    async fn an_installed_apps_export_is_listed_and_callable_as_a_tool() {
        let f = fixture("mcp_export_tools").await;
        let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
        let (subject, property) = counter_resource(&f).await;
        let grant = grant_for(&f, true).await;
        share(
            &f.appstate.store,
            &subject,
            &[&counter.agent, &grant.agent],
            &[&counter.agent, &grant.agent],
        )
        .await;

        let tools = list(&f.appstate, &grant).await;
        let tool = tools
            .iter()
            .find(|t| t["name"] == "atomic_example_counter_1__increment")
            .unwrap_or_else(|| panic!("not listed: {tools:?}"));
        assert!(tool["description"].as_str().unwrap().contains("Adds one"));
        assert_eq!(
            tool["inputSchema"]["required"],
            json!(["subject", "property"])
        );
        assert_eq!(tool["annotations"]["readOnlyHint"], json!(false));

        let req = actix_web::test::TestRequest::default().to_http_request();
        let args = json!({"subject": subject, "property": property});
        let result = call(
            &f.appstate,
            &req,
            &grant,
            tool["name"].as_str().unwrap(),
            &args,
        )
        .await
        .expect("the tool exists")
        .unwrap();
        assert_eq!(result, json!({"count": 1}));
        assert_eq!(count_of(&f.appstate.store, &subject, &property).await, 1);

        // Another tool name is not ours to answer.
        assert!(call(&f.appstate, &req, &grant, "nope", &args)
            .await
            .is_none());
    }

    #[actix_rt::test]
    async fn a_read_only_connection_is_not_offered_exports_that_write() {
        let f = fixture("mcp_export_tools_readonly").await;
        install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
        let grant = grant_for(&f, false).await;

        assert!(list(&f.appstate, &grant).await.is_empty());
        let req = actix_web::test::TestRequest::default().to_http_request();
        assert!(call(
            &f.appstate,
            &req,
            &grant,
            "atomic_example_counter_1__increment",
            &json!({"subject": "x", "property": "y"})
        )
        .await
        .is_none());
    }
}
