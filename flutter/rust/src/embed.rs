//! What the embedded renderer asks the store: the calls of the web app's
//! `NativeClientDb` (`browser/lib/src/client-db.native.ts`), answered from
//! `atomic_lib`. One request is a method name and its arguments as JSON; the
//! answer is JSON, with bytes as base64. See `planning/flutter-resource-webview.md`.
//!
//! Reads only for now. Writes and signing follow (step 3); until then they are
//! refused, so a page cannot appear to save what was not saved.

use crate::api::simple::state::{db, err};
use atomic_lib::{agents::ForAgent, storelike::Query, Resource, Storelike, Subject};
use serde_json::{json, Value as Json};
use std::collections::HashMap;

fn b64(bytes: &[u8]) -> String {
    atomic_lib::agents::encode_base64(bytes)
}

/// The origin subjects are addressed by in the page: a DID needs none, but a
/// resource served by URL does.
fn origin(store: &atomic_lib::Db) -> String {
    store
        .get_base_domain()
        .unwrap_or_else(|| "http://localhost".to_string())
}

fn str_arg<'a>(args: &'a [Json], i: usize) -> Result<&'a str, String> {
    args.get(i)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("argument {i} must be a string"))
}

fn strings(args: &[Json], i: usize) -> Vec<String> {
    args.get(i)
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn subject_of(store: &atomic_lib::Db, raw: &str) -> Subject {
    Subject::from_raw(raw, store.get_base_domain().as_deref())
}

/// A resource as JSON-AD under the subject it was asked by, plus its Loro
/// snapshot. Reads the stored row first, like the browser's database does:
/// decoding the whole CRDT history only to serialise it again is the slow way.
async fn read_one(store: &atomic_lib::Db, raw: &str) -> Json {
    let subject = subject_of(store, raw);
    let origin = origin(store);
    let resource: Option<Resource> = match store.get_resource_shallow(&subject) {
        Ok(r) => Some(r),
        Err(_) => store.get_resource(&subject).await.ok(),
    };
    let json_ad = resource.and_then(|r| r.to_json_ad(Some(&origin)).ok());
    let snapshot = json_ad
        .as_ref()
        .and_then(|_| store.get_loro_snapshot(&subject))
        .map(|b| b64(&b));
    json!({ "jsonAd": json_ad, "snapshot": snapshot })
}

async fn query(store: &atomic_lib::Db, opts: &Json) -> Result<Json, String> {
    let text = |k: &str| opts.get(k).and_then(Json::as_str).map(str::to_string);
    let base = store.get_base_domain();
    let property = text("property");
    let value = match text("value") {
        Some(raw) => Some(
            atomic_lib::collections::delocalize_filter_value(store, property.as_deref(), &raw)
                .await,
        ),
        None => None,
    };

    let mut filters = Vec::new();
    for f in opts
        .get("filters")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let p = f.get("property").and_then(Json::as_str).map(str::to_string);
        let v = match f.get("value").and_then(Json::as_str) {
            Some(raw) => Some(
                atomic_lib::collections::delocalize_filter_value(store, p.as_deref(), raw).await,
            ),
            None => None,
        };
        filters.push(atomic_lib::storelike::PropVal {
            property: p,
            value: v,
            operator: atomic_lib::storelike::filter_operator_from_str(
                f.get("operator").and_then(Json::as_str),
            ),
        });
    }

    let aggregation = opts
        .get("aggregation")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| e.to_string()))
        .transpose()?;
    let expression_filters = opts
        .get("expressionFilters")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or_default();
    let flag = |k: &str| opts.get(k).and_then(Json::as_bool).unwrap_or(false);
    let number = |k: &str| opts.get(k).and_then(Json::as_u64).map(|n| n as usize);

    let q = Query {
        property,
        value,
        filters,
        expression_filters,
        aggregation,
        sort_by: text("sortBy"),
        sort_desc: flag("sortDesc"),
        limit: number("limit"),
        offset: number("offset").unwrap_or(0),
        start_val: None,
        end_val: None,
        include_external: false,
        include_nested: flag("includeResources"),
        exclude_trashed: !flag("includeTrashed"),
        for_agent: ForAgent::Sudo,
        drive: text("drive").map(|d| Subject::from_raw(&d, base.as_deref())),
    };
    let result = store.query(&q).await.map_err(err)?;
    let origin = origin(store);
    let resources: Vec<String> = result
        .resources
        .iter()
        .filter_map(|r| r.to_json_ad(Some(&origin)).ok())
        .collect();
    Ok(json!({
        "subjects": result.subjects.iter().map(|s| s.resolve(&origin)).collect::<Vec<_>>(),
        "resources": resources,
        "count": result.count,
        "aggregates": result.aggregates,
    }))
}

fn search(store: &atomic_lib::Db, args: &[Json]) -> Result<Json, String> {
    let q = str_arg(args, 0)?;
    let opts = args.get(1).cloned().unwrap_or(Json::Null);
    let parents = match opts.get("parents") {
        Some(Json::String(s)) => Some(vec![s.clone()]),
        Some(Json::Array(a)) => Some(
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
    };
    let search_opts = atomic_lib::client::search::SearchOpts {
        limit: opts.get("limit").and_then(Json::as_u64).map(|n| n as u32),
        parents,
        include_trashed: opts
            .get("includeTrashed")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        ..Default::default()
    };
    let hits = atomic_lib::search::query(store, q, &search_opts).map_err(err)?;
    Ok(json!(hits
        .into_iter()
        .map(|h| h.subject.to_string())
        .collect::<Vec<_>>()))
}

/// Version vectors of the given subjects (`pure_id` strings, the keys of the
/// snapshot tree); subjects without a snapshot are left out.
fn version_vectors(store: &atomic_lib::Db, subjects: Vec<String>) -> Json {
    use atomic_lib::db::trees::Tree;
    use atomic_lib::loro::AtomicLoroDoc;
    let mut out: HashMap<String, HashMap<String, i32>> = HashMap::new();
    for subject in subjects {
        if let Ok(Some(bytes)) = store.kv.get(Tree::LoroSnapshots, subject.as_bytes()) {
            if let Ok(vv) = AtomicLoroDoc::vv_map_from_snapshot(&bytes) {
                out.insert(subject, vv);
            }
        }
    }
    json!(out)
}

/// One call from the page.
pub(crate) async fn call(method: &str, args_json: &str) -> Result<String, String> {
    let args: Vec<Json> = serde_json::from_str(args_json).map_err(|e| e.to_string())?;
    let store = db()?.as_ref();
    let answer: Json = match method {
        "init" => json!(true),
        "agent" => match store.get_default_agent() {
            Ok(agent) => json!(agent.subject.to_string()),
            Err(_) => Json::Null,
        },
        "getResource" => read_one(store, str_arg(&args, 0)?).await["jsonAd"].clone(),
        "getResourcesWithSnapshots" => {
            let mut rows = Vec::new();
            for s in strings(&args, 0) {
                rows.push(read_one(store, &s).await);
            }
            json!(rows)
        }
        "getLoroSnapshot" => json!(store
            .get_loro_snapshot(&subject_of(store, str_arg(&args, 0)?))
            .map(|b| b64(&b))),
        "query" => query(store, args.first().unwrap_or(&Json::Null)).await?,
        "search" => search(store, &args)?,
        "allSubjects" => json!(store
            .all_resources(true)
            .map(|r| r.get_subject().to_string())
            .collect::<Vec<_>>()),
        "getDriveSubjects" => json!(atomic_lib::sync::engine::collect_drive_subjects(
            store,
            &subject_of(store, str_arg(&args, 0)?)
        )
        .await
        .into_iter()
        .collect::<Vec<_>>()),
        "getVersionVectorsForDrive" => {
            let subjects: Vec<String> = atomic_lib::sync::engine::collect_drive_subjects(
                store,
                &subject_of(store, str_arg(&args, 0)?),
            )
            .await
            .into_iter()
            .collect();
            version_vectors(store, subjects)
        }
        "getVersionVectorsForSubjects" => version_vectors(store, strings(&args, 0)),
        // Nothing in the page syncs with a server, so nothing diffs versions.
        "getAllVersionVectors" => json!({}),
        "historyAttribution" => Json::Null,
        "getBlob" => Json::Null,
        "flush" => Json::Null,
        "outboxEntries" => json!([]),
        "outboxWrite" => Json::Null,
        // The page's local cache writes back what it just read; the real store
        // already has it, so there is nothing to keep.
        "putResource" | "putResources" | "putResourceWithSnapshot" | "putBlob"
        | "applyPeerCommit" | "removeResource" => Json::Null,
        "publicKey" => match store.get_default_agent() {
            Ok(agent) => json!(agent.public_key),
            Err(_) => Json::Null,
        },
        other => {
            return Err(format!(
                "{other}: not available in the embedded renderer yet"
            ))
        }
    };
    serde_json::to_string(&answer).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::simple::tests::shared_drive;
    use atomic_lib::urls;

    async fn ask(method: &str, args: Json) -> Json {
        serde_json::from_str(&call(method, &args.to_string()).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn the_page_can_read_a_resource_under_either_spelling() {
        let drive = shared_drive().await;
        let folder = db()
            .unwrap()
            .create_resource(urls::FOLDER, drive, "Embed folder", None)
            .await
            .unwrap();
        let other_spelling = if folder.starts_with("atomic:") {
            folder.replacen("atomic:", "did:ad:", 1)
        } else {
            folder.replacen("did:ad:", "atomic:", 1)
        };

        let rows = ask(
            "getResourcesWithSnapshots",
            json!([[folder, other_spelling, "did:ad:not-here"]]),
        )
        .await;
        let rows = rows.as_array().unwrap();

        for row in &rows[..2] {
            assert!(row["jsonAd"].as_str().unwrap().contains("Embed folder"));
            assert!(!row["snapshot"].as_str().unwrap().is_empty());
        }
        // Answered under the name it was asked by.
        assert!(rows[1]["jsonAd"]
            .as_str()
            .unwrap()
            .contains(&other_spelling));
        assert!(rows[2]["jsonAd"].is_null());
    }

    #[tokio::test]
    async fn the_page_can_list_the_children_of_a_folder_and_search_them() {
        let drive = shared_drive().await;
        let store = db().unwrap();
        let folder = store
            .create_resource(urls::FOLDER, drive, "Embed parent", None)
            .await
            .unwrap();
        let child = store
            .create_resource(urls::FOLDER, &folder, "Quokkaembed child", None)
            .await
            .unwrap();

        let result = ask(
            "query",
            json!([{ "property": urls::PARENT, "value": folder, "limit": 10 }]),
        )
        .await;
        let subjects: Vec<&str> = result["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Json::as_str)
            .collect();
        assert_eq!(subjects.len(), 1);
        assert!(subjects[0].ends_with(child.trim_start_matches("atomic:")));
        assert_eq!(result["count"], 1);

        let nested = ask(
            "query",
            json!([{ "property": urls::PARENT, "value": folder, "includeResources": true }]),
        )
        .await;
        assert!(nested["resources"][0]
            .as_str()
            .unwrap()
            .contains("Quokkaembed child"));

        let hits = ask(
            "search",
            json!(["quokkaembed", { "limit": 5, "parents": drive }]),
        )
        .await;
        assert!(hits
            .to_string()
            .contains(child.trim_start_matches("atomic:")));
    }

    #[tokio::test]
    async fn it_names_the_agent_and_says_it_is_ready() {
        shared_drive().await;
        assert_eq!(ask("init", json!([])).await, json!(true));
        assert!(ask("agent", json!([]))
            .await
            .as_str()
            .unwrap()
            .contains("agent"));
    }

    #[tokio::test]
    async fn writes_are_refused_until_they_are_signed_here() {
        shared_drive().await;
        for method in ["applyCommit", "sign", "signBytes"] {
            let refused = call(method, "[\"x\"]").await.unwrap_err();
            assert!(refused.contains("not available"), "{method}: {refused}");
        }
    }
}
