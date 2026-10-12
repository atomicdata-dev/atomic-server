//! The schema tools: `find_schema` reads the classes the connection may see as
//! JSON Schema, and `ensure_ontology` (write connections only) makes a JSON
//! Schema real as an ontology. The app's assistant has the same two tools
//! (`browser/data-browser/src/chunks/AI/schemaTools.ts`); the JSON Schema
//! import and export are `atomic_lib::schema::json_schema`, shared with the
//! TypeScript client.

use std::{collections::HashMap, sync::Arc};

use atomic_lib::{
    agents::ForAgent,
    schema::json_schema::{
        class_in_json_schema, ensure_ontology_with, ontology_from_json_schema,
        ontology_to_json_schema, CommitSink, EnsureTarget, ImportOptions,
    },
    urls, Storelike, Subject,
};
use serde_json::{json, Map, Value};

use super::{
    tools::shared_drives,
    write::{classes_on_drive, submit_commit, Writer},
};
use crate::appstate::AppState;

const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 50;

/// The lowercase words of a query: runs of letters and digits.
fn query_words(query: &str) -> Vec<String> {
    query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// How many of the words occur in the text.
fn score(words: &[String], haystack: &str) -> usize {
    let haystack = haystack.to_lowercase();
    words
        .iter()
        .filter(|w| haystack.contains(w.as_str()))
        .count()
}

struct Candidate {
    subject: String,
    shortname: String,
    score: usize,
    ontology: Option<(String, String)>,
}

fn text(resource: &atomic_lib::Resource, property: &str) -> String {
    resource
        .get(property)
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default()
}

/// Classes on the drives this connection may read (or on `only`), matched on
/// words in their shortname, name, description or ontology, each with its JSON
/// Schema. Words are OR-ed and the classes that match most come first; an empty
/// query lists everything, up to `limit`.
pub async fn find_schema(
    appstate: &AppState,
    for_agent: &ForAgent,
    agent: &str,
    args: &Value,
    only_drive: Option<&str>,
) -> Result<Value, String> {
    let query = args.get("query").and_then(Value::as_str).unwrap_or("");
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_LIMIT, |l| l as usize)
        .clamp(1, MAX_LIMIT);
    let words = query_words(query);

    let drives: Vec<String> = match only_drive {
        Some(drive) => vec![drive.to_string()],
        None => shared_drives(appstate, for_agent, agent)
            .await?
            .iter()
            .filter_map(|d| d["subject"].as_str().map(str::to_string))
            .collect(),
    };

    let read = |subject: String| async move {
        appstate
            .store
            .get_resource_extended(&subject.as_str().into(), true, for_agent)
            .await
            .ok()
            .map(|r| r.to_single())
    };

    let mut seen: Vec<String> = Vec::new();
    let mut candidates = Vec::new();
    for drive in drives {
        for subject in classes_on_drive(appstate, &drive)? {
            if seen.contains(&subject) {
                continue;
            }
            seen.push(subject.clone());
            let Some(class) = read(subject.clone()).await else {
                continue;
            };

            let mut ontology = None;
            if let Ok(parent) = class.get(urls::PARENT).map(|v| v.to_string()) {
                if let Some(resource) = read(parent.clone()).await {
                    let is_ontology = resource
                        .get(urls::IS_A)
                        .ok()
                        .and_then(|v| v.to_subjects(None).ok())
                        .is_some_and(|classes| classes.iter().any(|c| c == urls::ONTOLOGY));
                    if is_ontology {
                        ontology = Some((
                            parent,
                            text(&resource, urls::SHORTNAME),
                            text(&resource, urls::NAME),
                        ));
                    }
                }
            }

            let shortname = text(&class, urls::SHORTNAME);
            let haystack = [
                shortname.clone(),
                text(&class, urls::NAME),
                text(&class, urls::DESCRIPTION),
                ontology.as_ref().map(|o| o.1.clone()).unwrap_or_default(),
                ontology.as_ref().map(|o| o.2.clone()).unwrap_or_default(),
            ]
            .join(" ");

            candidates.push(Candidate {
                subject,
                shortname,
                score: score(&words, &haystack),
                ontology: ontology.map(|(subject, shortname, _)| (subject, shortname)),
            });
        }
    }

    let mut hits: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| words.is_empty() || c.score > 0)
        .collect();
    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.shortname.to_lowercase().cmp(&b.shortname.to_lowercase()))
            .then_with(|| a.subject.cmp(&b.subject))
    });
    let total = hits.len();

    let mut exports: HashMap<String, Result<Value, String>> = HashMap::new();
    let mut matches = Vec::new();
    for hit in hits.into_iter().take(limit) {
        let mut entry = Map::new();
        entry.insert("class".into(), json!(hit.subject));
        entry.insert("shortname".into(), json!(hit.shortname));

        let Some((ontology, ontology_shortname)) = hit.ontology else {
            entry.insert(
                "error".into(),
                json!("This class is not part of an ontology."),
            );
            matches.push(Value::Object(entry));
            continue;
        };
        entry.insert(
            "ontology".into(),
            json!({"subject": ontology, "shortname": ontology_shortname}),
        );

        let exported = match exports.get(&ontology) {
            Some(known) => known.clone(),
            None => {
                let fresh = ontology_to_json_schema(&appstate.store, &ontology)
                    .await
                    .map_err(|e| e.to_string());
                exports.insert(ontology.clone(), fresh.clone());
                fresh
            }
        };
        match exported {
            Ok(schema) => match class_in_json_schema(&schema, &hit.subject) {
                Some(def) => {
                    entry.insert("jsonSchema".into(), def.clone());
                }
                None => {
                    entry.insert(
                        "error".into(),
                        json!("The class is missing from its ontology."),
                    );
                }
            },
            Err(e) => {
                entry.insert("error".into(), json!(e));
            }
        }
        matches.push(Value::Object(entry));
    }

    Ok(json!({"matches": matches, "total": total}))
}

/// The deprecated `get_user_classes`: `find_schema` with an empty query, for
/// the drive asked for (else every drive shared), as the list it always was.
pub async fn get_user_classes(
    appstate: &AppState,
    for_agent: &ForAgent,
    agent: &str,
    args: &Value,
) -> Result<Value, String> {
    let drive = args.get("drive").and_then(Value::as_str);
    let mut found = find_schema(
        appstate,
        for_agent,
        agent,
        &json!({"query": "", "limit": MAX_LIMIT}),
        drive,
    )
    .await?;

    let mut matches = found["matches"].take();
    for entry in matches.as_array_mut().into_iter().flatten() {
        // The old shape was `{shortname, subject}`.
        let subject = entry["class"].clone();
        entry["subject"] = subject;
    }

    Ok(matches)
}

impl Writer<'_> {
    /// Makes a JSON Schema real as an ontology under `drive`: the same import
    /// and `ensure_ontology` as the app, with every commit signed as the issued
    /// agent and sent through the commit pipeline, so the agent's rights decide.
    pub async fn ensure_ontology(&self, args: &Value) -> Result<Value, String> {
        let drive = match args.get("drive").and_then(Value::as_str) {
            Some(drive) => drive.to_string(),
            None => self.default_editable_drive().await?,
        };
        // Readable at least; writing it is the commit pipeline's check.
        self.read(&drive).await?;

        let schema = match args.get("schema") {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s)
                .map_err(|_| "schema is not valid JSON.".to_string())?,
            Some(other) => other.clone(),
            None => return Err("schema is required".into()),
        };

        let mut shortname = args
            .get("shortname")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if shortname.is_none()
            && schema.get("x-atomic-ontology").is_none()
            && schema.get("title").is_none()
        {
            shortname = self.default_ontology_shortname(&drive).await;
        }

        let plan = ontology_from_json_schema(&schema, &ImportOptions { shortname })
            .map_err(|e| e.to_string())?;

        let appstate = self.appstate.clone();
        let origin = self.origin.to_string();
        let sink = CommitSink(Arc::new(move |commit| {
            let appstate = appstate.clone();
            let origin = origin.clone();
            Box::pin(async move {
                submit_commit(&appstate, &origin, commit)
                    .await
                    .map_err(Into::into)
            })
        }));
        let target = EnsureTarget {
            sink: Some(sink),
            ..Default::default()
        };

        let ensured = ensure_ontology_with(
            &self.appstate.store,
            &Subject::from(drive.as_str()),
            &plan,
            &self.agent,
            &target,
        )
        .await
        .map_err(|e| e.to_string())?;

        Ok(json!({
            "ontology": ensured.ontology,
            "shortname": plan.shortname,
            "classes": ensured.classes,
            "properties": ensured.properties,
        }))
    }

    /// The first shared drive the agent can edit.
    async fn default_editable_drive(&self) -> Result<String, String> {
        let agent = self.agent.subject.to_string();
        shared_drives(self.appstate, &self.for_agent, &agent)
            .await?
            .iter()
            .find(|d| d["canEdit"] == json!(true))
            .and_then(|d| d["subject"].as_str().map(str::to_string))
            .ok_or_else(|| {
                "No drive that can be edited has been shared with this connection.".into()
            })
    }

    /// The shortname of the drive's default ontology, when it has one.
    async fn default_ontology_shortname(&self, drive: &str) -> Option<String> {
        let drive = self.read(drive).await.ok()?;
        let ontology = drive.get(urls::DEFAULT_ONTOLOGY).ok()?.to_string();
        let ontology = self.read(&ontology).await.ok()?;

        Some(text(&ontology, urls::SHORTNAME)).filter(|s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_is_lowercase_words() {
        assert_eq!(
            query_words("Invoice, line-items 2"),
            ["invoice", "line", "items", "2"]
        );
        assert!(query_words("  ").is_empty());
        assert!(query_words("").is_empty());
    }

    #[test]
    fn classes_rank_by_how_many_words_they_match() {
        let words = query_words("customer invoice");
        assert_eq!(score(&words, "Invoice an invoice of a customer"), 2);
        assert_eq!(score(&words, "Customer"), 1);
        assert_eq!(score(&words, "Task"), 0);
        // No words matches nothing by score; the caller lists everything then.
        assert_eq!(score(&[], "Task"), 0);
    }

    use crate::{
        config::{self, Opts},
        mcp::{
            tokens::{issued_agent, Grant},
            tools,
        },
    };

    const ORIGIN: &str = "http://localhost";

    const SHOP: &str = r##"{
        "title": "Shop",
        "$defs": {
            "customer": {
                "type": "object",
                "description": "Someone who buys things",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "email": {"type": "string"}
                },
                "required": ["name"]
            },
            "order": {
                "type": "object",
                "properties": {
                    "customer": {"$ref": "#/$defs/customer"},
                    "status": {"type": "string", "enum": ["open", "paid"]},
                    "total": {"type": "number", "minimum": 0}
                },
                "required": ["customer"]
            }
        }
    }"##;

    async fn appstate() -> AppState {
        use clap::Parser;
        let unique = atomic_lib::utils::random_string(10);
        let opts = Opts::parse_from([
            "atomic-server",
            "--initialize",
            "--data-dir",
            &format!("./.temp/{unique}/db"),
            "--config-dir",
            &format!("./.temp/{unique}/config"),
        ]);
        let mut config = config::build_config(opts).expect("failed init config");
        config.search_index_path = format!("./.temp/{unique}/search_index").into();
        config.vector_search_index_path = format!("./.temp/{unique}/vector_search_index").into();

        AppState::init(config).await.expect("failed init appstate")
    }

    /// A drive the issued agent may read, and edit when `write`.
    async fn shared_drive(appstate: &AppState, agent: &str, write: bool) -> String {
        let drive = atomic_lib::test_utils::create_test_drive(&appstate.store)
            .await
            .unwrap();
        let mut resource = appstate.store.get_resource(&drive).await.unwrap();
        let owner = appstate.store.get_default_agent().unwrap().subject;
        for (property, add) in [(urls::READ, true), (urls::WRITE, write)] {
            let mut agents: Vec<String> = resource
                .get(property)
                .ok()
                .and_then(|v| v.to_subjects(None).ok())
                .unwrap_or_else(|| vec![owner.to_string()]);
            if add {
                agents.push(agent.to_string());
            }
            resource
                .set(property.into(), agents.into(), &appstate.store)
                .await
                .unwrap();
        }
        resource.save(&appstate.store).await.unwrap();

        drive.to_string()
    }

    fn grant(appstate: &AppState, write: bool) -> Grant {
        let agent = issued_agent(appstate, "did:ad:person", "client", "nonce", None).unwrap();

        Grant {
            agent: agent.subject.to_string(),
            client_id: "client".into(),
            person: "did:ad:person".into(),
            nonce: "nonce".into(),
            write,
        }
    }

    async fn call(
        appstate: &AppState,
        grant: &Grant,
        name: &str,
        args: Value,
    ) -> Result<Value, String> {
        let req = actix_web::test::TestRequest::default().to_http_request();

        tools::call(appstate, ORIGIN, &req, grant, name, &args).await
    }

    fn names(write: bool) -> Vec<String> {
        tools::list(write)
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn only_a_connection_that_may_edit_is_offered_ensure_ontology() {
        let read = names(false);
        for name in ["find_schema", "get_user_classes", "get_schema"] {
            assert!(read.contains(&name.to_string()), "{name}");
        }
        assert!(!read.contains(&"ensure_ontology".to_string()));
        assert!(names(true).contains(&"ensure_ontology".to_string()));

        // The advice is in the descriptions: search first, reuse, keywords, new property.
        let tools = tools::list(true);
        let description = |name: &str| {
            tools
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == name)
                .unwrap()["description"]
                .as_str()
                .unwrap()
                .to_lowercase()
        };
        assert!(description("find_schema").contains("search first"));
        let ensure = description("ensure_ontology");
        for needle in ["find_schema first", "reuse", "keywords", "new property"] {
            assert!(ensure.contains(needle), "{needle}");
        }
        assert!(description("get_user_classes").contains("deprecated"));
    }

    #[actix_rt::test]
    async fn a_connection_creates_finds_and_reuses_a_schema() {
        let appstate = appstate().await;
        let grant = grant(&appstate, true);
        let drive = shared_drive(&appstate, &grant.agent, true).await;
        let args = json!({"drive": drive, "schema": serde_json::from_str::<Value>(SHOP).unwrap()});

        let first = call(&appstate, &grant, "ensure_ontology", args.clone())
            .await
            .unwrap();
        assert_eq!(first["shortname"], "shop");
        assert!(first["classes"]["customer"].is_string());
        assert!(first["classes"]["order"].is_string());
        for property in ["name", "email", "customer", "status", "total"] {
            assert!(first["properties"][property].is_string(), "{property}");
        }

        // Idempotent: the same schema finds everything again.
        let second = call(&appstate, &grant, "ensure_ontology", args.clone())
            .await
            .unwrap();
        assert_eq!(first, second);

        // The edits were made by the issued agent, as a commit.
        let ontology = appstate
            .store
            .get_resource(&first["ontology"].as_str().unwrap().into())
            .await
            .unwrap();
        assert_eq!(ontology.get(urls::SHORTNAME).unwrap().to_string(), "shop");

        // Found by a word in the ontology or the class, best match first.
        let found = call(
            &appstate,
            &grant,
            "find_schema",
            json!({"query": "shop order"}),
        )
        .await
        .unwrap();
        let matches = found["matches"].as_array().unwrap();
        assert_eq!(found["total"], 2);
        assert_eq!(matches[0]["shortname"], "order");
        assert_eq!(matches[0]["class"], first["classes"]["order"]);
        assert_eq!(matches[0]["ontology"]["shortname"], "shop");
        assert_eq!(matches[0]["ontology"]["subject"], first["ontology"]);
        let order = &matches[0]["jsonSchema"];
        assert_eq!(order["required"], json!(["customer"]));
        assert_eq!(order["properties"]["total"]["minimum"], 0);
        assert_eq!(
            order["properties"]["status"]["enum"],
            json!(["open", "paid"])
        );
        assert!(order["properties"]["customer"]["$ref"]
            .as_str()
            .unwrap()
            .starts_with("#/$defs/"));
        assert!(order["properties"]["total"]["x-atomic-property"].is_string());

        // A limit, and an empty query that lists everything.
        let one = call(
            &appstate,
            &grant,
            "find_schema",
            json!({"query": "", "limit": 1}),
        )
        .await
        .unwrap();
        assert_eq!(one["matches"].as_array().unwrap().len(), 1);
        assert_eq!(one["total"], 2);
        let none = call(
            &appstate,
            &grant,
            "find_schema",
            json!({"query": "nothing-like-this"}),
        )
        .await
        .unwrap();
        assert_eq!(none["total"], 0);

        // The deprecated listing is find_schema with an empty query, in the old shape too.
        let legacy = call(
            &appstate,
            &grant,
            "get_user_classes",
            json!({"drive": drive}),
        )
        .await
        .unwrap();
        let legacy = legacy.as_array().unwrap();
        assert_eq!(legacy.len(), 2);
        assert!(legacy
            .iter()
            .all(|c| c["subject"] == c["class"] && c["jsonSchema"].is_object()));
        let everything = call(&appstate, &grant, "get_user_classes", json!({}))
            .await
            .unwrap();
        assert_eq!(everything.as_array().unwrap().len(), 2);

        // get_schema still describes the class, and create_resource takes its subject.
        let described = call(
            &appstate,
            &grant,
            "get_schema",
            json!({"subject": first["classes"]["customer"]}),
        )
        .await
        .unwrap();
        assert!(described.to_string().contains("name"));
        let created = call(
            &appstate,
            &grant,
            "create_resource",
            json!({"resources": [{"@class": first["classes"]["customer"], "@parent": drive, "name": "Anna"}]}),
        )
        .await
        .unwrap();
        assert_eq!(created["created"].as_array().unwrap().len(), 1);
    }

    #[actix_rt::test]
    async fn ensure_ontology_reports_import_errors_with_the_pointer() {
        let appstate = appstate().await;
        let grant = grant(&appstate, true);
        let drive = shared_drive(&appstate, &grant.agent, true).await;

        let error = call(
            &appstate,
            &grant,
            "ensure_ontology",
            json!({"drive": drive, "schema": {"title": "Bad", "$defs": {"thing": {
                "type": "object",
                "properties": {"x": {"oneOf": [{"type": "string"}, {"type": "integer"}]}}
            }}}}),
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("JSON Schema at /$defs/thing/properties/x"),
            "{error}"
        );

        let error = call(
            &appstate,
            &grant,
            "ensure_ontology",
            json!({"drive": drive, "schema": "{nope"}),
        )
        .await
        .unwrap_err();
        assert!(error.contains("not valid JSON"), "{error}");
    }

    #[actix_rt::test]
    async fn ensure_ontology_cannot_write_where_the_agent_cannot() {
        let appstate = appstate().await;
        let schema = serde_json::from_str::<Value>(SHOP).unwrap();

        // A connection the person did not allow to edit.
        let read_only = grant(&appstate, false);
        let drive = shared_drive(&appstate, &read_only.agent, false).await;
        let error = call(
            &appstate,
            &read_only,
            "ensure_ontology",
            json!({"drive": drive, "schema": schema}),
        )
        .await
        .unwrap_err();
        assert!(error.contains("read-only"), "{error}");

        // Allowed to edit, but the agent has no write right on this drive.
        let editor = grant(&appstate, true);
        let drive = shared_drive(&appstate, &editor.agent, false).await;
        let error = call(
            &appstate,
            &editor,
            "ensure_ontology",
            json!({"drive": drive, "schema": schema}),
        )
        .await
        .unwrap_err();
        assert!(!error.is_empty());
        let found = call(&appstate, &editor, "find_schema", json!({"query": "shop"}))
            .await
            .unwrap();
        assert_eq!(found["total"], 0, "nothing was written");
    }
}
