//! The write tools. The node builds the commit and signs it as the *issued
//! agent* behind the token (derived again from the token's claims, never
//! stored), then sends it through the same pipeline as any client's commit:
//! signature, rights, subject ownership, broadcast. So a write can only do what
//! the person's ACLs give that agent, and history shows the app by name, not
//! the person and not the node.

use atomic_lib::{
    agents::{Agent, ForAgent},
    client::search::SearchOpts,
    parse::ParseOpts,
    urls, Resource, Storelike, Subject,
};
use serde_json::{json, Value};

use super::{
    compact::{self, build_context, coerce_value, has_document_body, is_subject},
    tokens::Grant,
};
use crate::appstate::AppState;

/// Keys that carry a document's text instead of an ordinary property.
const BODY_KEYS: [&str; 3] = ["_documentText", "document-content", "documentContent"];

const MAX_CREATE: usize = 200;

pub struct Writer<'a> {
    pub appstate: &'a AppState,
    pub origin: &'a str,
    pub agent: Agent,
    pub for_agent: ForAgent,
}

impl<'a> Writer<'a> {
    pub fn new(appstate: &'a AppState, origin: &'a str, grant: &'a Grant) -> Result<Self, String> {
        if !grant.write {
            return Err(
                "This connection is read-only. Reconnect and allow editing to change data.".into(),
            );
        }

        Ok(Self {
            appstate,
            origin,
            agent: grant.agent_key(appstate)?,
            for_agent: ForAgent::AgentSubject(Subject::from_raw(&grant.agent, None)),
        })
    }

    /// Reads as the agent: the rights check is the store's.
    pub(super) async fn read(&self, subject: &str) -> Result<Resource, String> {
        self.appstate
            .store
            .get_resource_extended(&subject.into(), true, &self.for_agent)
            .await
            .map(|r| r.to_single())
            .map_err(|e| e.to_string())
    }

    async fn submit(&self, commit: atomic_lib::Commit) -> Result<(), String> {
        submit_commit(self.appstate, self.origin, commit).await
    }

    /// The drive a resource lives in: the top of its parent chain.
    async fn drive_of(&self, subject: &str) -> Option<String> {
        let mut current = subject.to_string();
        for _ in 0..32 {
            let resource = self.read(&current).await.ok()?;
            match resource.get(urls::PARENT) {
                Ok(parent) => current = parent.to_string(),
                Err(_) => return Some(current),
            }
        }

        None
    }

    /// A class by shortname or title: a built-in alias, or one defined on the drive.
    async fn resolve_class(&self, drive: &str, name: &str) -> Result<String, String> {
        if is_subject(name) {
            return Ok(name.to_string());
        }
        if let Some(standard) = compact::standard_class_alias(name) {
            return Ok(standard.to_string());
        }

        let wanted = name.to_lowercase();
        let mut matches = Vec::new();
        for subject in classes_on_drive(self.appstate, drive)? {
            let Ok(resource) = self.read(&subject).await else {
                continue;
            };
            let named = |property: &str| {
                resource
                    .get(property)
                    .ok()
                    .is_some_and(|v| v.to_string().to_lowercase() == wanted)
            };
            if named(urls::SHORTNAME) || named(urls::NAME) {
                matches.push(subject);
            }
        }

        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => Err(format!(
                "Unknown class \"{name}\". Use find_schema to look for classes, or pass a full class URL."
            )),
            _ => Err(format!(
                "Ambiguous class \"{name}\": {}. Use the full class URL.",
                matches.join(", ")
            )),
        }
    }

    /// Sets one property, or a document's text, and saves.
    pub async fn edit(&self, args: &Value) -> Result<Value, String> {
        let subject = str_arg(args, "subject")?;
        let property = str_arg(args, "property")?;
        let value = args.get("value").ok_or("value is required")?;

        let mut resource = self.read(subject).await?;
        let classes = class_subjects(&resource);

        if BODY_KEYS.contains(&property) {
            let text = value
                .as_str()
                .ok_or_else(|| format!("{property} takes Markdown or plain text as a string."))?;
            set_body(&mut resource, &classes, text)?;
        } else {
            let ctx = build_context(self.appstate, &classes).await;
            let info = ctx.resolve(self.appstate, property).await?;
            let coerced = coerce_value(&info, value)?;
            set_property(self.appstate, &mut resource, &info.subject, &coerced).await?;
        }

        let Some(commit) = resource
            .sign_pending(&self.agent, &self.appstate.store)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(json!({"subject": subject, "unchanged": true}));
        };
        self.submit(commit).await?;

        Ok(
            json!({"subject": subject, "property": if BODY_KEYS.contains(&property) { "_documentText" } else { property }}),
        )
    }

    /// Creates one or more resources from compact JSON-AD.
    pub async fn create(&self, args: &Value) -> Result<Value, String> {
        let items = args
            .get("resources")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty() && a.len() <= MAX_CREATE)
            .ok_or_else(|| format!("resources must hold between 1 and {MAX_CREATE} objects"))?;

        let mut created = Vec::new();
        let mut errors = Vec::new();
        for (index, item) in items.iter().enumerate() {
            match self.create_one(item).await {
                Ok(subject) => created.push(subject),
                Err(e) => errors.push(format!("Item {index}: {e}")),
            }
        }
        if created.is_empty() {
            return Err(errors.join("\n"));
        }

        Ok(if errors.is_empty() {
            json!({"created": created})
        } else {
            json!({"created": created, "errors": errors})
        })
    }

    async fn create_one(&self, item: &Value) -> Result<String, String> {
        let mut data = item
            .as_object()
            .ok_or("Each resource must be an object")?
            .clone();

        if data.contains_key("@id") {
            return Err("Do not include an @id, the subject is auto generated".into());
        }
        let class_ref = data
            .remove("@class")
            .or_else(|| data.remove(urls::IS_A))
            .ok_or("Missing @class (or a full isA property)")?;
        let class_ref = match &class_ref {
            Value::Array(list) => list.first().and_then(Value::as_str),
            other => other.as_str(),
        }
        .ok_or("@class must be a string")?
        .to_string();
        let parent = data
            .remove("@parent")
            .or_else(|| data.remove(urls::PARENT))
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or("Missing @parent (or a full parent property)")?;

        let mut body = None;
        for key in BODY_KEYS {
            if let Some(value) = data.remove(key) {
                body = Some(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{key} takes Markdown or plain text as a string."))?
                        .to_string(),
                );
            }
        }

        let parent_resource = self.read(&parent).await?;
        let drive = self
            .drive_of(&parent)
            .await
            .unwrap_or_else(|| parent.clone());
        let class = self.resolve_class(&drive, &class_ref).await?;

        let mut resource = Resource::new_instance(&class, &self.appstate.store)
            .await
            .map_err(|e| e.to_string())?;
        resource
            .set_unsafe(
                urls::PARENT.into(),
                atomic_lib::Value::AtomicUrl(parent.clone().into()),
            )
            .map_err(|e| e.to_string())?;

        let ctx = build_context(self.appstate, std::slice::from_ref(&class)).await;
        for (key, value) in &data {
            let info = ctx.resolve(self.appstate, key).await?;
            let coerced = coerce_value(&info, value)?;
            set_property(self.appstate, &mut resource, &info.subject, &coerced).await?;
        }

        // Rows carry their creation time, like the app writes them.
        if class_subjects(&parent_resource)
            .iter()
            .any(|c| c == urls::TABLE)
            && resource.get(urls::CREATED_AT).is_err()
        {
            resource
                .set_unsafe(
                    urls::CREATED_AT.into(),
                    atomic_lib::Value::Timestamp(atomic_lib::utils::now()),
                )
                .map_err(|e| e.to_string())?;
        }

        if let Some(text) = body {
            if !has_document_body(std::slice::from_ref(&class)) {
                return Err("_documentText only applies to documents and meetings.".into());
            }
            set_body(&mut resource, std::slice::from_ref(&class), &text)?;
        }

        let commit = resource
            .sign_genesis_pending(&self.agent, &self.appstate.store)
            .await
            .map_err(|e| e.to_string())?;
        let subject = commit.subject.to_string();
        self.submit(commit).await?;

        Ok(subject)
    }

    pub async fn delete(&self, args: &Value) -> Result<Value, String> {
        let subject = str_arg(args, "subject")?;
        let mut resource = self.read(subject).await?;

        if class_subjects(&resource).iter().any(|c| c == urls::DRIVE) {
            return Err("Deleting a whole drive is not allowed from MCP.".into());
        }
        let title = resource
            .get(urls::NAME)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| subject.to_string());
        let commit = resource
            .sign_destroy_pending(&self.agent, &self.appstate.store)
            .await
            .map_err(|e| e.to_string())?;
        self.submit(commit).await?;

        Ok(json!(format!("Deleted {title} ({subject}).")))
    }
}

/// Sends a signed commit through the same pipeline as any client's: signature,
/// rights, subject ownership, broadcast.
pub async fn submit_commit(
    appstate: &AppState,
    origin: &str,
    commit: atomic_lib::Commit,
) -> Result<(), String> {
    let json = commit
        .into_resource(&appstate.store)
        .await
        .and_then(|r| r.to_json_ad(Some(origin)))
        .map_err(|e| e.to_string())?;

    crate::handlers::commit::apply_commit_json(&appstate.store, origin, &json, None)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn str_arg<'v>(args: &'v Value, key: &str) -> Result<&'v str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn class_subjects(resource: &Resource) -> Vec<String> {
    resource
        .get(urls::IS_A)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default()
}

/// Every class defined somewhere inside `drive`.
pub fn classes_on_drive(appstate: &AppState, drive: &str) -> Result<Vec<String>, String> {
    let opts = SearchOpts {
        limit: Some(1000),
        parents: Some(vec![drive.to_string()]),
        filter_pairs: Some(vec![(urls::IS_A.to_string(), urls::CLASS.to_string())]),
        ..Default::default()
    };

    Ok(atomic_lib::search::query(&appstate.store, "", &opts)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|hit| hit.subject.to_string())
        .collect())
}

async fn set_property(
    appstate: &AppState,
    resource: &mut Resource,
    property: &str,
    value: &Value,
) -> Result<(), String> {
    let (key, parsed) = atomic_lib::parse::parse_propval(
        property,
        value,
        None,
        &appstate.store,
        &ParseOpts::default(),
    )
    .await
    .map_err(|e| format!("Could not use that value for {property}: {e}"))?;
    resource
        .set(key, parsed, &appstate.store)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn set_body(resource: &mut Resource, classes: &[String], text: &str) -> Result<(), String> {
    if !has_document_body(classes) {
        return Err(format!(
            "{} is not a document or meeting, so it has no text body.",
            resource.get_subject()
        ));
    }
    let doc = resource.live_doc().map_err(|e| e.to_string())?;
    atomic_lib::document_markdown::write_document_text(doc.doc(), text).map_err(|e| e.to_string())
}
