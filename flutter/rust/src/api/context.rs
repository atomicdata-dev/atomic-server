//! Plain text of a resource, to give an AI as context: what the person sees
//! when they open it, without ids and internals.

#[cfg(test)]
mod tests;

use super::assistant::{class_name_of, name_of};
use super::simple::state::{db, err};
use atomic_lib::{storelike::Query, urls, Resource, Storelike, Subject, Value};

/// Most children listed for a folder or drive.
const MAX_CHILDREN: usize = 50;

/// Properties that are bookkeeping, not content.
const SKIPPED: [&str; 7] = [
    urls::IS_A,
    urls::NAME,
    urls::DESCRIPTION,
    urls::PARENT,
    urls::CREATED_AT,
    urls::LAST_COMMIT,
    urls::SHORTNAME,
];

fn truncate(text: String, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text;
    }
    text.chars().take(max_chars).collect()
}

/// The readable form of a value, or None for ids, binary and nested data.
fn readable(value: &Value) -> Option<String> {
    match value {
        Value::String(s) | Value::Markdown(s) | Value::Slug(s) | Value::Date(s) => {
            // A long run without a space is an encoded blob, not prose.
            let blob = s.len() > 100 && !s.contains(char::is_whitespace);
            Some(s.clone()).filter(|s| !s.trim().is_empty() && !blob)
        }
        Value::Integer(n) => Some(n.to_string()),
        Value::Float(n) => Some(n.to_string()),
        Value::Boolean(b) => Some(b.to_string()),
        Value::LocalizedText(map) => map.values().next().cloned(),
        _ => None,
    }
}

async fn property_label(property: &str) -> String {
    if let Ok(store) = db() {
        if let Ok(p) = store.get_resource(&Subject::from(property)).await {
            let name = name_of(&p);
            if !name.is_empty() {
                return name;
            }
        }
    }
    property
        .rsplit(['/', '#'])
        .next()
        .unwrap_or(property)
        .to_string()
}

async fn children_titles(subject: &str) -> Result<Vec<String>, String> {
    let store = db()?;
    let found = store
        .query(&Query::new_prop_val(urls::PARENT, subject))
        .await
        .map_err(err)?;
    let mut titles = Vec::new();
    for child in found.subjects.iter().take(MAX_CHILDREN) {
        if let Ok(r) = store.get_resource(child).await {
            let title = name_of(&r);
            titles.push(if title.is_empty() {
                "Untitled".to_string()
            } else {
                title
            });
        }
    }
    Ok(titles)
}

fn document_text(resource: &Resource) -> String {
    resource
        .build_state_doc()
        .map(|doc| doc.extract_document_plain_text())
        .unwrap_or_default()
}

/// Readable text for the resource `subject` from the local store: title, class,
/// description, simple properties, the titles of the children of a folder or
/// drive, and the text of a document. At most `max_chars` characters.
pub async fn read_resource_text(subject: String, max_chars: u32) -> Result<String, String> {
    let store = db()?;
    let resource = store
        .get_resource(&Subject::from(subject.as_str()))
        .await
        .map_err(err)?;
    let mut out = String::new();
    let title = name_of(&resource);
    out.push_str(if title.is_empty() { "Untitled" } else { &title });
    out.push('\n');
    let class = class_name_of(&resource).await;
    if !class.is_empty() {
        out.push_str(&format!("Class: {class}\n"));
    }
    if let Some(d) = resource.get(urls::DESCRIPTION).ok().and_then(readable) {
        out.push_str(&format!("Description: {d}\n"));
    }
    let mut lines = Vec::new();
    for (property, value) in resource.get_propvals() {
        let lower = property.to_lowercase();
        let internal = ["loro", "genesis", "signature", "signer", "commit"]
            .iter()
            .any(|k| lower.contains(k));
        if SKIPPED.contains(&property.as_str()) || internal {
            continue;
        }
        if let Some(text) = readable(value) {
            lines.push(format!("{}: {text}", property_label(property).await));
        }
    }
    lines.sort();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }

    let is_container = resource.has_class(urls::FOLDER) || resource.has_class(urls::DRIVE);
    if is_container {
        let titles = children_titles(&subject).await?;
        if !titles.is_empty() {
            out.push_str("Contains:\n");
            for t in titles {
                out.push_str(&format!("- {t}\n"));
            }
        }
    }
    if resource.has_class(urls::DOCUMENT_V2) {
        let text = document_text(&resource);
        if !text.is_empty() {
            out.push_str(&format!("\n{text}\n"));
        }
    }
    Ok(truncate(out, max_chars as usize))
}
