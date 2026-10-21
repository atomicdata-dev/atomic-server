//! Plain text of a resource, to give an AI as context: what the person sees
//! when they open it, without ids and internals.

use super::rows::{class_name_of, name_of};
use crate::{
    errors::AtomicResult, storelike::Query, urls, Db, Resource, Storelike, Subject, Value,
};

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

async fn property_label(store: &Db, property: &str) -> String {
    if let Ok(p) = store.get_resource(&Subject::from(property)).await {
        let name = name_of(&p);
        if !name.is_empty() {
            return name;
        }
    }
    property
        .rsplit(['/', '#'])
        .next()
        .unwrap_or(property)
        .to_string()
}

async fn children_titles(store: &Db, subject: &str) -> AtomicResult<Vec<String>> {
    let found = store
        .query(&Query::new_prop_val(urls::PARENT, subject))
        .await?;
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
pub async fn read_resource_text(
    store: &Db,
    subject: &str,
    max_chars: usize,
) -> AtomicResult<String> {
    let resource = store.get_resource(&Subject::from(subject)).await?;
    let mut out = String::new();
    let title = name_of(&resource);
    out.push_str(if title.is_empty() { "Untitled" } else { &title });
    out.push('\n');
    let class = class_name_of(store, &resource).await;
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
            lines.push(format!("{}: {text}", property_label(store, property).await));
        }
    }
    lines.sort();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }

    let is_container = resource.has_class(urls::FOLDER) || resource.has_class(urls::DRIVE);
    if is_container {
        let titles = children_titles(store, subject).await?;
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
    Ok(truncate(out, max_chars))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::test_support::Device;

    async fn folder(d: &Device, parent: &str, name: &str) -> String {
        d.store
            .create_resource(urls::FOLDER, parent, name, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn folder_text_lists_title_class_and_children() {
        let d = Device::new().await;
        let parent = folder(&d, &d.drive, "Ctx parent").await;
        folder(&d, &parent, "Ctx child one").await;
        folder(&d, &parent, "Ctx child two").await;

        let text = read_resource_text(&d.store, &parent, 4000).await.unwrap();
        assert!(text.starts_with("Ctx parent\n"), "{text}");
        assert!(text.to_lowercase().contains("class: folder"), "{text}");
        assert!(text.contains("- Ctx child one"), "{text}");
        assert!(text.contains("- Ctx child two"), "{text}");
    }

    #[tokio::test]
    async fn resource_text_has_its_description() {
        let d = Device::new().await;
        let subject = folder(&d, &d.drive, "Ctx described").await;
        let mut resource = d
            .store
            .get_resource(&Subject::from(subject.as_str()))
            .await
            .unwrap();
        resource
            .set_string(urls::DESCRIPTION.into(), "A quokka lives here", &d.store)
            .await
            .unwrap();
        resource.save(&d.store).await.unwrap();

        let text = read_resource_text(&d.store, &subject, 4000).await.unwrap();
        assert!(text.contains("Description: A quokka lives here"), "{text}");
    }

    #[tokio::test]
    async fn text_is_capped() {
        let d = Device::new().await;
        let subject = folder(&d, &d.drive, "Ctx a long enough title").await;
        let text = read_resource_text(&d.store, &subject, 10).await.unwrap();
        assert_eq!(text.chars().count(), 10);
    }
}
