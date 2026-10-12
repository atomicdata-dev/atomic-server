//! Property names and values as a model writes them: shortnames from a
//! class's schema instead of full property URLs, tag names instead of tag
//! subjects, ISO dates instead of milliseconds. The write tools run what comes
//! in through here before building a commit.

use std::collections::HashMap;

use atomic_lib::{datatype::DataType, urls, Storelike};
use serde_json::{json, Value};

use crate::appstate::AppState;

#[derive(Clone, Debug)]
pub struct PropInfo {
    pub subject: String,
    pub shortname: String,
    /// The display name, when it differs from the shortname.
    pub name: Option<String>,
    pub datatype: DataType,
    /// For select properties: tag name to tag subject.
    pub tags: Option<Vec<(String, String)>>,
}

/// What a set of classes lets a key resolve to.
#[derive(Default)]
pub struct ClassContext {
    pub class_names: Vec<(String, String)>,
    pub properties: Vec<PropInfo>,
}

/// Properties every resource may have, whatever its class.
const UNIVERSAL: [&str; 2] = [urls::NAME, urls::DESCRIPTION];

async fn load_property(appstate: &AppState, subject: &str) -> Option<PropInfo> {
    let store = &appstate.store;
    let property = store.get_property(subject).await.ok()?;
    let mut info = PropInfo {
        subject: subject.to_string(),
        shortname: property.shortname.clone(),
        name: None,
        datatype: property.data_type.clone(),
        tags: None,
    };

    if let Ok(resource) = store.get_resource(&subject.into()).await {
        info.name = resource
            .get(urls::NAME)
            .ok()
            .map(|v| v.to_string())
            .filter(|n| n != &info.shortname);
    }

    if property.class_type.as_deref() == Some(urls::TAG) {
        let mut tags = Vec::new();
        for tag in property.allows_only.iter().flatten() {
            if let Ok(resource) = store.get_resource(&tag.as_str().into()).await {
                let name = resource
                    .get(urls::SHORTNAME)
                    .or_else(|_| resource.get(urls::NAME))
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| tag.clone());
                tags.push((name, tag.clone()));
            }
        }
        if !tags.is_empty() {
            info.tags = Some(tags);
        }
    }

    Some(info)
}

/// The resolution context for `classes` (class subjects).
pub async fn build_context(appstate: &AppState, classes: &[String]) -> ClassContext {
    let mut ctx = ClassContext::default();

    for class_subject in classes {
        let Ok(class) = appstate.store.get_class(class_subject).await else {
            continue;
        };
        ctx.class_names
            .push((class_subject.clone(), class.shortname.clone()));

        for subject in class.requires.iter().chain(class.recommends.iter()) {
            if ctx.properties.iter().any(|p| &p.subject == subject) {
                continue;
            }
            if let Some(info) = load_property(appstate, subject).await {
                ctx.properties.push(info);
            }
        }
    }

    for subject in UNIVERSAL {
        if ctx.properties.iter().any(|p| p.subject == subject) {
            continue;
        }
        if let Some(info) = load_property(appstate, subject).await {
            // A class's own `name` (a schema from ensure_ontology has one per
            // class) wins over the universal one; the universal is still
            // reachable by its full URL.
            let shadowed = ctx
                .properties
                .iter()
                .any(|p| p.shortname.to_lowercase() == info.shortname.to_lowercase());
            if !shadowed {
                ctx.properties.push(info);
            }
        }
    }

    ctx
}

impl ClassContext {
    /// The property a key means: a full URL (looked up if the class has it,
    /// else loaded on its own) or a shortname or display name. Unknown and
    /// ambiguous keys fail with what is available, so the model can repair.
    pub async fn resolve(&self, appstate: &AppState, key: &str) -> Result<PropInfo, String> {
        if is_subject(key) {
            if let Some(known) = self.properties.iter().find(|p| p.subject == key) {
                return Ok(known.clone());
            }

            return load_property(appstate, key)
                .await
                .ok_or_else(|| format!("Unknown property {key}"));
        }

        let wanted = key.to_lowercase();
        let matches: Vec<&PropInfo> = self
            .properties
            .iter()
            .filter(|p| {
                p.shortname.to_lowercase() == wanted
                    || p.name.as_ref().is_some_and(|n| n.to_lowercase() == wanted)
            })
            .collect();

        match matches.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(format!(
                "Unknown property \"{key}\". Available properties: {}. Use a listed shortname or a full property URL.",
                self.properties
                    .iter()
                    .map(|p| p.shortname.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            many => Err(format!(
                "Ambiguous property \"{key}\": matches {}. Use the full property URL to disambiguate.",
                many.iter()
                    .map(|p| format!("{} ({})", p.shortname, p.subject))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

/// A value as the model gave it, in the form the property stores.
pub fn coerce_value(info: &PropInfo, raw: &Value) -> Result<Value, String> {
    if let Some(tags) = &info.tags {
        let entries: Vec<&Value> = match raw {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        let mut out = Vec::new();
        for entry in entries {
            let name = entry
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| entry.to_string());
            if is_subject(&name) {
                out.push(json!(name));
                continue;
            }
            let found = tags
                .iter()
                .find(|(tag, _)| tag == &name || tag.to_lowercase() == name.to_lowercase());
            match found {
                Some((_, subject)) => out.push(json!(subject)),
                None => {
                    return Err(format!(
                        "Unknown tag \"{name}\" for {}. Allowed tags: {}",
                        info.shortname,
                        tags.iter()
                            .map(|(t, _)| t.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
            }
        }

        return Ok(Value::Array(out));
    }

    match (&info.datatype, raw) {
        (DataType::Timestamp, Value::String(s)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(s)
                .map(|d| d.timestamp_millis())
                .or_else(|_| {
                    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map(|d| {
                        d.and_hms_opt(0, 0, 0)
                            .map(|t| t.and_utc().timestamp_millis())
                            .unwrap_or_default()
                    })
                })
                .or_else(|_| s.parse::<i64>())
                .map_err(|_| {
                    format!(
                        "Invalid timestamp \"{s}\" for {}. Use an ISO date-time string or milliseconds since epoch.",
                        info.shortname
                    )
                })?;

            Ok(json!(parsed))
        }
        (DataType::Integer, Value::String(s)) if s.trim().parse::<i64>().is_ok() => {
            Ok(json!(s.trim().parse::<i64>().unwrap_or_default()))
        }
        (DataType::Float, Value::String(s)) if s.trim().parse::<f64>().is_ok() => {
            Ok(json!(s.trim().parse::<f64>().unwrap_or_default()))
        }
        (DataType::ResourceArray, value) if !value.is_array() => Ok(json!([value])),
        (_, value) => Ok(value.clone()),
    }
}

/// A class as the tools describe it to a model.
pub async fn describe_class(appstate: &AppState, class_subject: &str) -> Result<Value, String> {
    let class = appstate
        .store
        .get_class(class_subject)
        .await
        .map_err(|e| format!("Could not read class {class_subject}: {e}"))?;

    async fn describe(appstate: &AppState, subjects: &[String]) -> Vec<Value> {
        let mut out = Vec::new();
        for subject in subjects {
            match appstate.store.get_property(subject).await {
                Ok(p) => out.push(json!({
                    "subject": subject,
                    "shortname": p.shortname,
                    "datatype": p.data_type.to_string(),
                })),
                Err(_) => out.push(json!(format!("Could not read property: {subject}"))),
            }
        }

        out
    }

    Ok(json!({
        "subject": class_subject,
        "shortname": class.shortname,
        "description": class.description,
        "required": describe(appstate, &class.requires).await,
        "recommended": describe(appstate, &class.recommends).await,
    }))
}

/// Class names models use for the built-in classes.
/// Whether a name is already a subject: a URL, or an Atomic identifier in
/// either scheme (`did:ad:…`, `atomic:…`, as `ensure_ontology` returns them).
pub fn is_subject(name: &str) -> bool {
    atomic_lib::mapping::is_url(name) || atomic_lib::identifiers::is_atomic_identifier(name)
}

pub fn standard_class_alias(name: &str) -> Option<&'static str> {
    let aliases: HashMap<&str, &str> = HashMap::from([
        ("file", urls::FILE),
        ("folder", urls::FOLDER),
        ("document", urls::DOCUMENT_V2),
        ("document-v2", urls::DOCUMENT_V2),
        ("class", urls::CLASS),
        ("property", urls::PROPERTY),
        ("table", urls::TABLE),
    ]);

    aliases.get(name.trim().to_lowercase().as_str()).copied()
}

pub const MEETING: &str = "https://atomicdata.dev/classes/Meeting";

/// Whether any of these classes has a rich-text body.
pub fn has_document_body(classes: &[String]) -> bool {
    classes
        .iter()
        .any(|c| c == urls::DOCUMENT_V2 || c == MEETING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(datatype: DataType, tags: Option<Vec<(String, String)>>) -> PropInfo {
        PropInfo {
            subject: "https://example.com/p".into(),
            shortname: "p".into(),
            name: None,
            datatype,
            tags,
        }
    }

    #[test]
    fn tag_names_become_subjects() {
        let tags = vec![
            ("todo".to_string(), "https://example.com/todo".to_string()),
            ("done".to_string(), "https://example.com/done".to_string()),
        ];
        let p = info(DataType::ResourceArray, Some(tags));

        assert_eq!(
            coerce_value(&p, &json!("Done")).unwrap(),
            json!(["https://example.com/done"])
        );
        assert_eq!(
            coerce_value(&p, &json!("https://example.com/todo")).unwrap(),
            json!(["https://example.com/todo"])
        );
        let err = coerce_value(&p, &json!("later")).unwrap_err();
        assert!(err.contains("Allowed tags: todo, done"), "{err}");
    }

    #[test]
    fn timestamps_and_numbers_are_parsed_from_strings() {
        let ts = info(DataType::Timestamp, None);

        assert_eq!(
            coerce_value(&ts, &json!("2026-10-05T10:00:00Z")).unwrap(),
            json!(1_791_194_400_000_i64)
        );
        assert_eq!(
            coerce_value(&ts, &json!("2026-10-05")).unwrap(),
            json!(1_791_158_400_000_i64)
        );
        assert!(coerce_value(&ts, &json!("yesterday")).is_err());
        assert_eq!(
            coerce_value(&info(DataType::Integer, None), &json!(" 42 ")).unwrap(),
            json!(42)
        );
        assert_eq!(
            coerce_value(&info(DataType::ResourceArray, None), &json!("https://a")).unwrap(),
            json!(["https://a"])
        );
    }

    #[test]
    fn standard_classes_have_aliases() {
        assert_eq!(standard_class_alias(" Folder "), Some(urls::FOLDER));
        assert_eq!(standard_class_alias("document"), Some(urls::DOCUMENT_V2));
        assert_eq!(standard_class_alias("task"), None);
        assert!(has_document_body(&[MEETING.to_string()]));
        assert!(!has_document_body(&[urls::FOLDER.to_string()]));
    }
}
