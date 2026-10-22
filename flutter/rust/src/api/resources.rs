//! Generic, typed resource access: the bridge half of the Dart `Store` and
//! `Resource` (`packages/atomic_store`), which mirror `@tomic/lib`.
//!
//! Unlike the older flat functions these return typed values
//! ([`ResourceData`], [`AtomicValue`]) and fail with [`AtomicError`]. Writes
//! take the same path as every other local write: a signed commit, queued in
//! the outbox and pushed (`push_local_write`).
//!
//! The store and the signing agent are still the process-wide ones `open_db`
//! and `load_agent` set; see `flutter/README.md` for what removing those
//! globals takes.

use super::error::{open_store, AtomicError};
use super::error::ErrorKind;
use super::simple::local_write::push_local_write;
use super::simple::state::node;
use atomic_lib::{
    commit::CommitBuilder, host::lists, resources::PropVals, values::SubResource, Commit, Storelike, Value,
};

/// The datatype of an [`AtomicValue`]; says which of its fields is filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datatype {
    /// `text`.
    String,
    /// `text`.
    Markdown,
    /// `text`.
    Slug,
    /// `text`, an ISO date.
    Date,
    /// `text`.
    Uri,
    /// `text` is the linked resource's subject.
    Link,
    /// `text`, decimal (lossless on the web, where 64-bit ints are not exact).
    Integer,
    /// `text`, decimal.
    Float,
    /// `text`, Unix epoch milliseconds, decimal.
    Timestamp,
    /// `text` is `true` or `false`.
    Boolean,
    /// `items`: links and nested resources.
    Array,
    /// `props`: a resource without a subject of its own, inside another.
    Nested,
    /// `text` is JSON.
    Json,
    /// `props`: each property is a BCP 47 language tag, each value a string.
    Localized,
    /// `text` describes a value this bridge cannot interpret (a Loro
    /// document, an unknown datatype); `unsupported_datatype` names it.
    Unsupported,
}

/// A property value. `datatype` says which of the other fields carries it;
/// the rest are empty. (One flat struct instead of an enum with fields:
/// flutter_rust_bridge generates those with `freezed`, which this app does not
/// use. `packages/atomic_store` turns it into sealed Dart classes.)
#[derive(Debug, Clone, PartialEq)]
pub struct AtomicValue {
    pub datatype: Datatype,
    pub text: String,
    pub items: Vec<AtomicValue>,
    pub props: Vec<PropValue>,
    pub unsupported_datatype: Option<String>,
}

impl AtomicValue {
    fn scalar(datatype: Datatype, text: impl Into<String>) -> Self {
        AtomicValue {
            datatype,
            text: text.into(),
            items: Vec::new(),
            props: Vec::new(),
            unsupported_datatype: None,
        }
    }
}

/// One property of a resource.
#[derive(Debug, Clone, PartialEq)]
pub struct PropValue {
    /// The property's URL.
    pub property: String,
    pub value: AtomicValue,
}

/// A resource as the local store holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceData {
    pub subject: String,
    /// Sorted by property URL, so two reads of one state are equal.
    pub props: Vec<PropValue>,
}

/// One full-text search hit.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub subject: String,
    pub title: String,
    pub class_name: String,
    /// The drive the hit lives in, empty when unknown.
    pub drive: String,
    pub score: f64,
}

/// What `wait_for_resource_event` saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceEvent {
    Changed,
    Destroyed,
    /// Nothing happened within the timeout; call again.
    Timeout,
}

// ── Conversion ─────────────────────────────────────────────────────────────

fn sub_resource_to_value(sub: &SubResource) -> AtomicValue {
    match sub {
        SubResource::Subject(s) => AtomicValue::scalar(Datatype::Link, s.to_string()),
        SubResource::Nested(props) => AtomicValue {
            props: propvals_to_list(props),
            ..AtomicValue::scalar(Datatype::Nested, "")
        },
    }
}

pub(crate) fn value_to_atomic(value: &Value) -> AtomicValue {
    use Datatype::*;
    match value {
        Value::String(v) => AtomicValue::scalar(String, v),
        Value::Markdown(v) => AtomicValue::scalar(Markdown, v),
        Value::Slug(v) => AtomicValue::scalar(Slug, v),
        Value::Date(v) => AtomicValue::scalar(Date, v),
        Value::Uri(v) => AtomicValue::scalar(Uri, v),
        Value::AtomicUrl(s) => AtomicValue::scalar(Link, s.to_string()),
        Value::Integer(v) => AtomicValue::scalar(Integer, v.to_string()),
        Value::Float(v) => AtomicValue::scalar(Float, v.to_string()),
        Value::Timestamp(v) => AtomicValue::scalar(Timestamp, v.to_string()),
        Value::Boolean(v) => AtomicValue::scalar(Boolean, v.to_string()),
        Value::ResourceArray(items) => AtomicValue {
            items: items.iter().map(sub_resource_to_value).collect(),
            ..AtomicValue::scalar(Array, "")
        },
        Value::NestedResource(sub) => sub_resource_to_value(sub),
        Value::Json(v) => AtomicValue::scalar(Json, v.to_string()),
        Value::LocalizedText(map) => AtomicValue {
            props: map
                .iter()
                .map(|(language, text)| PropValue {
                    property: language.clone(),
                    value: AtomicValue::scalar(String, text),
                })
                .collect(),
            ..AtomicValue::scalar(Localized, "")
        },
        Value::LoroDoc(bytes) => AtomicValue {
            unsupported_datatype: Some("loroDoc".into()),
            ..AtomicValue::scalar(Unsupported, format!("{} bytes", bytes.len()))
        },
        Value::Unsupported(u) => AtomicValue {
            unsupported_datatype: Some(u.datatype.clone()),
            ..AtomicValue::scalar(Unsupported, &u.value)
        },
    }
}

fn propvals_to_list(props: &PropVals) -> Vec<PropValue> {
    let mut list: Vec<PropValue> = props
        .iter()
        .map(|(property, value)| PropValue {
            property: property.clone(),
            value: value_to_atomic(value),
        })
        .collect();
    list.sort_by(|a, b| a.property.cmp(&b.property));
    list
}

fn atomic_to_sub_resource(value: &AtomicValue) -> Result<SubResource, AtomicError> {
    match value.datatype {
        Datatype::Link => Ok(SubResource::from(value.text.as_str())),
        Datatype::Nested => Ok(SubResource::Nested(list_to_propvals(&value.props)?)),
        _ => Err(AtomicError::invalid(
            "An array holds links and nested resources only",
        )),
    }
}

fn parse<T: std::str::FromStr>(value: &AtomicValue) -> Result<T, AtomicError> {
    value.text.trim().parse().map_err(|_| {
        AtomicError::invalid(format!("{:?} is not a valid {:?}", value.text, value.datatype))
    })
}

pub(crate) fn atomic_to_value(value: &AtomicValue) -> Result<Value, AtomicError> {
    let text = || value.text.clone();
    Ok(match value.datatype {
        Datatype::String => Value::String(text()),
        Datatype::Markdown => Value::Markdown(text()),
        Datatype::Slug => Value::Slug(text()),
        Datatype::Date => Value::Date(text()),
        Datatype::Uri => Value::Uri(text()),
        Datatype::Link => Value::AtomicUrl(value.text.as_str().into()),
        Datatype::Integer => Value::Integer(parse(value)?),
        Datatype::Float => Value::Float(parse(value)?),
        Datatype::Timestamp => Value::Timestamp(parse(value)?),
        Datatype::Boolean => Value::Boolean(parse(value)?),
        Datatype::Array => Value::ResourceArray(
            value
                .items
                .iter()
                .map(atomic_to_sub_resource)
                .collect::<Result<_, _>>()?,
        ),
        Datatype::Nested => Value::NestedResource(SubResource::Nested(list_to_propvals(&value.props)?)),
        Datatype::Json => Value::Json(
            serde_json::from_str(&value.text)
                .map_err(|e| AtomicError::invalid(format!("Not valid JSON: {e}")))?,
        ),
        Datatype::Localized => Value::LocalizedText(
            value
                .props
                .iter()
                .map(|p| (p.property.clone(), p.value.text.clone()))
                .collect(),
        ),
        Datatype::Unsupported => {
            return Err(AtomicError::invalid("An unsupported value cannot be written"))
        }
    })
}

fn list_to_propvals(list: &[PropValue]) -> Result<PropVals, AtomicError> {
    list.iter()
        .map(|p| Ok((p.property.clone(), atomic_to_value(&p.value)?)))
        .collect()
}

// ── Reads ──────────────────────────────────────────────────────────────────

/// The resource `subject` as the local store holds it. [`AtomicError::NotFound`]
/// when this device does not have it (sync first, or ask the server).
pub async fn get_resource_data(subject: String) -> Result<ResourceData, AtomicError> {
    let store = open_store()?;
    let resource = store.get_resource(&subject.as_str().into()).await?;
    Ok(ResourceData {
        subject: resource.get_subject().to_string(),
        props: propvals_to_list(resource.get_propvals()),
    })
}

/// The subjects under `parent`, in the order the sidebar shows them (at most
/// `limit`), without the folders the web hides.
pub async fn get_child_subjects(parent: String, limit: u32) -> Result<Vec<String>, AtomicError> {
    let store = open_store()?;
    let listed = lists::list_children(store, &parent, limit as usize).await?;
    Ok(listed["children"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["subject"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// Full-text search, best first, across every drive or only in `drive`.
pub async fn search_resources(
    query: String,
    drive: Option<String>,
    limit: u32,
) -> Result<Vec<SearchHit>, AtomicError> {
    let store = open_store()?;
    let rows = lists::search(store, drive.as_deref(), &query, limit as usize)?;
    let text = |row: &serde_json::Value, key: &str| row[key].as_str().unwrap_or_default().to_string();
    Ok(rows
        .iter()
        .map(|row| SearchHit {
            subject: text(row, "subject"),
            title: text(row, "title"),
            class_name: text(row, "class_name"),
            drive: text(row, "drive"),
            score: row["score"].as_f64().unwrap_or_default(),
        })
        .collect())
}

// ── Writes ─────────────────────────────────────────────────────────────────

/// Set the `set` properties and remove the `remove` ones of an existing
/// resource, as one signed commit by the active agent.
pub async fn save_resource_changes(
    subject: String,
    set: Vec<PropValue>,
    remove: Vec<String>,
) -> Result<(), AtomicError> {
    let store = open_store()?;
    let mut resource = store.get_resource(&subject.as_str().into()).await?;
    for p in &set {
        resource.set_unsafe(p.property.clone(), atomic_to_value(&p.value)?)?;
    }
    for property in &remove {
        resource.remove_propval(property)?;
    }
    let node = node().map_err(AtomicError::storage)?;
    let response = node.save_locally(&mut resource).await?;
    push_local_write(&response, store.as_ref()).await;
    Ok(())
}

/// Create a resource with a new subject (a DID derived from the signed
/// genesis commit) holding `values`, signed by the active agent. Returns its
/// subject. `values` should include `isA` and `parent`.
pub async fn create_resource_with_values(values: Vec<PropValue>) -> Result<String, AtomicError> {
    if values.is_empty() {
        return Err(AtomicError::invalid("A new resource needs properties"));
    }
    let store = open_store()?;
    let agent = store.get_default_agent()?;
    let mut builder = CommitBuilder::new("placeholder".into());
    for p in &values {
        builder.set(p.property.clone(), atomic_to_value(&p.value)?);
    }
    let commit = Commit::create_did(builder, &agent, store.as_ref()).await?;
    let subject = commit.subject.to_string();
    let node = node().map_err(AtomicError::storage)?;
    let response = node
        .apply_local_commit(commit, &atomic_lib::host::own_commit_opts())
        .await?;
    push_local_write(&response, store.as_ref()).await;
    Ok(subject)
}

/// Create a drive named `name`. Returns its subject.
pub async fn new_drive(name: String) -> Result<String, AtomicError> {
    Ok(open_store()?.create_drive(&name).await?)
}

// ── Watching ───────────────────────────────────────────────────────────────

/// Wait until `subject` changes or is destroyed, or `timeout_ms` passes. Call
/// it in a loop (re-reading the resource on `Changed`) to watch a resource.
pub async fn wait_for_resource_event(
    subject: String,
    timeout_ms: u32,
) -> Result<ResourceEvent, AtomicError> {
    let store = open_store()?;
    Ok(super::simple::resource::wait_resource_event(
        store,
        &subject,
        std::time::Duration::from_millis(timeout_ms as u64),
    )
    .await)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::simple::tests::shared_drive;
    use atomic_lib::urls;

    fn roundtrip(value: AtomicValue) {
        let lib = atomic_to_value(&value).unwrap();
        assert_eq!(value_to_atomic(&lib), value);
    }

    fn scalar(datatype: Datatype, text: &str) -> AtomicValue {
        AtomicValue::scalar(datatype, text)
    }

    #[test]
    fn values_survive_a_round_trip_through_the_library_type() {
        roundtrip(scalar(Datatype::String, "a"));
        roundtrip(scalar(Datatype::Markdown, "# a"));
        roundtrip(scalar(Datatype::Link, "https://example.com/x"));
        roundtrip(scalar(Datatype::Integer, "-4"));
        roundtrip(scalar(Datatype::Float, "1.5"));
        roundtrip(scalar(Datatype::Timestamp, "1700000000000"));
        roundtrip(scalar(Datatype::Boolean, "true"));
        roundtrip(scalar(Datatype::Json, "{\"a\":1}"));
        roundtrip(AtomicValue {
            items: vec![
                scalar(Datatype::Link, "https://example.com/a"),
                AtomicValue {
                    props: vec![PropValue {
                        property: "https://example.com/p".into(),
                        value: scalar(Datatype::Integer, "1"),
                    }],
                    ..scalar(Datatype::Nested, "")
                },
            ],
            ..scalar(Datatype::Array, "")
        });
        roundtrip(AtomicValue {
            props: vec![PropValue {
                property: "nl".into(),
                value: scalar(Datatype::String, "hallo"),
            }],
            ..scalar(Datatype::Localized, "")
        });
    }

    #[test]
    fn what_cannot_be_written_is_invalid() {
        let kind = |v: AtomicValue| atomic_to_value(&v).unwrap_err().kind;
        assert_eq!(kind(scalar(Datatype::Unsupported, "y")), ErrorKind::Invalid);
        assert_eq!(kind(scalar(Datatype::Json, "{")), ErrorKind::Invalid);
        assert_eq!(kind(scalar(Datatype::Integer, "four")), ErrorKind::Invalid);
        assert_eq!(kind(scalar(Datatype::Boolean, "yes")), ErrorKind::Invalid);
        let bad_array = AtomicValue {
            items: vec![scalar(Datatype::Integer, "1")],
            ..scalar(Datatype::Array, "")
        };
        assert_eq!(kind(bad_array), ErrorKind::Invalid);
    }

    fn text(property: &str, value: &str) -> PropValue {
        PropValue {
            property: property.into(),
            value: scalar(Datatype::String, value),
        }
    }

    fn prop<'a>(data: &'a ResourceData, property: &str) -> Option<&'a AtomicValue> {
        data.props.iter().find(|p| p.property == property).map(|p| &p.value)
    }

    #[tokio::test]
    async fn a_resource_is_created_read_changed_and_found() {
        let drive = shared_drive().await.to_string();
        let subject = create_resource_with_values(vec![
            PropValue {
                property: urls::IS_A.into(),
                value: AtomicValue {
                    items: vec![scalar(Datatype::Link, urls::FOLDER)],
                    ..scalar(Datatype::Array, "")
                },
            },
            text(urls::NAME, "Typed pelican"),
            PropValue {
                property: urls::PARENT.into(),
                value: scalar(Datatype::Link, &drive),
            },
        ])
        .await
        .unwrap();

        let data = get_resource_data(subject.clone()).await.unwrap();
        assert_eq!(data.subject, subject);
        assert_eq!(prop(&data, urls::NAME), Some(&scalar(Datatype::String, "Typed pelican")));
        assert_eq!(prop(&data, urls::PARENT), Some(&scalar(Datatype::Link, &drive)));

        save_resource_changes(
            subject.clone(),
            vec![text(urls::NAME, "Typed heron"), text(urls::DESCRIPTION, "A bird")],
            vec![],
        )
        .await
        .unwrap();
        let data = get_resource_data(subject.clone()).await.unwrap();
        assert_eq!(prop(&data, urls::NAME), Some(&scalar(Datatype::String, "Typed heron")));
        save_resource_changes(subject.clone(), vec![], vec![urls::DESCRIPTION.into()])
            .await
            .unwrap();
        assert!(prop(&get_resource_data(subject.clone()).await.unwrap(), urls::DESCRIPTION).is_none());

        let children = get_child_subjects(drive, 100).await.unwrap();
        assert!(children.contains(&subject));
    }

    #[tokio::test]
    async fn a_missing_resource_is_not_found_and_a_bad_value_is_invalid() {
        let drive = shared_drive().await.to_string();
        let missing = get_resource_data(format!("{drive}/no-such-resource")).await;
        assert_eq!(missing.unwrap_err().kind, ErrorKind::NotFound);
        let bad = save_resource_changes(
            drive,
            vec![PropValue {
                property: urls::NAME.into(),
                value: scalar(Datatype::Json, "{"),
            }],
            vec![],
        )
        .await;
        assert_eq!(bad.unwrap_err().kind, ErrorKind::Invalid);
    }
}
