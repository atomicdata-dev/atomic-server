//! Atomic values and resources, to and from the ABI's typed records.
//!
//! Reads convert directly. Writes go the other way through JSON: an `intent`
//! becomes the verdict shape [`crate::plugins::plan`] already plans and
//! [`crate::plugins::apply`] already applies, so a write over the ABI is
//! checked by exactly the code that checks every other write.

use atomic_lib::{
    storelike::{FilterOperator, PropVal, Query},
    values::SubResource,
    Resource, Value,
};
use serde_json::{json, Value as Json};

use super::{
    bindings::atomic::host::{
        store::{Filter, FilterOp, Intent, QuerySpec},
        types::{PropVal as WitPropVal, Resource as WitResource, Value as WitValue},
    },
    code, error, HostError,
};

pub(super) fn subresource_subject(sub: &SubResource) -> Option<String> {
    match sub {
        SubResource::Subject(subject) => Some(subject.to_string()),
        SubResource::Nested(_) => None,
    }
}

/// An Atomic value as the closest typed case. Anything without one (a nested
/// resource, a Loro document, localized text) crosses as JSON text.
pub(super) fn to_wit_value(value: &Value) -> WitValue {
    match value {
        Value::Boolean(b) => WitValue::Boolean(*b),
        Value::Integer(i) | Value::Timestamp(i) => WitValue::Integer(*i),
        Value::Float(f) => WitValue::Float(*f),
        Value::String(s) | Value::Markdown(s) | Value::Slug(s) | Value::Date(s) | Value::Uri(s) => {
            WitValue::String(s.clone())
        }
        Value::AtomicUrl(subject) => WitValue::Link(subject.to_string()),
        Value::ResourceArray(items) => {
            let subjects: Option<Vec<String>> = items.iter().map(subresource_subject).collect();
            match subjects {
                Some(subjects) => WitValue::ResourceArray(subjects),
                None => WitValue::Json(value_json(value)),
            }
        }
        Value::Json(json) => WitValue::Json(json.to_string()),
        Value::LocalizedText(_) | Value::NestedResource(_) | Value::LoroDoc(_) => {
            WitValue::Json(value_json(value))
        }
        Value::Unsupported(unsupported) => WitValue::String(unsupported.value.clone()),
    }
}

fn value_json(value: &Value) -> String {
    match value {
        Value::LocalizedText(map) => json!(map).to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    }
}

pub(super) fn to_wit_resource(resource: &Resource) -> WitResource {
    let mut propvals: Vec<WitPropVal> = resource
        .get_propvals()
        .iter()
        .map(|(property, value)| WitPropVal {
            property: property.clone(),
            value: to_wit_value(value),
        })
        .collect();
    // A stable order: callers diff and hash what they read.
    propvals.sort_by(|a, b| a.property.cmp(&b.property));
    WitResource {
        subject: resource.get_subject().to_string(),
        classes: resource
            .get(atomic_lib::urls::IS_A)
            .ok()
            .and_then(|classes| classes.to_subjects(None).ok())
            .unwrap_or_default(),
        propvals,
    }
}

/// A typed value, as the JSON the planner takes for a `set`.
pub(super) fn wit_value_json(value: &WitValue) -> Result<Json, HostError> {
    Ok(match value {
        WitValue::Null => Json::Null,
        WitValue::Boolean(b) => Json::Bool(*b),
        WitValue::Integer(i) => json!(i),
        WitValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .ok_or_else(|| error(code::INVALID_ARGUMENT, "a float value must be finite"))?,
        WitValue::String(s) | WitValue::Link(s) => Json::String(s.clone()),
        WitValue::ResourceArray(items) => json!(items),
        WitValue::Json(text) => serde_json::from_str(text).map_err(|e| {
            error(
                code::INVALID_ARGUMENT,
                format!("a json value is not JSON text: {e}"),
            )
        })?,
    })
}

/// `local:<name>` as the bare `<name>` the planner's `localId` takes.
fn bare_local_id(id: &str) -> &str {
    id.strip_prefix("local:").unwrap_or(id)
}

/// The intents as one verdict for the planner.
pub(super) fn intents_to_verdict(intents: &[Intent]) -> Result<Json, HostError> {
    let props = |list: &[WitPropVal]| -> Result<serde_json::Map<String, Json>, HostError> {
        let mut map = serde_json::Map::new();
        for pv in list {
            map.insert(pv.property.clone(), wit_value_json(&pv.value)?);
        }
        Ok(map)
    };

    let mut out = Vec::with_capacity(intents.len());
    for intent in intents {
        out.push(match intent {
            Intent::Create(create) => json!({
                "op": "create",
                "localId": bare_local_id(&create.local_id),
                "parent": create.parent,
                "isA": create.classes,
                "set": props(&create.set)?,
            }),
            Intent::Set((subject, set)) => json!({
                "op": "set",
                "subject": subject,
                "set": props(set)?,
            }),
            Intent::Remove((subject, properties)) => json!({
                "op": "remove",
                "subject": subject,
                "properties": properties,
            }),
            Intent::Destroy(subject) => json!({"op": "destroy", "subject": subject}),
        });
    }
    Ok(json!({ "intents": out }))
}

fn operator(op: FilterOp) -> Option<FilterOperator> {
    Some(match op {
        FilterOp::Eq => FilterOperator::Equal,
        FilterOp::Lt => FilterOperator::LessThan,
        FilterOp::Lte => FilterOperator::LessThanOrEqual,
        FilterOp::Gt => FilterOperator::GreaterThan,
        FilterOp::Gte => FilterOperator::GreaterThanOrEqual,
        FilterOp::Contains => FilterOperator::Contains,
        // `exists` is a property with no value; `ne` has no index to answer it.
        FilterOp::Exists | FilterOp::Ne => return None,
    })
}

/// Largest page, and the page when none is asked for.
pub(super) const MAX_LIMIT: u32 = 500;
pub(super) const DEFAULT_LIMIT: u32 = 100;

/// The most rows one query scans; past it the answer is marked incomplete.
pub(super) const SCAN_CAP: usize = 10_000;

/// Checks a spec the host can answer and returns its page window as
/// `(offset, limit)`.
pub(super) fn check_spec(spec: &QuerySpec) -> Result<(usize, usize), HostError> {
    if spec.class.is_none() && spec.parent.is_none() && spec.filters.is_empty() {
        return Err(error(
            code::INVALID_ARGUMENT,
            "a query needs a class, a parent or a filter",
        ));
    }
    if let Some(limit) = spec.limit {
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(error(
                code::INVALID_ARGUMENT,
                format!("limit must be 1..={MAX_LIMIT}"),
            ));
        }
    }
    for filter in &spec.filters {
        if matches!(filter.op, FilterOp::Ne) {
            return Err(error(
                code::UNSUPPORTED,
                "the ne filter is not supported yet",
            ));
        }
        if !matches!(filter.op, FilterOp::Exists) && filter.value.is_none() {
            return Err(error(code::INVALID_ARGUMENT, "this filter needs a value"));
        }
    }
    let offset = match &spec.cursor {
        None => 0,
        Some(cursor) => cursor.parse::<usize>().map_err(|_| {
            error(
                code::INVALID_ARGUMENT,
                "the cursor is not one this host gave",
            )
        })?,
    };
    Ok((offset, spec.limit.unwrap_or(DEFAULT_LIMIT) as usize))
}

/// The store query for a spec, scoped to the drive. Every constraint is an
/// index lookup; the caller applies the page window itself (see `store.rs`).
pub(super) async fn to_query(
    db: &atomic_lib::Db,
    spec: &QuerySpec,
    drive: &str,
) -> Result<Query, HostError> {
    use atomic_lib::{urls, Storelike};

    let mut constraints: Vec<PropVal> = Vec::new();
    if let Some(class) = &spec.class {
        constraints.push(PropVal {
            property: Some(urls::IS_A.into()),
            value: Some(Value::AtomicUrl(class.as_str().into())),
            operator: FilterOperator::Equal,
        });
    }
    if let Some(parent) = &spec.parent {
        constraints.push(PropVal {
            property: Some(urls::PARENT.into()),
            value: Some(Value::AtomicUrl(parent.as_str().into())),
            operator: FilterOperator::Equal,
        });
    }
    for Filter {
        property,
        op,
        value,
    } in &spec.filters
    {
        if matches!(op, FilterOp::Exists) {
            constraints.push(PropVal {
                property: Some(property.clone()),
                value: None,
                operator: FilterOperator::Equal,
            });
            continue;
        }
        let operator = operator(*op)
            .ok_or_else(|| error(code::UNSUPPORTED, "the ne filter is not supported yet"))?;
        let datatype = db
            .get_property(property)
            .await
            .map_err(|e| {
                error(
                    code::INVALID_ARGUMENT,
                    format!("{property} is not a property: {e}"),
                )
            })?
            .data_type;
        let json = wit_value_json(value.as_ref().expect("checked by check_spec"))?;
        let value = crate::plugins::store_host::json_to_value(json, &datatype)
            .map_err(|e| error(code::INVALID_ARGUMENT, e))?;
        constraints.push(PropVal {
            property: Some(property.clone()),
            value: Some(value),
            operator,
        });
    }

    let mut constraints = constraints.into_iter();
    let first = constraints.next().expect("checked by check_spec");
    let mut query = Query::new();
    // `Query` has one equality slot and a list of further constraints; a first
    // constraint that is not an equality goes in the list.
    if first.operator == FilterOperator::Equal {
        query.property = first.property;
        query.value = first.value;
    } else {
        query.filters.push(first);
    }
    query.filters.extend(constraints);
    query.sort_by = spec.sort_by.clone();
    query.sort_desc = spec.sort_desc;
    query.include_nested = true;
    query.drive = Some(drive.into());
    Ok(query)
}
