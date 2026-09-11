//! Schema-to-value synthesis, shared by the mock server for seeding and
//! for example responses.
//!
//! A schema's own fixed `example` is reused verbatim on every call, so
//! callers generating more than one item from the same schema (resource
//! seeding, paginated list generation) must inject their own unique `id`
//! afterward rather than relying on the generated value to differ per item.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Number, Value};

use crate::openapi::types::SchemaObject;

static STRING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Synthesizes a value matching a JSON Schema, preferring an `example` on
/// the schema itself when present.
pub fn generate_from_schema(schema: Option<&SchemaObject>) -> Value {
    let Some(schema) = schema else {
        return Value::Null;
    };
    if let Some(example) = &schema.example {
        return example.clone();
    }
    if let Some(enum_values) = &schema.enum_values {
        if let Some(first) = enum_values.first() {
            return first.clone();
        }
    }
    if let Some(all_of) = &schema.all_of {
        let mut merged = Map::new();
        for sub in all_of {
            if let Value::Object(object) = generate_from_schema(Some(sub)) {
                merged.extend(object);
            }
        }
        return Value::Object(merged);
    }
    if let Some(one_of) = &schema.one_of {
        if let Some(first) = one_of.first() {
            return generate_from_schema(Some(first));
        }
    }
    if let Some(any_of) = &schema.any_of {
        if let Some(first) = any_of.first() {
            return generate_from_schema(Some(first));
        }
    }

    match schema.schema_type.as_deref() {
        Some("string") => Value::String(generate_string(schema)),
        Some("integer" | "number") => {
            Number::from_f64(schema.minimum.unwrap_or(1.0)).map_or(Value::Null, Value::Number)
        }
        Some("boolean") => Value::Bool(true),
        Some("array") => Value::Array(vec![generate_from_schema(schema.items.as_deref())]),
        Some("object") | None => Value::Object(generate_object(schema)),
        Some(_) => Value::Null,
    }
}

fn generate_object(schema: &SchemaObject) -> Map<String, Value> {
    let mut result = Map::new();
    for (key, property_schema) in schema.properties.iter().flatten() {
        result.insert(key.clone(), generate_from_schema(Some(property_schema)));
    }
    result
}

fn generate_string(schema: &SchemaObject) -> String {
    match schema.format.as_deref() {
        Some("date-time") => "1970-01-01T00:00:00.000Z".to_string(),
        Some("date") => "1970-01-01".to_string(),
        Some("uuid") => "00000000-0000-4000-8000-000000000000".to_string(),
        Some("email") => "user@example.com".to_string(),
        Some("uri" | "url") => "https://example.com".to_string(),
        _ => {
            let next = STRING_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
            format!("string-{next}")
        }
    }
}
