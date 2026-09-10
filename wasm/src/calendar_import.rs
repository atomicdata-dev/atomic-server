//! Generic, caller supplied query overrides for bounded imports.
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryOverride {
    path: String,
    values: BTreeMap<String, Value>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaPropertyOverride {
    schema: String,
    properties: BTreeMap<String, Value>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportOverrides {
    #[serde(default)]
    query_overrides: Vec<QueryOverride>,
    #[serde(default)]
    schema_property_overrides: Vec<SchemaPropertyOverride>,
}

/// Applies values supplied by the selected external lens. The host only
/// matches documented collection URL templates and knows no provider names.
pub(super) fn apply_query_overrides(
    document: &mut Value,
    input: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let overrides: ImportOverrides = serde_json::from_str(input)?;
    let resources_read = document
        .pointer("/components/crudResources")
        .and_then(Value::as_object)
        .ok_or("Catalog has no CRUD resources")?;
    for override_ in &overrides.query_overrides {
        let matches = resources_read
            .values()
            .filter_map(|resource| resource.get("collections").and_then(Value::as_object))
            .flat_map(|collections| collections.values())
            .filter(|collection| {
                collection.get("urlTemplate").and_then(Value::as_str)
                    == Some(override_.path.as_str())
            })
            .count();
        if matches != 1 {
            return Err(format!("Unknown or ambiguous collection path {}", override_.path).into());
        }
        let operation = document
            .get("paths")
            .and_then(|paths| paths.get(&override_.path))
            .and_then(|path| path.get("get"))
            .ok_or_else(|| format!("Collection {} has no GET operation", override_.path))?;
        for name in override_.values.keys() {
            let declared = operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|parameter| {
                    parameter.get("name").and_then(Value::as_str) == Some(name)
                        && parameter.get("in").and_then(Value::as_str) == Some("query")
                });
            if !declared {
                return Err(
                    format!("Unknown query parameter {name} for {}", override_.path).into(),
                );
            }
        }
    }
    let resources = document
        .pointer_mut("/components/crudResources")
        .and_then(Value::as_object_mut)
        .ok_or("Catalog has no CRUD resources")?;
    for resource in resources.values_mut() {
        let Some(collections) = resource
            .get_mut("collections")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        for collection in collections.values_mut() {
            let Some(path) = collection.get("urlTemplate").and_then(Value::as_str) else {
                continue;
            };
            let Some(override_) = overrides
                .query_overrides
                .iter()
                .find(|item| item.path == path)
            else {
                continue;
            };
            let query = collection
                .as_object_mut()
                .unwrap()
                .entry("x-list-query")
                .or_insert_with(|| Value::Object(Default::default()))
                .as_object_mut()
                .ok_or("Invalid collection query")?;
            for (name, value) in &override_.values {
                if value.is_null() {
                    query.remove(name);
                } else {
                    query.insert(name.clone(), value.clone());
                }
            }
        }
    }
    let schemas = document
        .pointer_mut("/components/schemas")
        .and_then(Value::as_object_mut)
        .ok_or("Catalog has no schemas")?;
    for override_ in &overrides.schema_property_overrides {
        let properties = schemas
            .get_mut(&override_.schema)
            .and_then(|schema| schema.get_mut("properties"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("Unknown schema {}", override_.schema))?;
        for (name, value) in &override_.properties {
            properties.insert(name.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn applies_matching_documented_collection_path() {
        let mut doc = json!({"paths":{"/events":{"get":{"parameters":[{"name":"from","in":"query"}]}}},"components":{"crudResources":{"event":{"collections":{"events":{"urlTemplate":"/events"}}}}}});
        apply_query_overrides(
            &mut doc,
            r#"{"query_overrides":[{"path":"/events","values":{"from":"2026-03-01"}}]}"#,
        )
        .unwrap();
        assert_eq!(
            doc["components"]["crudResources"]["event"]["collections"]["events"]["x-list-query"]
                ["from"],
            "2026-03-01"
        );
    }

    #[test]
    fn rejects_unknown_collection_paths_and_query_parameters() {
        let document = || json!({"paths":{"/events":{"get":{"parameters":[{"name":"from","in":"query"}]}}},"components":{"crudResources":{"event":{"collections":{"events":{"urlTemplate":"/events"}}}}}});
        assert!(apply_query_overrides(
            &mut document(),
            r#"{"query_overrides":[{"path":"/missing","values":{"from":"x"}}]}"#,
        )
        .unwrap_err()
        .to_string()
        .contains("Unknown or ambiguous collection path"));
        assert!(apply_query_overrides(
            &mut document(),
            r#"{"query_overrides":[{"path":"/events","values":{"typo":"x"}}]}"#,
        )
        .unwrap_err()
        .to_string()
        .contains("Unknown query parameter typo"));
    }

    #[test]
    fn removes_defaults_and_extends_existing_schema() {
        let mut doc = json!({"paths":{"/events":{"get":{"parameters":[{"name":"from","in":"query"}]}}},"components":{"schemas":{"event":{"properties":{}}},"crudResources":{"event":{"collections":{"events":{"urlTemplate":"/events","x-list-query":{"from":"stale"}}}}}}});
        apply_query_overrides(
            &mut doc,
            r#"{"query_overrides":[{"path":"/events","values":{"from":null}}],"schema_property_overrides":[{"schema":"event","properties":{"recurrence":{"type":"array"}}}]}"#,
        )
        .unwrap();
        assert!(doc["components"]["crudResources"]["event"]["collections"]["events"]
            ["x-list-query"]
            .get("from")
            .is_none());
        assert_eq!(doc["components"]["schemas"]["event"]["properties"]["recurrence"]["type"], "array");
    }
}
