//! Denormalized form definitions, submission validation, and the publish-slug
//! index behind the `/form/:id` server endpoints.
//!
//! See `planning/atomic-forms.md` (Phase 3) for the architecture decisions
//! this module implements: submissions are written by the store's own
//! default agent (there is no visitor agent), so there is no rights check
//! here — only publish-state gating (done by the caller) and the field
//! validation in [`validate_submission`].

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};

use crate::{
    datatype::DataType, db::trees::Tree, errors::AtomicResult, storelike::Storelike,
    utils::random_string, Db, Resource, Subject, Value,
};

/// The submit body's top-level key checked for a non-empty honeypot value.
pub const HONEYPOT_FIELD: &str = "hp";

const PUBLISH_SLUG_MAP_KEY: &[u8] = b"_form_publish_slugs_v1";
const SLUG_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormDefinition {
    pub version: u8,
    pub id: String,
    pub name: String,
    pub settings: JsonValue,
    #[serde(rename = "honeypotField")]
    pub honeypot_field: String,
    pub pages: Vec<FormPageDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormPageDefinition {
    pub name: Option<String>,
    #[serde(rename = "coverImage")]
    pub cover_image: Option<String>,
    #[serde(rename = "imagePosition")]
    pub image_position: Option<String>,
    pub blocks: Vec<FormBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormBlock {
    Heading {
        text: String,
    },
    Paragraph {
        text: String,
    },
    Field {
        #[serde(rename = "mapsTo")]
        maps_to: String,
        label: String,
        description: Option<String>,
        #[serde(rename = "type")]
        field_type: String,
        required: bool,
        options: JsonValue,
    },
}

/// Walks Form -> form-pages -> FormPage -> form-fields, resolving each child
/// into a denormalized block. `id` (the publish slug) is left empty — the
/// caller owns slug resolution/minting and fills it in.
pub async fn build_form_definition(
    store: &impl Storelike,
    form: &Resource,
) -> AtomicResult<FormDefinition> {
    let name = form.get(crate::urls::NAME)?.to_string();
    let settings = match form.get(crate::urls::FORM_SETTINGS) {
        Ok(Value::Json(v)) => v.clone(),
        _ => json!({}),
    };

    let page_subjects = form
        .get(crate::urls::FORM_PAGES)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    let mut pages = Vec::with_capacity(page_subjects.len());
    for page_subject in page_subjects {
        let page = store.get_resource(&page_subject.into()).await?;
        pages.push(build_page_definition(store, &page).await?);
    }

    Ok(FormDefinition {
        version: 1,
        id: String::new(),
        name,
        settings,
        honeypot_field: HONEYPOT_FIELD.to_string(),
        pages,
    })
}

async fn build_page_definition(
    store: &impl Storelike,
    page: &Resource,
) -> AtomicResult<FormPageDefinition> {
    let name = page.get(crate::urls::NAME).ok().map(|v| v.to_string());
    let cover_image = page
        .get(crate::urls::COVER_IMAGE)
        .ok()
        .map(|v| v.to_string());
    let image_position = page
        .get(crate::urls::IMAGE_POSITION)
        .ok()
        .map(|v| v.to_string());

    let field_subjects = page
        .get(crate::urls::FORM_FIELDS)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    let mut blocks = Vec::with_capacity(field_subjects.len());
    for field_subject in field_subjects {
        let field = store.get_resource(&field_subject.into()).await?;
        blocks.push(build_block(&field)?);
    }

    Ok(FormPageDefinition {
        name,
        cover_image,
        image_position,
        blocks,
    })
}

fn build_block(field: &Resource) -> AtomicResult<FormBlock> {
    let classes = field
        .get(crate::urls::IS_A)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    if classes.iter().any(|c| c == crate::urls::FORM_HEADING) {
        let text = field.get(crate::urls::NAME)?.to_string();
        return Ok(FormBlock::Heading { text });
    }
    if classes.iter().any(|c| c == crate::urls::FORM_PARAGRAPH) {
        let text = field.get(crate::urls::DESCRIPTION)?.to_string();
        return Ok(FormBlock::Paragraph { text });
    }
    if classes.iter().any(|c| c == crate::urls::FORM_FIELD) {
        let maps_to = field.get(crate::urls::FORM_MAPS_TO)?.to_string();
        let label = field.get(crate::urls::NAME)?.to_string();
        let description = field
            .get(crate::urls::DESCRIPTION)
            .ok()
            .map(|v| v.to_string());
        let field_type = field.get(crate::urls::FORM_FIELD_TYPE)?.to_string();
        let required = field
            .get(crate::urls::REQUIRED)
            .and_then(|v| v.to_bool())
            .unwrap_or(false);
        let options = match field.get(crate::urls::FORM_FIELD_OPTIONS) {
            Ok(Value::Json(v)) => v.clone(),
            _ => json!({}),
        };
        return Ok(FormBlock::Field {
            maps_to,
            label,
            description,
            field_type,
            required,
            options,
        });
    }

    Err(format!(
        "Resource {} is not a recognized form block (expected FormField, FormHeading or FormParagraph)",
        field.get_subject()
    )
    .into())
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Validates a submitted `values` map against a form's field blocks
/// (required-ness, datatype shape, numeric bounds, option membership) and
/// coerces accepted values into `atomic_lib::Value`s ready for
/// `resource.set()`. Collects every error rather than failing fast, so a
/// client can show all problems at once. Unknown keys in `values` (not
/// matching any field's `mapsTo`) are also reported as errors.
pub fn validate_submission(
    definition: &FormDefinition,
    values: &Map<String, JsonValue>,
) -> Result<Vec<(String, Value)>, Vec<ValidationError>> {
    let fields: Vec<(&String, &String, bool, &JsonValue)> = definition
        .pages
        .iter()
        .flat_map(|p| p.blocks.iter())
        .filter_map(|b| match b {
            FormBlock::Field {
                maps_to,
                field_type,
                required,
                options,
                ..
            } => Some((maps_to, field_type, *required, options)),
            _ => None,
        })
        .collect();

    let mut errors = Vec::new();
    let mut coerced = Vec::new();

    let known: HashSet<&String> = fields.iter().map(|(maps_to, ..)| *maps_to).collect();
    for key in values.keys() {
        if !known.contains(key) {
            errors.push(ValidationError {
                field: key.clone(),
                message: "Unknown property".into(),
            });
        }
    }

    for (maps_to, field_type, required, options) in fields {
        let raw = values.get(maps_to);
        let is_empty = match raw {
            None | Some(JsonValue::Null) => true,
            Some(JsonValue::String(s)) => s.is_empty(),
            Some(JsonValue::Array(a)) => a.is_empty(),
            _ => false,
        };

        if is_empty {
            if required {
                errors.push(ValidationError {
                    field: maps_to.clone(),
                    message: "This field is required".into(),
                });
            }
            continue;
        }

        match coerce_value(field_type, options, raw.expect("checked non-empty above")) {
            Ok(value) => coerced.push((maps_to.clone(), value)),
            Err(message) => errors.push(ValidationError {
                field: maps_to.clone(),
                message,
            }),
        }
    }

    if errors.is_empty() {
        Ok(coerced)
    } else {
        Err(errors)
    }
}

fn coerce_value(field_type: &str, options: &JsonValue, raw: &JsonValue) -> Result<Value, String> {
    match field_type {
        "short-text" | "long-text" => {
            Ok(Value::String(raw.as_str().ok_or("Expected a string")?.to_string()))
        }
        "email" => {
            let s = raw.as_str().ok_or("Expected a string")?.to_string();
            if !is_valid_email(&s) {
                return Err("Not a valid email address".into());
            }
            Ok(Value::String(s))
        }
        "number" => {
            let f = raw.as_f64().ok_or("Expected a number")?;
            if let Some(min) = options.get("min").and_then(|v| v.as_f64()) {
                if f < min {
                    return Err(format!("Must be at least {min}"));
                }
            }
            if let Some(max) = options.get("max").and_then(|v| v.as_f64()) {
                if f > max {
                    return Err(format!("Must be at most {max}"));
                }
            }
            Ok(Value::Float(f))
        }
        "date" => {
            let s = raw.as_str().ok_or("Expected a date string (YYYY-MM-DD)")?;
            Value::new(s, &DataType::Date).map_err(|e| e.to_string())
        }
        "datetime" => {
            let ts = raw.as_i64().ok_or("Expected a timestamp in ms since epoch")?;
            Ok(Value::Timestamp(ts))
        }
        "checkbox" => Ok(Value::Boolean(raw.as_bool().ok_or("Expected a boolean")?)),
        "radio" => {
            let s = raw.as_str().ok_or("Expected a string")?.to_string();
            check_membership(std::slice::from_ref(&s), options)?;
            Ok(Value::String(s))
        }
        "multi-select" => {
            let arr = raw.as_array().ok_or("Expected an array of strings")?;
            let items: Vec<String> = arr
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| "Expected an array of strings".to_string())
                })
                .collect::<Result<_, _>>()?;
            check_membership(&items, options)?;
            Ok(Value::Json(raw.clone()))
        }
        other => Err(format!("Unknown field type: {other}")),
    }
}

fn check_membership(items: &[String], options: &JsonValue) -> Result<(), String> {
    let Some(allowed) = options.get("options").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    let allowed: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
    for item in items {
        if !allowed.contains(&item.as_str()) {
            return Err(format!("'{item}' is not one of the allowed options"));
        }
    }
    Ok(())
}

fn is_valid_email(s: &str) -> bool {
    let re = regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("valid regex");
    re.is_match(s)
}

// ── Publish slug index (redb-backed, mirrors sync::peer's known-peers map) ──

fn get_slug_map(store: &Db) -> HashMap<String, String> {
    if let Ok(Some(bytes)) = store.kv.get(Tree::PluginMeta, PUBLISH_SLUG_MAP_KEY) {
        serde_json::from_slice(&bytes).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

fn save_slug_map(store: &Db, map: &HashMap<String, String>) {
    let _ = store.kv.insert(
        Tree::PluginMeta,
        PUBLISH_SLUG_MAP_KEY,
        &serde_json::to_vec(map).unwrap_or_default(),
    );
}

/// Resolves a `{id}` path segment to a Form resource: first as a known
/// publish slug, falling back to treating `id` as a DID `pure_id()` (which
/// already includes the `did:ad:` scheme — only prefixed when missing) — a
/// bootstrap path for forms that haven't had a slug minted yet (see
/// `planning/atomic-forms.md` Phase 3, "slug bootstrapping decision"). DIDs
/// aren't secret here: form resources need no public read rights (decision
/// #3), so accepting the raw id isn't a new information leak.
pub async fn resolve_form(store: &Db, id: &str) -> AtomicResult<Resource> {
    let map = get_slug_map(store);
    let subject: Subject = match map.get(id) {
        Some(subject) => subject.clone().into(),
        None if id.starts_with("did:ad:") => id.to_string().into(),
        None => format!("did:ad:{id}").into(),
    };
    store.get_resource(&subject).await
}

/// Returns the Form's existing publish slug, or mints, persists (as
/// `form-publish-id`, signed by the store's default agent) and indexes a new
/// one. `form` must reflect the currently stored state.
pub async fn mint_publish_slug(store: &Db, form: &mut Resource) -> AtomicResult<String> {
    if let Ok(existing) = form.get(crate::urls::FORM_PUBLISH_ID) {
        let slug = existing.to_string();
        if !slug.is_empty() {
            return Ok(slug);
        }
    }

    let mut map = get_slug_map(store);
    let slug = loop {
        let candidate = random_string(SLUG_LEN);
        if !map.contains_key(&candidate) {
            break candidate;
        }
    };

    form.set(
        crate::urls::FORM_PUBLISH_ID.into(),
        Value::String(slug.clone()),
        store,
    )
    .await?;
    form.save(store).await?;

    map.insert(slug.clone(), form.get_subject().to_string());
    save_slug_map(store, &map);

    Ok(slug)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::init_store, urls};
    use serde_json::json;

    async fn make_class_and_property(
        store: &Db,
        class_shortname: &str,
        prop_shortname: &str,
        datatype: &str,
    ) -> (String, String) {
        let mut class = Resource::new_instance(urls::CLASS, store).await.unwrap();
        class
            .set(
                urls::SHORTNAME.into(),
                Value::Slug(class_shortname.into()),
                store,
            )
            .await
            .unwrap();
        class
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown("test class".into()),
                store,
            )
            .await
            .unwrap();
        class.save_locally(store).await.unwrap();

        let mut property = Resource::new_instance(urls::PROPERTY, store).await.unwrap();
        property
            .set(
                urls::SHORTNAME.into(),
                Value::Slug(prop_shortname.into()),
                store,
            )
            .await
            .unwrap();
        property
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown("test property".into()),
                store,
            )
            .await
            .unwrap();
        property
            .set(
                urls::DATATYPE_PROP.into(),
                Value::AtomicUrl(datatype.into()),
                store,
            )
            .await
            .unwrap();
        property.save_locally(store).await.unwrap();

        (
            class.get_subject().to_string(),
            property.get_subject().to_string(),
        )
    }

    async fn build_test_form(store: &Db) -> (Resource, String) {
        let (data_class, email_prop) =
            make_class_and_property(store, "test-class", "email-question", urls::STRING).await;

        let mut table = Resource::new_instance(urls::TABLE, store).await.unwrap();
        table
            .set(urls::NAME.into(), Value::String("Test Table".into()), store)
            .await
            .unwrap();
        table
            .set(
                urls::CLASSTYPE_PROP.into(),
                Value::AtomicUrl(data_class.clone().into()),
                store,
            )
            .await
            .unwrap();
        table.save_locally(store).await.unwrap();

        let mut field = Resource::new_instance(urls::FORM_FIELD, store).await.unwrap();
        field
            .set(urls::NAME.into(), Value::String("Email".into()), store)
            .await
            .unwrap();
        field
            .set(
                urls::FORM_MAPS_TO.into(),
                Value::AtomicUrl(email_prop.clone().into()),
                store,
            )
            .await
            .unwrap();
        field
            .set(
                urls::FORM_FIELD_TYPE.into(),
                Value::String("email".into()),
                store,
            )
            .await
            .unwrap();
        field
            .set(urls::REQUIRED.into(), Value::Boolean(true), store)
            .await
            .unwrap();
        field.save_locally(store).await.unwrap();

        let mut page = Resource::new_instance(urls::FORM_PAGE, store).await.unwrap();
        page.set(
            urls::FORM_FIELDS.into(),
            Value::ResourceArray(vec![field.get_subject().to_string().into()]),
            store,
        )
        .await
        .unwrap();
        page.save_locally(store).await.unwrap();

        let mut form = Resource::new_instance(urls::FORM, store).await.unwrap();
        form.set(urls::NAME.into(), Value::String("Test Form".into()), store)
            .await
            .unwrap();
        form.set(
            urls::FORM_DATA_CLASS.into(),
            Value::AtomicUrl(data_class.into()),
            store,
        )
        .await
        .unwrap();
        form.set(
            urls::FORM_TARGET_TABLE.into(),
            Value::AtomicUrl(table.get_subject().to_string().into()),
            store,
        )
        .await
        .unwrap();
        form.set(
            urls::FORM_PAGES.into(),
            Value::ResourceArray(vec![page.get_subject().to_string().into()]),
            store,
        )
        .await
        .unwrap();
        // A DID (genesis) subject, matching how forms are actually created by
        // the data-browser client (`store.newResource` for a DID-based
        // agent) — needed so the slug bootstrap fallback (resolving by
        // `pure_id()`) is exercised faithfully.
        form.save_as_genesis(store).await.unwrap();

        (form, email_prop)
    }

    #[tokio::test]
    async fn builds_definition_from_graph() {
        let store = init_store().await;
        let (form, email_prop) = build_test_form(&store).await;

        let definition = build_form_definition(&store, &form).await.unwrap();
        assert_eq!(definition.pages.len(), 1);
        assert_eq!(definition.pages[0].blocks.len(), 1);
        match &definition.pages[0].blocks[0] {
            FormBlock::Field {
                maps_to,
                field_type,
                required,
                ..
            } => {
                assert_eq!(maps_to, &email_prop);
                assert_eq!(field_type, "email");
                assert!(*required);
            }
            other => panic!("expected a Field block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_submission_rejects_missing_required_field() {
        let store = init_store().await;
        let (form, _email_prop) = build_test_form(&store).await;
        let definition = build_form_definition(&store, &form).await.unwrap();

        let values = Map::new();
        let result = validate_submission(&definition, &values);
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "This field is required");
    }

    #[tokio::test]
    async fn validate_submission_rejects_invalid_email() {
        let store = init_store().await;
        let (form, email_prop) = build_test_form(&store).await;
        let definition = build_form_definition(&store, &form).await.unwrap();

        let mut values = Map::new();
        values.insert(email_prop, json!("not-an-email"));
        let errors = validate_submission(&definition, &values).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "Not a valid email address");
    }

    #[tokio::test]
    async fn validate_submission_rejects_unknown_property() {
        let store = init_store().await;
        let (form, email_prop) = build_test_form(&store).await;
        let definition = build_form_definition(&store, &form).await.unwrap();

        let mut values = Map::new();
        values.insert(email_prop, json!("a@b.com"));
        values.insert("https://example.com/unknown".into(), json!("x"));
        let errors = validate_submission(&definition, &values).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "Unknown property");
    }

    #[tokio::test]
    async fn validate_submission_accepts_valid_email() {
        let store = init_store().await;
        let (form, email_prop) = build_test_form(&store).await;
        let definition = build_form_definition(&store, &form).await.unwrap();

        let mut values = Map::new();
        values.insert(email_prop.clone(), json!("a@b.com"));
        let coerced = validate_submission(&definition, &values).unwrap();
        assert_eq!(coerced.len(), 1);
        assert_eq!(coerced[0].0, email_prop);
    }

    #[tokio::test]
    async fn number_field_enforces_min_max() {
        let definition = FormDefinition {
            version: 1,
            id: String::new(),
            name: "n".into(),
            settings: json!({}),
            honeypot_field: HONEYPOT_FIELD.into(),
            pages: vec![FormPageDefinition {
                name: None,
                cover_image: None,
                image_position: None,
                blocks: vec![FormBlock::Field {
                    maps_to: "https://example.com/n".into(),
                    label: "Number".into(),
                    description: None,
                    field_type: "number".into(),
                    required: true,
                    options: json!({"min": 1, "max": 10}),
                }],
            }],
        };

        let mut values = Map::new();
        values.insert("https://example.com/n".into(), json!(100));
        let errors = validate_submission(&definition, &values).unwrap_err();
        assert_eq!(errors[0].message, "Must be at most 10");
    }

    #[tokio::test]
    async fn radio_field_enforces_option_membership() {
        let definition = FormDefinition {
            version: 1,
            id: String::new(),
            name: "n".into(),
            settings: json!({}),
            honeypot_field: HONEYPOT_FIELD.into(),
            pages: vec![FormPageDefinition {
                name: None,
                cover_image: None,
                image_position: None,
                blocks: vec![FormBlock::Field {
                    maps_to: "https://example.com/r".into(),
                    label: "Radio".into(),
                    description: None,
                    field_type: "radio".into(),
                    required: true,
                    options: json!({"options": ["A", "B"]}),
                }],
            }],
        };

        let mut values = Map::new();
        values.insert("https://example.com/r".into(), json!("C"));
        let errors = validate_submission(&definition, &values).unwrap_err();
        assert!(errors[0].message.contains("not one of the allowed options"));
    }

    #[tokio::test]
    async fn mints_and_resolves_publish_slug() {
        let store = init_store().await;
        let (mut form, _email_prop) = build_test_form(&store).await;

        let slug = mint_publish_slug(&store, &mut form).await.unwrap();
        assert_eq!(slug.len(), SLUG_LEN);

        // Minting again returns the same, already-persisted slug.
        let slug_again = mint_publish_slug(&store, &mut form).await.unwrap();
        assert_eq!(slug, slug_again);

        let resolved = resolve_form(&store, &slug).await.unwrap();
        assert_eq!(resolved.get_subject(), form.get_subject());

        // Bootstrap fallback: the DID pure_id still resolves even without a slug.
        let resolved_by_did = resolve_form(&store, &form.get_subject().pure_id())
            .await
            .unwrap();
        assert_eq!(resolved_by_did.get_subject(), form.get_subject());
    }

    #[tokio::test]
    async fn slug_collision_retries() {
        let store = init_store().await;
        let (mut form_a, _) = build_test_form(&store).await;
        let (mut form_b, _) = build_test_form(&store).await;

        let slug_a = mint_publish_slug(&store, &mut form_a).await.unwrap();
        let slug_b = mint_publish_slug(&store, &mut form_b).await.unwrap();
        assert_ne!(slug_a, slug_b);
    }
}
