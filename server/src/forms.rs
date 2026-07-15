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

use atomic_lib::{
    agents::ForAgent,
    datatype::DataType,
    db::{drive_prefix_from_subject, trees::Tree},
    errors::AtomicResult,
    storelike::{FilterOperator, PropVal, Query, QueryResult, Storelike},
    utils::random_string,
    Db, Resource, Subject, Value,
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
    pub styling: FormStyling,
    #[serde(rename = "honeypotField")]
    pub honeypot_field: String,
    /// Captcha client config (`crate::captcha::CaptchaVerifier::client_config`).
    /// Left `None` by [build_form_definition] — the HTTP handlers fill it in
    /// (it references the publish slug), keeping this builder pure and the
    /// data-browser's preview mirror (`buildFormDefinition.ts`) unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha: Option<JsonValue>,
    pub pages: Vec<FormPageDefinition>,
}

/// Visual theming for the published runtime, mirrored by `FormStyling` in
/// `@tomic/form-renderer` (same keep-in-lockstep convention as
/// [FormDefinition]). Colors/roundness come from the Form's `form-styling`
/// JSON; `image_url` is left empty by [build_form_definition] — the caller
/// owns URL construction (the HTTP handlers point it at `/form/{id}/image`,
/// the data-browser preview at the File's own `downloadURL`). `has_image` +
/// `image_position` come from the Form's `cover-image` / `image-position`
/// props.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FormStyling {
    /// Internal signal for the handlers (a cover-image exists, fill in
    /// `image_url`); not part of the wire format.
    #[serde(skip)]
    pub has_image: bool,
    #[serde(rename = "imageUrl", skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(rename = "imagePosition", skip_serializing_if = "Option::is_none")]
    pub image_position: Option<String>,
    #[serde(rename = "textColor", skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(rename = "mainColor", skip_serializing_if = "Option::is_none")]
    pub main_color: Option<String>,
    #[serde(rename = "backgroundColor", skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roundness: Option<String>,
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
    let name = form.get(atomic_lib::urls::NAME)?.to_string();
    let settings = match form.get(atomic_lib::urls::FORM_SETTINGS) {
        Ok(Value::Json(v)) => v.clone(),
        _ => json!({}),
    };
    let styling = build_form_styling(form);

    let page_subjects = form
        .get(atomic_lib::urls::FORM_PAGES)
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
        styling,
        honeypot_field: HONEYPOT_FIELD.to_string(),
        captcha: None,
        pages,
    })
}

fn build_form_styling(form: &Resource) -> FormStyling {
    // The String arm covers docs written before the client could resolve the
    // form-styling Property (no `json` datatype tag → the value materializes
    // as its raw serialized string).
    let styling_json = match form.get(atomic_lib::urls::FORM_STYLING) {
        Ok(Value::Json(v)) => v.clone(),
        Ok(Value::String(s)) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
        _ => json!({}),
    };
    let get_str = |key: &str| {
        styling_json
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    FormStyling {
        has_image: form.get(atomic_lib::urls::COVER_IMAGE).is_ok(),
        image_url: None,
        image_position: form
            .get(atomic_lib::urls::IMAGE_POSITION)
            .ok()
            .map(|v| v.to_string()),
        text_color: get_str("textColor"),
        main_color: get_str("mainColor"),
        background_color: get_str("backgroundColor"),
        roundness: get_str("roundness"),
    }
}

async fn build_page_definition(
    store: &impl Storelike,
    page: &Resource,
) -> AtomicResult<FormPageDefinition> {
    let name = page.get(atomic_lib::urls::NAME).ok().map(|v| v.to_string());
    let cover_image = page
        .get(atomic_lib::urls::COVER_IMAGE)
        .ok()
        .map(|v| v.to_string());
    let image_position = page
        .get(atomic_lib::urls::IMAGE_POSITION)
        .ok()
        .map(|v| v.to_string());

    let field_subjects = page
        .get(atomic_lib::urls::FORM_FIELDS)
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
        .get(atomic_lib::urls::IS_A)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    if classes.iter().any(|c| c == atomic_lib::urls::FORM_HEADING) {
        let text = field.get(atomic_lib::urls::NAME)?.to_string();
        return Ok(FormBlock::Heading { text });
    }
    if classes
        .iter()
        .any(|c| c == atomic_lib::urls::FORM_PARAGRAPH)
    {
        let text = field.get(atomic_lib::urls::DESCRIPTION)?.to_string();
        return Ok(FormBlock::Paragraph { text });
    }
    if classes.iter().any(|c| c == atomic_lib::urls::FORM_FIELD) {
        let maps_to = field.get(atomic_lib::urls::FORM_MAPS_TO)?.to_string();
        let label = field.get(atomic_lib::urls::NAME)?.to_string();
        let description = field
            .get(atomic_lib::urls::DESCRIPTION)
            .ok()
            .map(|v| v.to_string());
        let field_type = field.get(atomic_lib::urls::FORM_FIELD_TYPE)?.to_string();
        let required = field
            .get(atomic_lib::urls::REQUIRED)
            .and_then(|v| v.to_bool())
            .unwrap_or(false);
        let options = match field.get(atomic_lib::urls::FORM_FIELD_OPTIONS) {
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
        "short-text" | "long-text" => Ok(Value::String(
            raw.as_str().ok_or("Expected a string")?.to_string(),
        )),
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
            let ts = raw
                .as_i64()
                .ok_or("Expected a timestamp in ms since epoch")?;
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

// ── Submission summary (server-computed, ephemeral) ─────────────────────────

/// Hard cap on rows aggregated per summary, so a huge table can't stall a GET.
const SUMMARY_ROW_LIMIT: usize = 10_000;
/// Max free-text answers included per field.
const SUMMARY_ANSWER_SAMPLE_LIMIT: usize = 100;
/// Histogram bin count the nice-width search aims for (actual count varies).
const SUMMARY_HISTOGRAM_TARGET_BINS: usize = 9;

/// Aggregates a Form's submission rows into the `form-submission-summary`
/// JSON served by the Form class extender. Field order follows the form
/// definition (pages, then fields). The row query runs as `for_agent`, so a
/// caller inside the resource-GET path inherits its rights checks. Shape is
/// mirrored by `FormSummary` in the data-browser's `SummaryTab` — keep in
/// lockstep (no codegen), same convention as [FormDefinition].
pub async fn build_form_summary(
    store: &Db,
    form: &Resource,
    for_agent: &ForAgent,
) -> AtomicResult<JsonValue> {
    let definition = build_form_definition(store, form).await?;
    let table_subject = form.get(atomic_lib::urls::FORM_TARGET_TABLE)?.to_string();
    let data_class = form.get(atomic_lib::urls::FORM_DATA_CLASS)?.to_string();

    let query = Query {
        property: Some(atomic_lib::urls::PARENT.into()),
        value: Some(Value::AtomicUrl(table_subject.into())),
        filters: vec![PropVal {
            property: Some(atomic_lib::urls::IS_A.into()),
            value: Some(Value::AtomicUrl(data_class.into())),
            operator: FilterOperator::Equal,
        }],
        limit: Some(SUMMARY_ROW_LIMIT),
        for_agent: for_agent.clone(),
        // Same fallback the collections `/query` path uses when no drive is
        // given; the propval (stamped at genesis on client-created forms) is
        // the real owning drive.
        drive: Some(
            form.get_drive()
                .unwrap_or_else(|| drive_prefix_from_subject(form.get_subject())),
        ),
        ..Query::new()
    };
    let QueryResult {
        resources: rows, ..
    } = store.query(&query).await?;

    let mut fields = Vec::new();
    for page in &definition.pages {
        for block in &page.blocks {
            if let FormBlock::Field {
                maps_to,
                label,
                field_type,
                options,
                ..
            } = block
            {
                let values: Vec<&Value> = rows
                    .iter()
                    .filter_map(|row| row.get(maps_to).ok())
                    .filter(|v| !is_empty_value(v))
                    .collect();
                fields.push(summarize_field(
                    maps_to,
                    label,
                    field_type,
                    options,
                    &values,
                    rows.len(),
                ));
            }
        }
    }

    Ok(json!({ "responses": rows.len(), "fields": fields }))
}

/// Values the submit pipeline would never write, but that could sneak in via
/// direct table edits — treated as "skipped" rather than as an answer.
fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::String(s) | Value::Markdown(s) | Value::Slug(s) => s.is_empty(),
        Value::Json(JsonValue::Null) => true,
        Value::Json(JsonValue::Array(a)) => a.is_empty(),
        _ => false,
    }
}

fn summarize_field(
    maps_to: &str,
    label: &str,
    field_type: &str,
    options: &JsonValue,
    values: &[&Value],
    total_rows: usize,
) -> JsonValue {
    let answered = values.len();
    let mut summary = json!({
        "mapsTo": maps_to,
        "label": label,
        "type": field_type,
        "answered": answered,
        "skipped": total_rows.saturating_sub(answered),
    });
    let obj = summary.as_object_mut().expect("built as an object above");

    match field_type {
        "radio" => {
            let picks = values.iter().map(|v| v.to_string());
            obj.insert("counts".into(), choice_counts(options, picks));
        }
        "multi-select" => {
            // Each answer is a `Value::Json` array of picked option strings.
            let picks = values.iter().flat_map(|v| match v {
                Value::Json(JsonValue::Array(items)) => items
                    .iter()
                    .filter_map(|i| i.as_str().map(str::to_string))
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            });
            obj.insert("counts".into(), choice_counts(options, picks));
        }
        "checkbox" => {
            let checked = values
                .iter()
                .filter(|v| matches!(v, Value::Boolean(true)))
                .count();
            obj.insert("checked".into(), json!(checked));
            obj.insert("unchecked".into(), json!(answered - checked));
        }
        "number" => {
            let numbers: Vec<f64> = values.iter().filter_map(|v| as_f64(v)).collect();
            if let Some((bins, min, max, mean)) = histogram(&numbers) {
                obj.insert("bins".into(), bins);
                obj.insert("min".into(), json!(min));
                obj.insert("max".into(), json!(max));
                obj.insert("mean".into(), json!(mean));
            }
        }
        // short-text, long-text, email, date, datetime: a sample of answers.
        _ => {
            let answers: Vec<JsonValue> = values
                .iter()
                .take(SUMMARY_ANSWER_SAMPLE_LIMIT)
                .map(|v| match v {
                    Value::Timestamp(t) => json!(t),
                    other => json!(other.to_string()),
                })
                .collect();
            obj.insert("answers".into(), json!(answers));
        }
    }

    summary
}

/// Counts picks per configured option (field options JSON `{"options": [..]}`),
/// preserving the configured order and zero-filling unpicked options. Picks
/// not matching any configured option fold into a trailing `"Other"` bucket.
fn choice_counts(options: &JsonValue, picks: impl Iterator<Item = String>) -> JsonValue {
    let configured: Vec<String> = options
        .get("options")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut counts: Vec<(String, usize)> = configured.iter().map(|o| (o.clone(), 0)).collect();
    let mut other = 0;
    for pick in picks {
        match counts.iter_mut().find(|(option, _)| option == &pick) {
            Some((_, count)) => *count += 1,
            None => other += 1,
        }
    }
    if other > 0 {
        counts.push(("Other".to_string(), other));
    }

    json!(counts
        .into_iter()
        .map(|(option, count)| json!([option, count]))
        .collect::<Vec<_>>())
}

fn as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Float(f) => Some(*f),
        Value::Integer(i) => Some(*i as f64),
        Value::Timestamp(t) => Some(*t as f64),
        _ => None,
    }
}

/// Bins `values` into a histogram with a "nice" bin width (1·2·5×10ⁿ) and
/// edges aligned to multiples of that width. Returns `(bins, min, max, mean)`
/// as JSON-ready values, or `None` when there is nothing to bin.
fn histogram(values: &[f64]) -> Option<(JsonValue, f64, f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let mean = values.iter().sum::<f64>() / values.len() as f64;

    // All values identical: one bin holding everything.
    if min == max {
        let bins = json!([{ "min": min, "max": max, "count": values.len() }]);
        return Some((bins, min, max, mean));
    }

    let width = nice_bin_width((max - min) / SUMMARY_HISTOGRAM_TARGET_BINS as f64);
    let start = (min / width).floor() * width;
    let bin_count = (((max - start) / width).ceil() as usize).max(1);

    let mut counts = vec![0usize; bin_count];
    for &v in values {
        // The top edge is inclusive so `max` itself doesn't fall off the end.
        let idx = (((v - start) / width).floor() as usize).min(bin_count - 1);
        counts[idx] += 1;
    }

    let bins: Vec<JsonValue> = counts
        .iter()
        .enumerate()
        .map(|(i, count)| {
            json!({
                "min": round_clean(start + i as f64 * width),
                "max": round_clean(start + (i + 1) as f64 * width),
                "count": count,
            })
        })
        .collect();

    Some((json!(bins), min, max, mean))
}

/// Smallest 1·2·5×10ⁿ value ≥ `raw`.
fn nice_bin_width(raw: f64) -> f64 {
    let magnitude = 10f64.powf(raw.log10().floor());
    for multiplier in [1.0, 2.0, 5.0, 10.0] {
        if magnitude * multiplier >= raw {
            return magnitude * multiplier;
        }
    }
    magnitude * 10.0
}

/// Rounds away float noise from repeated width additions (e.g. 0.30000000000000004).
fn round_clean(x: f64) -> f64 {
    (x * 1e9).round() / 1e9
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
    if let Ok(existing) = form.get(atomic_lib::urls::FORM_PUBLISH_ID) {
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
        atomic_lib::urls::FORM_PUBLISH_ID.into(),
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
    use atomic_lib::{test_utils::init_store, urls};
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

        let mut field = Resource::new_instance(urls::FORM_FIELD, store)
            .await
            .unwrap();
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

        let mut page = Resource::new_instance(urls::FORM_PAGE, store)
            .await
            .unwrap();
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
    async fn definition_includes_styling() {
        let store = init_store().await;
        let (mut form, _email_prop) = build_test_form(&store).await;

        // Defaults: no styling props set.
        let definition = build_form_definition(&store, &form).await.unwrap();
        assert!(!definition.styling.has_image);
        assert!(definition.styling.main_color.is_none());
        // Wire format hides the empty fields entirely.
        let wire = serde_json::to_value(&definition).unwrap();
        assert_eq!(wire["styling"], json!({}));

        form.set(
            urls::FORM_STYLING.into(),
            Value::Json(json!({
                "textColor": "#112233",
                "mainColor": "#445566",
                "backgroundColor": "#778899",
                "roundness": "round",
            })),
            &store,
        )
        .await
        .unwrap();
        form.set(
            urls::IMAGE_POSITION.into(),
            Value::String("behind".into()),
            &store,
        )
        .await
        .unwrap();
        // Any subject works; has_image only checks presence.
        form.set(
            urls::COVER_IMAGE.into(),
            Value::AtomicUrl("https://example.com/image".to_string().into()),
            &store,
        )
        .await
        .unwrap();
        form.save_locally(&store).await.unwrap();

        let styling = build_form_definition(&store, &form).await.unwrap().styling;
        assert!(styling.has_image);
        assert_eq!(styling.image_position.as_deref(), Some("behind"));
        assert_eq!(styling.text_color.as_deref(), Some("#112233"));
        assert_eq!(styling.main_color.as_deref(), Some("#445566"));
        assert_eq!(styling.background_color.as_deref(), Some("#778899"));
        assert_eq!(styling.roundness.as_deref(), Some("round"));
        // `has_image` never leaks into the wire format.
        let wire = serde_json::to_value(&styling).unwrap();
        assert!(wire.get("hasImage").is_none());
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
            styling: FormStyling::default(),
            honeypot_field: HONEYPOT_FIELD.into(),
            captcha: None,
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
            styling: FormStyling::default(),
            honeypot_field: HONEYPOT_FIELD.into(),
            captcha: None,
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

    fn field_summary(
        field_type: &str,
        options: JsonValue,
        values: &[Value],
        total: usize,
    ) -> JsonValue {
        let refs: Vec<&Value> = values.iter().collect();
        summarize_field(
            "https://example.com/p",
            "Q",
            field_type,
            &options,
            &refs,
            total,
        )
    }

    #[test]
    fn radio_counts_preserve_option_order_and_fold_unknown() {
        let values = vec![
            Value::String("B".into()),
            Value::String("A".into()),
            Value::String("B".into()),
            Value::String("stray".into()),
        ];
        let summary = field_summary("radio", json!({"options": ["A", "B", "C"]}), &values, 5);

        assert_eq!(summary["answered"], 4);
        assert_eq!(summary["skipped"], 1);
        assert_eq!(
            summary["counts"],
            json!([["A", 1], ["B", 2], ["C", 0], ["Other", 1]])
        );
    }

    #[test]
    fn multi_select_counts_iterate_json_arrays() {
        let values = vec![
            Value::Json(json!(["Red", "Green"])),
            Value::Json(json!(["Red"])),
        ];
        let summary = field_summary(
            "multi-select",
            json!({"options": ["Red", "Green", "Blue"]}),
            &values,
            2,
        );

        // Two responses, three total picks.
        assert_eq!(summary["answered"], 2);
        assert_eq!(
            summary["counts"],
            json!([["Red", 2], ["Green", 1], ["Blue", 0]])
        );
    }

    #[test]
    fn checkbox_counts_checked_and_unchecked() {
        let values = vec![
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Boolean(true),
        ];
        let summary = field_summary("checkbox", json!({}), &values, 4);

        assert_eq!(summary["checked"], 2);
        assert_eq!(summary["unchecked"], 1);
        assert_eq!(summary["skipped"], 1);
    }

    #[test]
    fn number_histogram_uses_nice_bins() {
        let values: Vec<Value> = [1.0, 3.0, 7.0, 12.0, 42.0]
            .iter()
            .map(|f| Value::Float(*f))
            .collect();
        let summary = field_summary("number", json!({}), &values, 5);

        assert_eq!(summary["min"], 1.0);
        assert_eq!(summary["max"], 42.0);
        assert_eq!(summary["mean"], 13.0);

        let bins = summary["bins"].as_array().unwrap();
        // (42-1)/9 ≈ 4.6 → nice width 5, start 0 → bins 0..45.
        assert_eq!(bins[0]["min"], 0.0);
        assert_eq!(bins[0]["max"], 5.0);
        assert_eq!(bins.len(), 9);
        // Every value lands in exactly one bin.
        let total: u64 = bins.iter().map(|b| b["count"].as_u64().unwrap()).sum();
        assert_eq!(total, 5);
        // 42 (the max) is inside the last bin, not dropped off the top edge.
        assert_eq!(bins[8]["count"], 1);
    }

    #[test]
    fn number_histogram_single_value_degenerates_to_one_bin() {
        let values = vec![Value::Float(3.5), Value::Float(3.5)];
        let summary = field_summary("number", json!({}), &values, 2);

        assert_eq!(
            summary["bins"],
            json!([{"min": 3.5, "max": 3.5, "count": 2}])
        );
    }

    #[test]
    fn text_answers_are_sampled_and_capped() {
        let values: Vec<Value> = (0..150)
            .map(|i| Value::String(format!("answer {i}")))
            .collect();
        let summary = field_summary("short-text", json!({}), &values, 150);

        assert_eq!(summary["answered"], 150);
        assert_eq!(summary["answers"].as_array().unwrap().len(), 100);
        assert_eq!(summary["answers"][0], "answer 0");
    }

    #[test]
    fn datetime_answers_stay_numeric() {
        let values = vec![Value::Timestamp(1700000000000)];
        let summary = field_summary("datetime", json!({}), &values, 1);

        assert_eq!(summary["answers"], json!([1700000000000i64]));
    }

    #[tokio::test]
    async fn builds_summary_from_stored_rows() {
        let store = init_store().await;
        let (form, email_prop) = build_test_form(&store).await;

        let table_subject = form.get(urls::FORM_TARGET_TABLE).unwrap().to_string();
        let data_class = form.get(urls::FORM_DATA_CLASS).unwrap().to_string();

        for i in 0..2 {
            let mut row = Resource::new_instance(&data_class, &store).await.unwrap();
            row.set(
                urls::PARENT.into(),
                Value::AtomicUrl(table_subject.clone().into()),
                &store,
            )
            .await
            .unwrap();
            row.set(
                email_prop.clone(),
                Value::String(format!("visitor{i}@example.com")),
                &store,
            )
            .await
            .unwrap();
            row.save_locally(&store).await.unwrap();
        }

        let summary = build_form_summary(&store, &form, &ForAgent::Sudo)
            .await
            .unwrap();

        assert_eq!(summary["responses"], 2);
        let fields = summary["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0]["mapsTo"], email_prop);
        assert_eq!(fields[0]["type"], "email");
        assert_eq!(fields[0]["answered"], 2);
        assert_eq!(fields[0]["answers"].as_array().unwrap().len(), 2);
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
