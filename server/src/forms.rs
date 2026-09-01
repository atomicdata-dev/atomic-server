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
    /// Vertical space between the blocks of a page (`small` / `large`).
    /// `None` keeps the renderer's default (`small`, 1.5rem).
    #[serde(rename = "fieldSpacing", skip_serializing_if = "Option::is_none")]
    pub field_spacing: Option<String>,
    /// Multi-page progress bar visibility. `None` means unset (shown by
    /// default); the runtime and preview both treat only `Some(false)` as
    /// hiding it.
    #[serde(rename = "showProgressBar", skip_serializing_if = "Option::is_none")]
    pub show_progress_bar: Option<bool>,
    /// Whether Next/Back page changes animate. Opt-in, unlike
    /// [FormStyling::show_progress_bar]: only `Some(true)` animates, so a
    /// form that predates the setting keeps its instant page changes. A
    /// visitor's `prefers-reduced-motion` overrides it in the runtime
    /// regardless.
    #[serde(
        rename = "animatePageTransitions",
        skip_serializing_if = "Option::is_none"
    )]
    pub animate_page_transitions: Option<bool>,
    /// Whether the runtime keeps a half-filled form in the visitor's
    /// `localStorage` (see `@tomic/form-renderer`'s `draft.ts`). `None` means
    /// unset — drafts are on by default; only `Some(false)` opts out, for
    /// kiosks and other shared devices.
    #[serde(rename = "saveDrafts", skip_serializing_if = "Option::is_none")]
    pub save_drafts: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormPageDefinition {
    pub name: Option<String>,
    #[serde(rename = "coverImage")]
    pub cover_image: Option<String>,
    #[serde(rename = "imagePosition")]
    pub image_position: Option<String>,
    /// AND-ed visibility predicates. Empty (or omitted) means always shown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<FormConditionDef>,
    pub blocks: Vec<FormBlock>,
}

/// Denormalized visibility predicate. `field` is the referenced question's
/// `mapsTo` (property subject), not the FormField resource URL. Mirrors
/// `FormCondition` in `@tomic/form-renderer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormConditionDef {
    pub field: String,
    pub operator: String,
    pub value: JsonValue,
}

/// The styles a `FormInfoBox` may carry. Mirrors `INFO_BOX_STYLES` in
/// `@tomic/form-renderer`; anything else falls back to
/// [DEFAULT_INFO_BOX_STYLE], since `form-info-box-style` is a plain String at
/// the store (same limitation as `form-field-type`).
pub const INFO_BOX_STYLES: [&str; 6] = ["info", "note", "tip", "success", "warning", "danger"];

pub const DEFAULT_INFO_BOX_STYLE: &str = "info";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormBlock {
    Heading {
        text: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        conditions: Vec<FormConditionDef>,
    },
    Paragraph {
        text: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        conditions: Vec<FormConditionDef>,
    },
    /// A callout box: markdown `text`, an optional `title` line above it, and
    /// a `style` picked from [INFO_BOX_STYLES]. `kind` is spelled kebab-case
    /// (not serde's default `info_box`) to match the builder's field-type ids.
    #[serde(rename = "info-box")]
    InfoBox {
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        text: String,
        style: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        conditions: Vec<FormConditionDef>,
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
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        conditions: Vec<FormConditionDef>,
    },
}

impl FormBlock {
    pub fn conditions(&self) -> &[FormConditionDef] {
        match self {
            Self::Heading { conditions, .. }
            | Self::Paragraph { conditions, .. }
            | Self::InfoBox { conditions, .. }
            | Self::Field { conditions, .. } => conditions,
        }
    }
}

/// Walk the definition in document order and decide what's shown.
/// A referenced field that is itself hidden (or unanswered) fails the
/// condition, so later questions cannot be unlocked by submitting a
/// value for a hidden predecessor. AND semantics; empty list = visible.
#[derive(Debug, Clone)]
pub struct FormVisibility {
    /// `mapsTo` of every visible input field, in document order.
    pub fields: Vec<String>,
    /// Indices of pages whose own conditions match.
    pub page_indices: Vec<usize>,
    /// Per page, which block indices are visible (page-hidden → empty).
    /// Used by the TS renderer; kept here so the two visibility structs match.
    #[allow(dead_code)]
    pub blocks: Vec<HashSet<usize>>,
}

/// Whether an answer counts as "not given". Mirrored by `isEmptyValue` in
/// `browser/form-renderer/src/conditions.ts` — an array or object whose
/// entries are all themselves empty (e.g. an untouched `table-input` grid or
/// a blank `address`) counts as unanswered, not as a partial answer.
fn json_is_empty(value: Option<&JsonValue>) -> bool {
    match value {
        None | Some(JsonValue::Null) => true,
        Some(JsonValue::String(s)) => s.is_empty(),
        Some(JsonValue::Array(a)) => a.iter().all(|v| json_is_empty(Some(v))),
        Some(JsonValue::Object(o)) => o.values().all(|v| json_is_empty(Some(v))),
        _ => false,
    }
}

fn json_as_number(value: &JsonValue) -> Option<f64> {
    match value {
        JsonValue::Number(n) => n.as_f64(),
        JsonValue::String(s) if !s.is_empty() => s.parse().ok(),
        _ => None,
    }
}

fn json_as_str(value: &JsonValue) -> String {
    match value {
        JsonValue::String(s) => s.clone(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// Numeric equality when both sides look like numbers; otherwise JSON Eq.
pub fn json_equal(a: &JsonValue, b: &JsonValue) -> bool {
    if let (Some(na), Some(nb)) = (json_as_number(a), json_as_number(b)) {
        return na == nb;
    }
    a == b
}

fn json_contains(answer: &JsonValue, expected: &JsonValue) -> bool {
    match answer {
        JsonValue::String(s) => s
            .to_lowercase()
            .contains(&json_as_str(expected).to_lowercase()),
        JsonValue::Array(arr) => arr.iter().any(|item| json_equal(item, expected)),
        _ => false,
    }
}

fn json_compare(answer: &JsonValue, expected: &JsonValue) -> Option<std::cmp::Ordering> {
    if let (Some(na), Some(nb)) = (json_as_number(answer), json_as_number(expected)) {
        return na.partial_cmp(&nb);
    }
    if let (JsonValue::String(a), JsonValue::String(b)) = (answer, expected) {
        return Some(a.cmp(b));
    }
    None
}

/// A single predicate. Unanswered / hidden referenced fields fail
/// (the dependent stays hidden). Unknown operators fail closed.
pub fn evaluate_condition(condition: &FormConditionDef, answer: Option<&JsonValue>) -> bool {
    if json_is_empty(answer) {
        return false;
    }
    let answer = answer.expect("checked non-empty above");
    match condition.operator.as_str() {
        "equals" => json_equal(answer, &condition.value),
        "not-equals" => !json_equal(answer, &condition.value),
        "contains" => json_contains(answer, &condition.value),
        "greater-than" => matches!(
            json_compare(answer, &condition.value),
            Some(std::cmp::Ordering::Greater)
        ),
        "less-than" => matches!(
            json_compare(answer, &condition.value),
            Some(std::cmp::Ordering::Less)
        ),
        _ => false,
    }
}

fn conditions_match(
    conditions: &[FormConditionDef],
    values: &Map<String, JsonValue>,
    visible_fields: &[String],
) -> bool {
    if conditions.is_empty() {
        return true;
    }
    conditions.iter().all(|condition| {
        let answer = if !condition.field.is_empty()
            && visible_fields.iter().any(|f| f == &condition.field)
        {
            values.get(&condition.field)
        } else {
            None
        };
        evaluate_condition(condition, answer)
    })
}

pub fn compute_visibility(
    definition: &FormDefinition,
    values: &Map<String, JsonValue>,
) -> FormVisibility {
    let mut fields = Vec::new();
    let mut page_indices = Vec::new();
    let mut blocks = Vec::new();

    for (p, page) in definition.pages.iter().enumerate() {
        let mut visible_blocks = HashSet::new();
        if !conditions_match(&page.conditions, values, &fields) {
            blocks.push(visible_blocks);
            continue;
        }
        page_indices.push(p);
        for (b, block) in page.blocks.iter().enumerate() {
            if !conditions_match(block.conditions(), values, &fields) {
                continue;
            }
            visible_blocks.insert(b);
            if let FormBlock::Field { maps_to, .. } = block {
                fields.push(maps_to.clone());
            }
        }
        blocks.push(visible_blocks);
    }

    FormVisibility {
        fields,
        page_indices,
        blocks,
    }
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

/// `form-field-options` key holding a choice question's resolved options.
pub const OPTIONS_KEY: &str = "options";

/// The question types whose options are Tag resources listed on the mapped
/// Property's `allowsOnly`. Mirrored by `CHOICE_FIELD_TYPES` in
/// `chunks/FormBuilder/fieldTypes.ts`.
pub const CHOICE_FIELD_TYPES: [&str; 5] = [
    "radio",
    "multi-select",
    "dropdown",
    "dropdown-multi",
    "picture-choice",
];

/// The choice types that accept exactly one option. The mapped Property is a
/// SelectProperty either way (always a `resourceArray`, as everywhere else in
/// the app); single-pick is expressed as `max: 1` and stores a one-element
/// array.
const SINGLE_CHOICE_FIELD_TYPES: [&str; 3] = ["radio", "dropdown", "picture-choice"];

pub fn is_choice_field(field_type: &str) -> bool {
    CHOICE_FIELD_TYPES.contains(&field_type)
}

/// One resolved choice option on the wire. Mirrors `FieldOption` in
/// `@tomic/form-renderer` (keep in lockstep, no codegen — same convention as
/// [FormDefinition]). `value` is the Tag's subject: what a submission stores
/// and what conditions compare against. Everything user-facing renders
/// `label`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldOption {
    pub value: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
    /// `picture-choice`: the Tag's `cover-image`. A File subject in the store
    /// and a URL on the wire — see [rewrite_option_images].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

fn option_str<'a>(option: &'a JsonValue, key: &str) -> Option<&'a str> {
    option.get(key).and_then(|v| v.as_str())
}

/// The resolved options of a choice question, as stored in its options bag.
fn options_list(options: &JsonValue) -> &[JsonValue] {
    options
        .get(OPTIONS_KEY)
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// `form-field-options` key describing where a choice question's options come
/// from, when they are not its own column's Tags. Mirrors `OptionsSource` in
/// `chunks/FormBuilder/FieldOptions/optionsSource.ts`. Two shapes:
///
/// - `{ "property": <SelectProperty subject> }` — the options are another
///   column's Tags. The builder mirrors those Tags onto the field's own
///   Property too, so the response column keeps working standalone.
/// - `{ "table": <Table subject>, "labelProperty": <Property subject> }` —
///   the options are the table's *rows*, resolved on every definition read.
///
/// `table` is also stored alongside `property` (the builder picks a table
/// first); resolution ignores it in that case.
pub const OPTIONS_SOURCE_KEY: &str = "optionsSource";

/// Cap on how many rows a table-sourced question turns into options. Smaller
/// than [SUMMARY_ROW_LIMIT] deliberately: a summary is read once per results
/// view, while this list is inlined into the form HTML on *every* page load,
/// and a picker of more than a thousand entries is not a usable control
/// anyway. Rows past the cap are not offered and would be rejected by
/// [check_membership].
const OPTIONS_ROW_LIMIT: usize = 1_000;

fn source_str<'a>(options: &'a JsonValue, key: &str) -> Option<&'a str> {
    options
        .get(OPTIONS_SOURCE_KEY)
        .and_then(|source| source.get(key))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// Resolves a choice question's options and writes them into the options bag.
/// A published form's visitor has no agent and so cannot fetch the underlying
/// resources itself — this is the same denormalization
/// [rewrite_option_images] does for Files.
///
/// Where the list comes from is [OPTIONS_SOURCE_KEY]'s business; by default it
/// is the Tags on the field's own mapped Property's `allowsOnly`.
///
/// A non-choice field, an unreadable Property/Table, or an empty list all
/// leave an empty list, which [check_membership] treats as "nothing is
/// allowed" rather than "everything is".
async fn resolve_choice_options(
    store: &impl Storelike,
    field_type: &str,
    maps_to: &str,
    options: &mut JsonValue,
) {
    if !is_choice_field(field_type) {
        return;
    }

    let resolved = if let Some(property) = source_str(options, "property") {
        tag_options(store, property).await
    } else if let Some(table) = source_str(options, "table") {
        row_options(store, table, source_str(options, "labelProperty")).await
    } else {
        tag_options(store, maps_to).await
    };

    match options.as_object_mut() {
        Some(obj) => {
            obj.insert(OPTIONS_KEY.into(), json!(resolved));
        }
        None => *options = json!({ OPTIONS_KEY: resolved }),
    }
}

/// Reads a resource's property as a non-empty string, or `None`.
fn option_prop(resource: &Resource, prop: &str) -> Option<String> {
    resource
        .get(prop)
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty())
}

/// The Tags on `property_subject`'s `allowsOnly`, as options. An unreadable
/// Property or an empty `allowsOnly` yields an empty list.
async fn tag_options(store: &impl Storelike, property_subject: &str) -> Vec<FieldOption> {
    let mut resolved: Vec<FieldOption> = Vec::new();

    let Ok(property) = store
        .get_resource(&property_subject.to_string().into())
        .await
    else {
        return resolved;
    };

    let tag_subjects = property
        .get(atomic_lib::urls::ALLOWS_ONLY)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    for subject in tag_subjects {
        let Ok(tag) = store.get_resource(&subject.clone().into()).await else {
            continue;
        };
        resolved.push(FieldOption {
            // `name` is the free-text label; `shortname` is the slug every
            // Tag is required to have. Same precedence as `useTitle`.
            label: option_prop(&tag, atomic_lib::urls::NAME)
                .or_else(|| option_prop(&tag, atomic_lib::urls::SHORTNAME))
                .unwrap_or_else(|| subject.clone()),
            color: option_prop(&tag, atomic_lib::urls::COLOR),
            emoji: option_prop(&tag, atomic_lib::urls::EMOJI),
            image: option_prop(&tag, atomic_lib::urls::COVER_IMAGE),
            value: subject,
        });
    }

    resolved
}

/// The rows of `table_subject`, as options: `value` is the row's subject, so
/// an answer becomes a reference to the row rather than a copy of its label.
///
/// Same row query as [build_form_summary] (`parent` = table, `isA` = the
/// table's `classtype`), capped at [OPTIONS_ROW_LIMIT]. Runs as
/// [ForAgent::Sudo]: the caller is building a definition for an agent-less
/// visitor, and publishing these labels is the deliberate tradeoff of linking
/// a question to a table (the builder says so when you pick one).
async fn row_options(
    store: &impl Storelike,
    table_subject: &str,
    label_property: Option<&str>,
) -> Vec<FieldOption> {
    let Ok(table) = store.get_resource(&table_subject.to_string().into()).await else {
        return Vec::new();
    };
    let Some(row_class) = option_prop(&table, atomic_lib::urls::CLASSTYPE_PROP) else {
        return Vec::new();
    };

    let query = Query {
        property: Some(atomic_lib::urls::PARENT.into()),
        value: Some(Value::AtomicUrl(table_subject.to_string().into())),
        filters: vec![PropVal {
            property: Some(atomic_lib::urls::IS_A.into()),
            value: Some(Value::AtomicUrl(row_class.into())),
            operator: FilterOperator::Equal,
        }],
        limit: Some(OPTIONS_ROW_LIMIT),
        for_agent: ForAgent::Sudo,
        drive: Some(
            table
                .get_drive()
                .unwrap_or_else(|| drive_prefix_from_subject(table.get_subject())),
        ),
        ..Query::new()
    };

    let Ok(QueryResult {
        resources: rows, ..
    }) = store.query(&query).await
    else {
        return Vec::new();
    };

    rows.iter()
        .filter_map(|row| {
            let subject = row.get_subject().to_string();
            let label = match label_property {
                Some(prop) => row_label(row, prop)?,
                // No label column named: fall back to how the row titles
                // itself, the same precedence `useTitle` uses.
                None => option_prop(row, atomic_lib::urls::NAME)
                    .or_else(|| option_prop(row, atomic_lib::urls::SHORTNAME))
                    .unwrap_or_else(|| subject.clone()),
            };
            Some(FieldOption {
                label,
                color: option_prop(row, atomic_lib::urls::COLOR),
                emoji: option_prop(row, atomic_lib::urls::EMOJI),
                image: option_prop(row, atomic_lib::urls::COVER_IMAGE),
                value: subject,
            })
        })
        .collect()
}

/// A row's label for a table-sourced option: whatever the picked column holds,
/// as one line of text.
///
/// `None` means the row is **not offered at all**, which is the point: falling
/// back to the row's own name would put a different column's text in the list
/// for exactly the rows the picked column is empty for, and an option labelled
/// from somewhere else is worse than no option.
///
/// Composite values count as absent for the same reason — a relation, a nested
/// resource or a JSON blob has no one-line rendering, only a debug one.
/// Mirrored by `rowLabel` in `chunks/FormBuilder/buildFormDefinition.ts`.
fn row_label(row: &Resource, label_property: &str) -> Option<String> {
    match row.get(label_property).ok()? {
        Value::ResourceArray(_)
        | Value::NestedResource(_)
        | Value::Json(_)
        | Value::LoroDoc(_)
        | Value::LocalizedText(_) => None,
        value => Some(value.to_string()).filter(|s| !s.trim().is_empty()),
    }
}

/// Turns every `picture-choice` option image from a File subject into
/// something an agent-less visitor can fetch. Same split as
/// `FormStyling::image_url`: [build_form_definition] stays id-agnostic and
/// the caller owns URL construction (the HTTP handlers point at
/// `/form/{id}/image?file=…`, the data-browser preview at the File's own
/// `downloadURL`). Entries that aren't subjects are left alone.
pub fn rewrite_option_images(definition: &mut FormDefinition, to_url: impl Fn(&str) -> String) {
    for page in definition.pages.iter_mut() {
        for block in page.blocks.iter_mut() {
            let FormBlock::Field { options, .. } = block else {
                continue;
            };
            let Some(list) = options.get_mut(OPTIONS_KEY).and_then(|v| v.as_array_mut()) else {
                continue;
            };
            for option in list.iter_mut() {
                let Some(subject) = option_str(option, "image")
                    .filter(|s| !s.is_empty())
                    .map(&to_url)
                else {
                    continue;
                };
                if let Some(obj) = option.as_object_mut() {
                    obj.insert("image".into(), JsonValue::String(subject));
                }
            }
        }
    }
}

/// Every File subject this form is allowed to serve anonymously through
/// `GET /form/{id}/image?file=…`, i.e. the images its `picture-choice`
/// questions reference. Gating on this set is what keeps that route from
/// becoming a proxy for any file the server agent can read. (The form's own
/// `cover-image` is served by the same route *without* a `file` param, so it
/// doesn't need to be listed here.)
pub async fn collect_option_image_subjects(
    store: &impl Storelike,
    form: &Resource,
) -> AtomicResult<HashSet<String>> {
    let mut subjects = HashSet::new();

    let page_subjects = form
        .get(atomic_lib::urls::FORM_PAGES)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    for page_subject in page_subjects {
        let Ok(page) = store.get_resource(&page_subject.into()).await else {
            continue;
        };
        let field_subjects = page
            .get(atomic_lib::urls::FORM_FIELDS)
            .and_then(|v| v.to_subjects(None))
            .unwrap_or_default();

        for field_subject in field_subjects {
            let Ok(field) = store.get_resource(&field_subject.into()).await else {
                continue;
            };
            // Option images live on the Tags, so the walk goes through the
            // mapped Property's `allowsOnly` rather than the options bag.
            let Ok(maps_to) = field.get(atomic_lib::urls::FORM_MAPS_TO) else {
                continue;
            };
            let Ok(property) = store.get_resource(&maps_to.to_string().into()).await else {
                continue;
            };
            let tag_subjects = property
                .get(atomic_lib::urls::ALLOWS_ONLY)
                .and_then(|v| v.to_subjects(None))
                .unwrap_or_default();

            for tag_subject in tag_subjects {
                let Ok(tag) = store.get_resource(&tag_subject.into()).await else {
                    continue;
                };
                if let Ok(image) = tag.get(atomic_lib::urls::COVER_IMAGE) {
                    let image = image.to_string();
                    if !image.is_empty() {
                        subjects.insert(image);
                    }
                }
            }
        }
    }

    Ok(subjects)
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
    let get_bool = |key: &str| styling_json.get(key).and_then(|v| v.as_bool());

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
        field_spacing: get_str("fieldSpacing"),
        show_progress_bar: get_bool("showProgressBar"),
        animate_page_transitions: get_bool("animatePageTransitions"),
        save_drafts: get_bool("saveDrafts"),
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
        blocks.push(build_block(store, &field).await?);
    }

    Ok(FormPageDefinition {
        name,
        cover_image,
        image_position,
        conditions: build_conditions(store, page).await,
        blocks,
    })
}

async fn build_conditions(store: &impl Storelike, resource: &Resource) -> Vec<FormConditionDef> {
    let subjects = resource
        .get(atomic_lib::urls::FORM_CONDITIONS)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();
    let mut out = Vec::with_capacity(subjects.len());
    for subject in subjects {
        let Ok(cond) = store.get_resource(&subject.into()).await else {
            continue;
        };
        let field_subject = cond
            .get(atomic_lib::urls::FORM_CONDITION_FIELD)
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_default();
        let maps_to = if field_subject.is_empty() {
            String::new()
        } else {
            match store.get_resource(&field_subject.into()).await {
                Ok(field) => field
                    .get(atomic_lib::urls::FORM_MAPS_TO)
                    .ok()
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                Err(_) => String::new(),
            }
        };
        let operator = cond
            .get(atomic_lib::urls::FORM_CONDITION_OPERATOR)
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "equals".into());
        let value = match cond.get(atomic_lib::urls::FORM_CONDITION_VALUE) {
            Ok(Value::Json(v)) => v.clone(),
            Ok(Value::String(s)) => serde_json::from_str(s).unwrap_or_else(|_| json!(s)),
            Ok(other) => json!(other.to_string()),
            Err(_) => JsonValue::Null,
        };
        out.push(FormConditionDef {
            field: maps_to,
            operator,
            value,
        });
    }
    out
}

async fn build_block(store: &impl Storelike, field: &Resource) -> AtomicResult<FormBlock> {
    let conditions = build_conditions(store, field).await;
    let classes = field
        .get(atomic_lib::urls::IS_A)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();

    if classes.iter().any(|c| c == atomic_lib::urls::FORM_HEADING) {
        let text = field.get(atomic_lib::urls::NAME)?.to_string();
        return Ok(FormBlock::Heading { text, conditions });
    }
    if classes
        .iter()
        .any(|c| c == atomic_lib::urls::FORM_PARAGRAPH)
    {
        let text = field.get(atomic_lib::urls::DESCRIPTION)?.to_string();
        return Ok(FormBlock::Paragraph { text, conditions });
    }
    if classes.iter().any(|c| c == atomic_lib::urls::FORM_INFO_BOX) {
        let text = field.get(atomic_lib::urls::DESCRIPTION)?.to_string();
        // A title is optional — an untitled box is just a styled paragraph.
        let title = field
            .get(atomic_lib::urls::NAME)
            .ok()
            .map(|v| v.to_string())
            .filter(|t| !t.is_empty());
        let style = field
            .get(atomic_lib::urls::FORM_INFO_BOX_STYLE)
            .ok()
            .map(|v| v.to_string())
            .filter(|s| INFO_BOX_STYLES.contains(&s.as_str()))
            .unwrap_or_else(|| DEFAULT_INFO_BOX_STYLE.to_string());
        return Ok(FormBlock::InfoBox {
            title,
            text,
            style,
            conditions,
        });
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
        let mut options = match field.get(atomic_lib::urls::FORM_FIELD_OPTIONS) {
            Ok(Value::Json(v)) => v.clone(),
            // Same fallback as `build_form_styling`: a JSON value written
            // while its Property was unresolvable materializes as the raw
            // serialized string.
            Ok(Value::String(s)) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
            _ => json!({}),
        };
        resolve_choice_options(store, &field_type, &maps_to, &mut options).await;
        return Ok(FormBlock::Field {
            maps_to,
            label,
            description,
            field_type,
            required,
            options,
            conditions,
        });
    }

    Err(format!(
        "Resource {} is not a recognized form block (expected FormField, FormHeading, FormParagraph or FormInfoBox)",
        field.get_subject()
    )
    .into())
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Validates a submitted `values` map against a form's *visible* field
/// blocks (required-ness, datatype shape, numeric bounds, option
/// membership) and coerces accepted values into `atomic_lib::Value`s ready
/// for `resource.set()`. Hidden fields (conditions not matching) are
/// skipped: required-on-hidden is not an error, and submitted values for
/// them are dropped rather than stored. Collects every error rather than
/// failing fast. Unknown keys in `values` (not matching any field's
/// `mapsTo`) are also reported as errors.
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

    let visibility = compute_visibility(definition, values);

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
        if !visibility.fields.iter().any(|f| f == maps_to) {
            continue;
        }

        let raw = values.get(maps_to);

        if json_is_empty(raw) {
            if required {
                errors.push(ValidationError {
                    field: maps_to.clone(),
                    message: "This field is required".into(),
                });
            }
            continue;
        }

        match coerce_value(
            field_type,
            options,
            required,
            raw.expect("checked non-empty above"),
        ) {
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

/// Validates one non-empty answer and converts it into the `Value` the
/// mapped Property expects. `required` only matters for composite types
/// (`choice-matrix`, `address`), where "answered" is per-subfield — plain
/// requiredness of the whole field is handled by the caller.
fn coerce_value(
    field_type: &str,
    options: &JsonValue,
    required: bool,
    raw: &JsonValue,
) -> Result<Value, String> {
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
            check_bounds(f, options)?;
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
        "multi-select" | "dropdown-multi" => {
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
            check_selection_count(items.len(), options)?;
            Ok(items.into())
        }
        "phone" => {
            let s = raw.as_str().ok_or("Expected a string")?.to_string();
            if !is_valid_phone(s.trim()) {
                return Err("Not a valid phone number".into());
            }
            Ok(Value::String(s))
        }
        "country" => {
            let c = raw.as_str().ok_or("Expected a string")?.trim().to_string();
            if !is_valid_country(&c) {
                return Err("Not a valid country".into());
            }
            Ok(Value::String(c))
        }
        "url" => {
            let s = raw.as_str().ok_or("Expected a string")?.to_string();
            if !is_valid_url(s.trim()) {
                return Err("Not a valid URL (must start with http:// or https://)".into());
            }
            Ok(Value::String(s))
        }
        "currency" => {
            let f = raw.as_f64().ok_or("Expected a number")?;
            check_bounds(f, options)?;
            Ok(Value::Float(f))
        }
        // Single-pick choice questions. The answer travels as one subject
        // string and is stored as a one-element resourceArray, so the mapped
        // column is an ordinary SelectProperty like any other.
        t if SINGLE_CHOICE_FIELD_TYPES.contains(&t) => {
            let s = raw.as_str().ok_or("Expected a string")?.to_string();
            check_membership(std::slice::from_ref(&s), options)?;
            Ok(vec![s].into())
        }
        "likert" => Ok(Value::Integer(check_step(
            raw,
            likert_scale(options),
            "Answer",
        )?)),
        "rating" => Ok(Value::Integer(check_step(
            raw,
            rating_max(options),
            "Rating",
        )?)),
        "choice-matrix" => {
            let answers = raw.as_object().ok_or("Expected an object of row answers")?;
            let rows = string_list(options, "rows");
            let columns = matrix_columns(options);

            for (row, answer) in answers {
                if !rows.contains(row) {
                    return Err(format!("'{row}' is not one of the rows"));
                }
                if json_is_empty(Some(answer)) {
                    continue;
                }
                let picked = answer.as_str().unwrap_or_default();
                if !columns.iter().any(|c| c == picked) {
                    return Err(format!(
                        "'{}' is not one of the allowed options",
                        json_as_str(answer)
                    ));
                }
            }

            if required && rows.iter().any(|row| json_is_empty(answers.get(row))) {
                return Err("Please answer every row".into());
            }

            Ok(Value::Json(raw.clone()))
        }
        "table-input" => {
            let rows = raw.as_array().ok_or("Expected a list of rows")?;
            let columns = table_columns(options);

            for row in rows {
                let cells = row.as_object().ok_or("Expected a list of rows")?;
                for (key, cell) in cells {
                    let Some((_, column_type)) = columns.iter().find(|(label, _)| label == key)
                    else {
                        return Err(format!("'{key}' is not one of the columns"));
                    };
                    if json_is_empty(Some(cell)) {
                        continue;
                    }
                    if column_type == "number" {
                        if cell.as_f64().is_none() {
                            return Err(format!("'{key}' must be a number"));
                        }
                    } else if !cell.is_string() {
                        return Err(format!("'{key}' must be text"));
                    }
                }
            }

            let filled = rows.iter().filter(|row| !json_is_empty(Some(row))).count();
            if let Some(min) = options.get("minRows").and_then(|v| v.as_u64()) {
                if (filled as u64) < min {
                    return Err(format!("Please fill in at least {min} row(s)"));
                }
            }
            if let Some(max) = options.get("maxRows").and_then(|v| v.as_u64()) {
                if (filled as u64) > max {
                    return Err(format!("At most {max} row(s) allowed"));
                }
            }

            Ok(Value::Json(raw.clone()))
        }
        "address" => {
            let address = raw.as_object().ok_or("Expected an address object")?;

            for (key, value) in address {
                let Some((_, label)) = ADDRESS_FIELDS.iter().find(|(k, _)| k == key) else {
                    return Err(format!("'{key}' is not part of an address"));
                };
                if !json_is_empty(Some(value)) && !value.is_string() {
                    return Err(format!("'{label}' must be text"));
                }
            }

            if required {
                for key in ADDRESS_REQUIRED_FIELDS {
                    if json_is_empty(address.get(*key)) {
                        let label = ADDRESS_FIELDS
                            .iter()
                            .find(|(k, _)| k == key)
                            .map(|(_, label)| *label)
                            .unwrap_or(key);
                        return Err(format!("{label} is required"));
                    }
                }
            }

            Ok(Value::Json(raw.clone()))
        }
        other => Err(format!("Unknown field type: {other}")),
    }
}

/// The `address` subfields, in render order. Mirrors `ADDRESS_FIELDS` in
/// `browser/form-renderer/src/types.ts` (key, human label).
const ADDRESS_FIELDS: [(&str, &str); 6] = [
    ("line1", "Address"),
    ("line2", "Address line 2"),
    ("postalCode", "Postal code"),
    ("city", "City"),
    ("state", "State / Province"),
    ("country", "Country"),
];

/// Subfields that must be filled when an `address` field is required.
const ADDRESS_REQUIRED_FIELDS: &[&str] = &["line1", "city", "country"];

/// Default number of points on a `likert` scale / steps in a `rating`.
const DEFAULT_LIKERT_SCALE: i64 = 5;
const DEFAULT_RATING_MAX: i64 = 5;

fn bounded_option(options: &JsonValue, key: &str, min: i64, max: i64, fallback: i64) -> i64 {
    options
        .get(key)
        .and_then(|v| v.as_i64())
        .filter(|n| *n >= min && *n <= max)
        .unwrap_or(fallback)
}

fn likert_scale(options: &JsonValue) -> i64 {
    bounded_option(options, "scale", 2, 11, DEFAULT_LIKERT_SCALE)
}

fn rating_max(options: &JsonValue) -> i64 {
    bounded_option(options, "max", 2, 10, DEFAULT_RATING_MAX)
}

fn string_list(options: &JsonValue, key: &str) -> Vec<String> {
    options
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `choice-matrix` and `table-input` share the `columns` key: the former
/// stores plain labels, the latter `{label, type}` objects.
fn matrix_columns(options: &JsonValue) -> Vec<String> {
    options
        .get("columns")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| match v {
                    JsonValue::String(s) => Some(s.clone()),
                    JsonValue::Object(o) => {
                        o.get("label").and_then(|l| l.as_str()).map(str::to_string)
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn table_columns(options: &JsonValue) -> Vec<(String, String)> {
    options
        .get("columns")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| match v {
                    JsonValue::String(s) => Some((s.clone(), "text".to_string())),
                    JsonValue::Object(o) => o.get("label").and_then(|l| l.as_str()).map(|label| {
                        let column_type = o
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("text")
                            .to_string();
                        (label.to_string(), column_type)
                    }),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Integer answer within `1..=max` (likert / rating).
fn check_step(raw: &JsonValue, max: i64, what: &str) -> Result<i64, String> {
    let n = raw.as_i64().ok_or("Expected a whole number")?;
    if n < 1 || n > max {
        return Err(format!("{what} must be between 1 and {max}"));
    }
    Ok(n)
}

fn check_bounds(value: f64, options: &JsonValue) -> Result<(), String> {
    if let Some(min) = options.get("min").and_then(|v| v.as_f64()) {
        if value < min {
            return Err(format!("Must be at least {min}"));
        }
    }
    if let Some(max) = options.get("max").and_then(|v| v.as_f64()) {
        if value > max {
            return Err(format!("Must be at most {max}"));
        }
    }
    Ok(())
}

/// How many options a multi-pick question accepts. A bound has to be a whole
/// number of at least one to mean anything, so everything else — an absent
/// key, `0`, junk from a hand-edited bag — reads as "no bound". Mirrors
/// `selectionBounds` in `browser/form-renderer/src/validation.ts`.
fn selection_bounds(options: &JsonValue) -> (Option<u64>, Option<u64>) {
    let bound = |key: &str| {
        options
            .get(key)
            .and_then(|v| v.as_u64())
            .filter(|n| *n >= 1)
    };

    (bound("minSelected"), bound("maxSelected"))
}

/// Bounds on how many options a `multi-select` / `dropdown-multi` answer may
/// carry. An *empty* answer never reaches here (it counts as unanswered, which
/// is `required`'s business), so a minimum only ever applies to an answer the
/// visitor actually gave.
fn check_selection_count(picked: usize, options: &JsonValue) -> Result<(), String> {
    let (min, max) = selection_bounds(options);
    if let Some(min) = min {
        if (picked as u64) < min {
            return Err(format!("Please select at least {min} option(s)"));
        }
    }
    if let Some(max) = max {
        if (picked as u64) > max {
            return Err(format!("At most {max} option(s) allowed"));
        }
    }
    Ok(())
}

/// Checks picked option subjects against the question's resolved options.
/// Unlike the other validators this fails closed on an empty list: options
/// are resolved from `allowsOnly`, so "no options" means the question has
/// none to pick, not that anything goes.
fn check_membership(items: &[String], options: &JsonValue) -> Result<(), String> {
    let allowed: Vec<&str> = options_list(options)
        .iter()
        .filter_map(|o| option_str(o, "value"))
        .collect();
    for item in items {
        if !allowed.contains(&item.as_str()) {
            return Err("Not one of the allowed options".to_string());
        }
    }
    Ok(())
}

fn is_valid_email(s: &str) -> bool {
    let re = regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("valid regex");
    re.is_match(s)
}

/// Deliberately permissive: digits with the usual separators, optional
/// country prefix. Mirrors `PHONE_RE` in
/// `browser/form-renderer/src/validation.ts`.
fn is_valid_phone(s: &str) -> bool {
    let re = regex::Regex::new(r"^\+?[0-9(][0-9\s\-().]{4,24}$").expect("valid regex");
    re.is_match(s)
}

/// A country answer is an ISO 3166-1 alpha-2 code. Only the shape is checked
/// here: the canonical list lives in `browser/form-renderer/src/countries.ts`,
/// where the picker is, and duplicating 249 codes on this side would buy
/// nothing but a second thing to keep current.
fn is_valid_country(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// Mirrors `URL_RE` in `browser/form-renderer/src/validation.ts`.
fn is_valid_url(s: &str) -> bool {
    let re = regex::Regex::new(r"(?i)^https?://[^\s/$.?#][^\s]*$").expect("valid regex");
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
        Value::ResourceArray(a) => a.is_empty(),
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
        // Every choice question stores a resourceArray of option subjects —
        // single-pick ones just hold exactly one — so they all aggregate the
        // same way.
        t if is_choice_field(t) => {
            let picks = values
                .iter()
                .flat_map(|v| v.to_subjects(None).unwrap_or_default());
            obj.insert("counts".into(), choice_counts(options, picks));
        }
        // No configured option list to zero-fill: count the codes that were
        // actually picked, most-picked first.
        "country" => {
            obj.insert(
                "counts".into(),
                distinct_counts(values.iter().map(|v| v.to_string())),
            );
        }
        "checkbox" => {
            let checked = values
                .iter()
                .filter(|v| matches!(v, Value::Boolean(true)))
                .count();
            obj.insert("checked".into(), json!(checked));
            obj.insert("unchecked".into(), json!(answered - checked));
        }
        // Numeric questions (incl. the bounded likert/rating scales) share the
        // histogram treatment.
        "number" | "currency" | "likert" | "rating" => {
            let numbers: Vec<f64> = values.iter().filter_map(|v| as_f64(v)).collect();
            if let Some((bins, min, max, mean)) = histogram(&numbers) {
                obj.insert("bins".into(), bins);
                obj.insert("min".into(), json!(min));
                obj.insert("max".into(), json!(max));
                obj.insert("mean".into(), json!(mean));
            }
        }
        // short-text, long-text, email, phone, url, date, datetime and the
        // composite JSON types (address, choice-matrix, table-input): a
        // sample of raw answers.
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
/// Zero-filled counts in the question's configured option order. Picks are
/// option subjects (that is what a submission stores); the pairs are keyed by
/// the option's *label*, since that is what the results UI renders. Answers
/// matching no current option — an option deleted since — collect in "Other".
fn choice_counts(options: &JsonValue, picks: impl Iterator<Item = String>) -> JsonValue {
    // (value, label, count)
    let mut counts: Vec<(&str, &str, usize)> = options_list(options)
        .iter()
        .filter_map(|o| {
            let value = option_str(o, "value")?;
            Some((value, option_str(o, "label").unwrap_or(value), 0))
        })
        .collect();

    let mut other = 0;
    for pick in picks {
        match counts.iter_mut().find(|(value, ..)| *value == pick) {
            Some((.., count)) => *count += 1,
            None => other += 1,
        }
    }

    let mut pairs: Vec<JsonValue> = counts
        .into_iter()
        .map(|(_, label, count)| json!([label, count]))
        .collect();
    if other > 0 {
        pairs.push(json!(["Other", other]));
    }

    json!(pairs)
}

/// Counts repeats of free-form answers (`country`), ordered by count and then
/// alphabetically so the same data always renders the same way.
fn distinct_counts(picks: impl Iterator<Item = String>) -> JsonValue {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for pick in picks {
        match counts.iter_mut().find(|(value, _)| value == &pick) {
            Some((_, count)) => *count += 1,
            None => counts.push((pick, 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    json!(counts
        .into_iter()
        .map(|(value, count)| json!([value, count]))
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

// ── Invite codes (Phase 6 "Private links") ──────────────────────────────────

/// `form-access` value that switches a Form from "anyone with the link" to
/// invite-code gating. Any other value (or absence) means public.
pub const ACCESS_INVITE_ONLY: &str = "invite-only";
/// The submit body's top-level key carrying the visitor's invite code.
pub const INVITE_CODE_FIELD: &str = "code";

pub fn is_invite_only(form: &Resource) -> bool {
    form.get(atomic_lib::urls::FORM_ACCESS)
        .map(|v| v.to_string() == ACCESS_INVITE_ONLY)
        .unwrap_or(false)
}

/// Outcome of a non-consuming invite-code check ([check_invite_code]).
#[derive(Debug)]
pub enum InviteCodeCheck {
    /// The code exists, belongs to this form, and hasn't been consumed.
    /// Carries the code resource so the submit path can consume it without a
    /// second lookup.
    Valid(Box<Resource>),
    Used,
    /// Unknown code, a code belonging to another form, or an empty string.
    Invalid,
}

/// Looks up an invite code presented for `form`, without consuming it.
///
/// Deliberately queries the **basic-path** `PropValSub` index alone
/// (`form-code = X`, no extra filters) and verifies the hit's `parent` in
/// code: adding a `parent`/`isA` filter would route through the complex query
/// path, which lazily persists one watched query per distinct filter — i.e.
/// one per code value ever looked up (`Tree::WatchedQueries` bloat).
pub async fn check_invite_code(store: &Db, form: &Resource, code: &str) -> InviteCodeCheck {
    if code.is_empty() {
        return InviteCodeCheck::Invalid;
    }

    let query = Query::new_prop_val(atomic_lib::urls::FORM_CODE, code);
    let Ok(QueryResult { resources, .. }) = store.query(&query).await else {
        return InviteCodeCheck::Invalid;
    };

    let form_id = form.get_subject().pure_id();
    for candidate in resources {
        let belongs_to_form = matches!(
            candidate.get(atomic_lib::urls::PARENT),
            Ok(Value::AtomicUrl(parent)) if parent.pure_id() == form_id
        );
        let is_invite_code = candidate
            .get(atomic_lib::urls::IS_A)
            .and_then(|v| v.to_subjects(None))
            .unwrap_or_default()
            .iter()
            .any(|c| c == atomic_lib::urls::FORM_INVITE_CODE);
        if !belongs_to_form || !is_invite_code {
            continue;
        }

        if candidate.get(atomic_lib::urls::USED_AT).is_ok() {
            return InviteCodeCheck::Used;
        }

        return InviteCodeCheck::Valid(Box::new(candidate));
    }

    InviteCodeCheck::Invalid
}

/// Marks an invite code as consumed (`used-at` = now), signed by the store's
/// default agent. The caller must serialize check-and-consume (the submit
/// handler holds a per-form mutex) — commits are not compare-and-swap, so
/// this alone can't prevent a double spend.
pub async fn consume_invite_code(store: &Db, code: &mut Resource) -> AtomicResult<()> {
    code.set(
        atomic_lib::urls::USED_AT.into(),
        Value::Timestamp(atomic_lib::utils::now()),
        store,
    )
    .await?;
    code.save(store).await?;
    Ok(())
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
    use serde::Deserialize;
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

    /// Appends a layout block to the form's only page, in place.
    async fn append_block(store: &Db, form: &Resource, block: &Subject) {
        let page_subject = form
            .get(urls::FORM_PAGES)
            .unwrap()
            .to_subjects(None)
            .unwrap()[0]
            .clone();
        let mut page = store.get_resource(&page_subject.into()).await.unwrap();
        let mut fields = page
            .get(urls::FORM_FIELDS)
            .unwrap()
            .to_subjects(None)
            .unwrap();
        fields.push(block.to_string());
        page.set(
            urls::FORM_FIELDS.into(),
            Value::ResourceArray(fields.into_iter().map(|s| s.into()).collect()),
            store,
        )
        .await
        .unwrap();
        page.save_locally(store).await.unwrap();
    }

    async fn make_info_box(store: &Db, title: Option<&str>, style: Option<&str>) -> Resource {
        let mut info = Resource::new_instance(urls::FORM_INFO_BOX, store)
            .await
            .unwrap();
        info.set(
            urls::DESCRIPTION.into(),
            Value::Markdown("Read **this** first.".into()),
            store,
        )
        .await
        .unwrap();
        if let Some(title) = title {
            info.set(urls::NAME.into(), Value::String(title.into()), store)
                .await
                .unwrap();
        }
        if let Some(style) = style {
            info.set(
                urls::FORM_INFO_BOX_STYLE.into(),
                Value::String(style.into()),
                store,
            )
            .await
            .unwrap();
        }
        info.save_locally(store).await.unwrap();
        info
    }

    #[tokio::test]
    async fn builds_info_box_block() {
        let store = init_store().await;
        let (form, _) = build_test_form(&store).await;

        let info = make_info_box(&store, Some("Heads up"), Some("warning")).await;
        append_block(&store, &form, info.get_subject()).await;

        let definition = build_form_definition(&store, &form).await.unwrap();
        match &definition.pages[0].blocks[1] {
            FormBlock::InfoBox {
                title, text, style, ..
            } => {
                assert_eq!(title.as_deref(), Some("Heads up"));
                assert_eq!(text, "Read **this** first.");
                assert_eq!(style, "warning");
            }
            other => panic!("expected an InfoBox block, got {other:?}"),
        }
    }

    /// `form-info-box-style` is a plain String at the store, so a definition
    /// must never hand the renderer a style it has no CSS for. An untitled
    /// box drops `title` rather than emitting an empty one.
    #[tokio::test]
    async fn info_box_falls_back_to_info_style() {
        let store = init_store().await;
        let (form, _) = build_test_form(&store).await;

        let info = make_info_box(&store, None, Some("chartreuse")).await;
        append_block(&store, &form, info.get_subject()).await;

        let definition = build_form_definition(&store, &form).await.unwrap();
        match &definition.pages[0].blocks[1] {
            FormBlock::InfoBox { title, style, .. } => {
                assert_eq!(*title, None);
                assert_eq!(style, DEFAULT_INFO_BOX_STYLE);
            }
            other => panic!("expected an InfoBox block, got {other:?}"),
        }
    }

    /// The `kind` a client sees is kebab-case, not serde's default
    /// `info_box` — `@tomic/form-renderer` switches on the exact string.
    #[tokio::test]
    async fn info_box_serializes_as_kebab_kind() {
        let store = init_store().await;
        let (form, _) = build_test_form(&store).await;

        let info = make_info_box(&store, None, None).await;
        append_block(&store, &form, info.get_subject()).await;

        let definition = build_form_definition(&store, &form).await.unwrap();
        let json = serde_json::to_value(&definition.pages[0].blocks[1]).unwrap();
        assert_eq!(json["kind"], "info-box");
        assert_eq!(json["style"], "info");
        assert!(json.get("title").is_none());
    }

    /// Creates a Tag under `parent`, as the builder's tag editor does:
    /// `name` is the free-text label, `shortname` the required slug.
    async fn make_tag(store: &Db, parent: &str, name: &str, color: Option<&str>) -> String {
        let mut tag = Resource::new_instance(urls::TAG, store).await.unwrap();
        tag.set(urls::NAME.into(), Value::String(name.into()), store)
            .await
            .unwrap();
        tag.set(
            urls::SHORTNAME.into(),
            Value::Slug(name.to_lowercase().replace(' ', "-")),
            store,
        )
        .await
        .unwrap();
        if let Some(color) = color {
            tag.set(urls::COLOR.into(), Value::String(color.into()), store)
                .await
                .unwrap();
        }
        tag.set(
            urls::PARENT.into(),
            Value::AtomicUrl(parent.to_string().into()),
            store,
        )
        .await
        .unwrap();
        tag.save_locally(store).await.unwrap();
        tag.get_subject().to_string()
    }

    #[tokio::test]
    async fn resolves_choice_options_from_the_mapped_propertys_tags() {
        let store = init_store().await;
        let (_class, prop) =
            make_class_and_property(&store, "c", "pick", urls::RESOURCE_ARRAY).await;

        let yes = make_tag(&store, &prop, "Yes please", Some("#ff0000")).await;
        let no = make_tag(&store, &prop, "No thanks", None).await;

        let mut property = store.get_resource(&prop.clone().into()).await.unwrap();
        property
            .set(
                urls::ALLOWS_ONLY.into(),
                Value::ResourceArray(vec![yes.clone().into(), no.clone().into()]),
                &store,
            )
            .await
            .unwrap();
        property.save_locally(&store).await.unwrap();

        let mut options = json!({});
        resolve_choice_options(&store, "dropdown", &prop, &mut options).await;

        assert_eq!(
            options[OPTIONS_KEY],
            json!([
                { "value": yes, "label": "Yes please", "color": "#ff0000" },
                { "value": no, "label": "No thanks" },
            ]),
            "options resolve in `allowsOnly` order, carrying the Tag's free-text \
             name as the label and omitting unset keys"
        );

        // The resolved list is what membership is checked against, so a
        // submission naming a tag subject validates and a stray one does not.
        assert!(check_membership(&[yes], &options).is_ok());
        assert!(check_membership(&["did:ad:tag:elsewhere".to_string()], &options).is_err());
    }

    #[tokio::test]
    async fn choice_options_are_empty_when_the_property_allows_nothing() {
        let store = init_store().await;
        let (_class, prop) =
            make_class_and_property(&store, "c2", "pick2", urls::RESOURCE_ARRAY).await;

        let mut options = json!({ "placeholder": "Pick one" });
        resolve_choice_options(&store, "dropdown", &prop, &mut options).await;

        assert_eq!(options[OPTIONS_KEY], json!([]));
        assert_eq!(
            options["placeholder"], "Pick one",
            "resolution only replaces the options key"
        );
        // Fails closed: an empty list allows nothing, rather than everything.
        assert!(check_membership(&["anything".to_string()], &options).is_err());
    }

    /// A Table plus `count` rows under it, each labelled by `label_prop`.
    /// Same shape `build_form_summary`'s rows have.
    async fn make_table_with_rows(
        store: &Db,
        class: &str,
        label_prop: &str,
        labels: &[&str],
    ) -> String {
        let mut table = Resource::new_instance(urls::TABLE, store).await.unwrap();
        table
            .set(urls::NAME.into(), Value::String("Customers".into()), store)
            .await
            .unwrap();
        table
            .set(
                urls::CLASSTYPE_PROP.into(),
                Value::AtomicUrl(class.to_string().into()),
                store,
            )
            .await
            .unwrap();
        table.save_locally(store).await.unwrap();
        let table_subject = table.get_subject().to_string();

        // An empty label leaves the column unset on that row.
        for label in labels {
            let mut row = Resource::new_instance(class, store).await.unwrap();
            row.set(
                urls::PARENT.into(),
                Value::AtomicUrl(table_subject.clone().into()),
                store,
            )
            .await
            .unwrap();
            row.set(
                urls::NAME.into(),
                Value::String(format!("row {label}")),
                store,
            )
            .await
            .unwrap();
            if !label.is_empty() {
                row.set(
                    label_prop.to_string(),
                    Value::String((*label).to_string()),
                    store,
                )
                .await
                .unwrap();
            }
            row.save_locally(store).await.unwrap();
        }

        table_subject
    }

    #[tokio::test]
    async fn choice_options_can_mirror_another_columns_tags() {
        let store = init_store().await;
        let (_class, own_prop) =
            make_class_and_property(&store, "c-own", "pick-own", urls::RESOURCE_ARRAY).await;
        let (_other_class, source_prop) =
            make_class_and_property(&store, "c-src", "status", urls::RESOURCE_ARRAY).await;

        let open = make_tag(&store, &source_prop, "Open", None).await;
        let done = make_tag(&store, &source_prop, "Done", None).await;

        let mut source = store
            .get_resource(&source_prop.clone().into())
            .await
            .unwrap();
        source
            .set(
                urls::ALLOWS_ONLY.into(),
                Value::ResourceArray(vec![open.clone().into(), done.clone().into()]),
                &store,
            )
            .await
            .unwrap();
        source.save_locally(&store).await.unwrap();

        // The question's own Property allows nothing — the source is what
        // counts, so this must not shadow it.
        let mut options = json!({ OPTIONS_SOURCE_KEY: { "property": source_prop } });
        resolve_choice_options(&store, "dropdown", &own_prop, &mut options).await;

        assert_eq!(
            options[OPTIONS_KEY],
            json!([
                { "value": open, "label": "Open" },
                { "value": done, "label": "Done" },
            ])
        );
        assert!(check_membership(&[open], &options).is_ok());
    }

    #[tokio::test]
    async fn choice_options_can_be_the_rows_of_a_table() {
        let store = init_store().await;
        let (row_class, name_prop) =
            make_class_and_property(&store, "customer", "customer-name", urls::STRING).await;
        let (_c, own_prop) =
            make_class_and_property(&store, "c-rows", "pick-row", urls::RESOURCE_ARRAY).await;

        let table = make_table_with_rows(&store, &row_class, &name_prop, &["Acme", "Globex"]).await;

        let mut options = json!({
            OPTIONS_SOURCE_KEY: { "table": table, "labelProperty": name_prop },
        });
        resolve_choice_options(&store, "dropdown", &own_prop, &mut options).await;

        let resolved = options[OPTIONS_KEY].as_array().unwrap().clone();
        let mut labels: Vec<&str> = resolved
            .iter()
            .map(|o| o["label"].as_str().unwrap())
            .collect();
        labels.sort_unstable();
        assert_eq!(labels, ["Acme", "Globex"]);

        // The answer is the row's subject, not a copy of its label — which is
        // the whole point of sourcing from a table.
        let picked = resolved[0]["value"].as_str().unwrap().to_string();
        assert_ne!(picked, resolved[0]["label"].as_str().unwrap());
        assert!(check_membership(&[picked], &options).is_ok());
        assert!(check_membership(&["Acme".to_string()], &options).is_err());
    }

    #[tokio::test]
    async fn rows_the_label_column_is_empty_for_are_not_offered() {
        let store = init_store().await;
        let (row_class, notes_prop) =
            make_class_and_property(&store, "lead", "lead-notes", urls::STRING).await;
        let (_c, own_prop) =
            make_class_and_property(&store, "c-blank", "pick-blank", urls::RESOURCE_ARRAY).await;

        // Two rows have notes, one does not — but all three have a `name`.
        let table =
            make_table_with_rows(&store, &row_class, &notes_prop, &["Hot", "", "Cold"]).await;

        let mut options = json!({
            OPTIONS_SOURCE_KEY: { "table": table, "labelProperty": notes_prop },
        });
        resolve_choice_options(&store, "dropdown", &own_prop, &mut options).await;

        let mut labels: Vec<&str> = options[OPTIONS_KEY]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["label"].as_str().unwrap())
            .collect();
        labels.sort_unstable();
        assert_eq!(
            labels,
            ["Cold", "Hot"],
            "the unlabelled row is dropped rather than falling back to its \
             `name` — an option labelled from a different column than the one \
             the builder picked is worse than no option"
        );
    }

    #[tokio::test]
    async fn an_unresolvable_options_source_allows_nothing() {
        let store = init_store().await;
        let (_class, own_prop) =
            make_class_and_property(&store, "c-gone", "pick-gone", urls::RESOURCE_ARRAY).await;

        // Both branches fail closed rather than falling back to the field's
        // own tags, which would silently offer a different list than the
        // builder shows.
        for source in [
            json!({ "property": "did:ad:property:gone" }),
            json!({ "table": "did:ad:table:gone" }),
        ] {
            let mut options = json!({ OPTIONS_SOURCE_KEY: source });
            resolve_choice_options(&store, "dropdown", &own_prop, &mut options).await;

            assert_eq!(options[OPTIONS_KEY], json!([]));
            assert!(check_membership(&["anything".to_string()], &options).is_err());
        }
    }

    #[tokio::test]
    async fn non_choice_fields_keep_their_options_bag() {
        let store = init_store().await;
        let (_class, prop) = make_class_and_property(&store, "c3", "txt", urls::STRING).await;

        let mut options = json!({ "placeholder": "Your name" });
        resolve_choice_options(&store, "short-text", &prop, &mut options).await;

        assert_eq!(options, json!({ "placeholder": "Your name" }));
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
        // Unset: the renderer treats this as "show" (only `Some(false)` hides it).
        assert_eq!(styling.show_progress_bar, None);
        // The page animation is the other way round — unset means no
        // animation, so this form's pages change instantly.
        assert_eq!(styling.animate_page_transitions, None);
        // `has_image` never leaks into the wire format.
        let wire = serde_json::to_value(&styling).unwrap();
        assert!(wire.get("hasImage").is_none());
    }

    #[tokio::test]
    async fn definition_carries_field_spacing() {
        let store = init_store().await;
        let (mut form, _email_prop) = build_test_form(&store).await;

        form.set(
            urls::FORM_STYLING.into(),
            Value::Json(json!({ "fieldSpacing": "large" })),
            &store,
        )
        .await
        .unwrap();
        form.save_locally(&store).await.unwrap();

        let styling = build_form_definition(&store, &form).await.unwrap().styling;
        assert_eq!(styling.field_spacing.as_deref(), Some("large"));
        let wire = serde_json::to_value(&styling).unwrap();
        assert_eq!(wire["fieldSpacing"], json!("large"));
    }

    #[tokio::test]
    async fn definition_can_disable_progress_bar() {
        let store = init_store().await;
        let (mut form, _email_prop) = build_test_form(&store).await;

        form.set(
            urls::FORM_STYLING.into(),
            Value::Json(json!({ "showProgressBar": false })),
            &store,
        )
        .await
        .unwrap();
        form.save_locally(&store).await.unwrap();

        let styling = build_form_definition(&store, &form).await.unwrap().styling;
        assert_eq!(styling.show_progress_bar, Some(false));
        let wire = serde_json::to_value(&styling).unwrap();
        assert_eq!(wire["showProgressBar"], json!(false));
    }

    #[tokio::test]
    async fn definition_can_disable_drafts() {
        let store = init_store().await;
        let (mut form, _email_prop) = build_test_form(&store).await;

        // Unset means drafts are on: the key must be absent from the wire
        // format so the runtime's `!== false` default applies.
        let styling = build_form_definition(&store, &form).await.unwrap().styling;
        assert_eq!(styling.save_drafts, None);
        assert!(serde_json::to_value(&styling)
            .unwrap()
            .get("saveDrafts")
            .is_none());

        form.set(
            urls::FORM_STYLING.into(),
            Value::Json(json!({ "saveDrafts": false })),
            &store,
        )
        .await
        .unwrap();
        form.save_locally(&store).await.unwrap();

        let styling = build_form_definition(&store, &form).await.unwrap().styling;
        assert_eq!(styling.save_drafts, Some(false));
        let wire = serde_json::to_value(&styling).unwrap();
        assert_eq!(wire["saveDrafts"], json!(false));
    }

    #[tokio::test]
    async fn definition_can_enable_page_animations() {
        let store = init_store().await;
        let (mut form, _email_prop) = build_test_form(&store).await;

        form.set(
            urls::FORM_STYLING.into(),
            Value::Json(json!({ "animatePageTransitions": true })),
            &store,
        )
        .await
        .unwrap();
        form.save_locally(&store).await.unwrap();

        let styling = build_form_definition(&store, &form).await.unwrap().styling;
        assert_eq!(styling.animate_page_transitions, Some(true));
        let wire = serde_json::to_value(&styling).unwrap();
        assert_eq!(wire["animatePageTransitions"], json!(true));
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
                conditions: vec![],
                blocks: vec![FormBlock::Field {
                    maps_to: "https://example.com/n".into(),
                    label: "Number".into(),
                    description: None,
                    field_type: "number".into(),
                    required: true,
                    options: json!({"min": 1, "max": 10}),
                    conditions: vec![],
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
                conditions: vec![],
                blocks: vec![FormBlock::Field {
                    maps_to: "https://example.com/r".into(),
                    label: "Radio".into(),
                    description: None,
                    field_type: "radio".into(),
                    required: true,
                    options: choice_options(&["A", "B"]),
                    conditions: vec![],
                }],
            }],
        };

        let mut values = Map::new();
        values.insert("https://example.com/r".into(), json!(tag("C")));
        let errors = validate_submission(&definition, &values).unwrap_err();
        assert!(errors[0].message.contains("Not one of the allowed options"));
    }

    // ── Extended field types (planning/form-field-types.md) ──────────────

    const Q: &str = "https://example.com/q";

    /// A one-question form, so the extended types can be validated without
    /// building a whole resource graph.
    fn single_field_definition(
        field_type: &str,
        required: bool,
        options: JsonValue,
    ) -> FormDefinition {
        FormDefinition {
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
                conditions: vec![],
                blocks: vec![FormBlock::Field {
                    maps_to: Q.into(),
                    label: "Q".into(),
                    description: None,
                    field_type: field_type.into(),
                    required,
                    options,
                    conditions: vec![],
                }],
            }],
        }
    }

    /// Submits `answer` to a one-question form and returns the coerced value
    /// or the first error message.
    fn submit_one(
        field_type: &str,
        required: bool,
        options: JsonValue,
        answer: JsonValue,
    ) -> Result<Value, String> {
        let definition = single_field_definition(field_type, required, options);
        let mut values = Map::new();
        values.insert(Q.into(), answer);
        match validate_submission(&definition, &values) {
            Ok(mut coerced) => Ok(coerced.remove(0).1),
            Err(errors) => Err(errors[0].message.clone()),
        }
    }

    /// `Value` has no `PartialEq`, so accepted answers are asserted through
    /// these narrowing helpers (which also pin down the `Value` variant, i.e.
    /// the datatype the mapped Property will receive).
    fn ok_string(result: Result<Value, String>) -> String {
        match result.expect("expected the answer to validate") {
            Value::String(s) => s,
            other => panic!("expected a String value, got {other:?}"),
        }
    }

    /// The Tag subject a test's option label stands for. Choice answers are
    /// option subjects now, so tests name options by label and go through
    /// this to get what actually crosses the wire.
    fn tag(label: &str) -> String {
        format!("did:ad:tag:{label}")
    }

    /// An options bag as [resolve_choice_options] would leave it.
    fn choice_options(labels: &[&str]) -> JsonValue {
        json!({
            OPTIONS_KEY: labels
                .iter()
                .map(|label| json!({ "value": tag(label), "label": label }))
                .collect::<Vec<_>>()
        })
    }

    /// Choice answers land as a `resourceArray` of option subjects — single-pick
    /// questions included, which is what makes the mapped column an ordinary
    /// SelectProperty.
    fn ok_choice(result: Result<Value, String>) -> Vec<String> {
        match result.expect("expected the answer to validate") {
            value @ Value::ResourceArray(_) => value.to_subjects(None).expect("subjects"),
            other => panic!("expected a ResourceArray value, got {other:?}"),
        }
    }

    fn ok_integer(result: Result<Value, String>) -> i64 {
        match result.expect("expected the answer to validate") {
            Value::Integer(i) => i,
            other => panic!("expected an Integer value, got {other:?}"),
        }
    }

    fn ok_float(result: Result<Value, String>) -> f64 {
        match result.expect("expected the answer to validate") {
            Value::Float(f) => f,
            other => panic!("expected a Float value, got {other:?}"),
        }
    }

    fn err_message(result: Result<Value, String>) -> String {
        result.err().expect("expected a validation error")
    }

    #[test]
    fn phone_field_accepts_common_shapes_and_rejects_junk() {
        // `+31612345678` is the E.164 shape the browser's phone input submits.
        for good in [
            "+31612345678",
            "+31 6 1234 5678",
            "0201234567",
            "(020) 123-4567",
        ] {
            assert!(
                submit_one("phone", false, json!({}), json!(good)).is_ok(),
                "expected {good} to be accepted"
            );
        }
        assert_eq!(
            err_message(submit_one("phone", false, json!({}), json!("call me"))),
            "Not a valid phone number"
        );
    }

    #[test]
    fn country_field_takes_an_iso_code_and_rejects_a_name() {
        assert_eq!(
            ok_string(submit_one("country", false, json!({}), json!("NL"))),
            "NL"
        );
        for bad in ["Netherlands", "nl", "N", "NLD", "N1"] {
            assert_eq!(
                err_message(submit_one("country", false, json!({}), json!(bad))),
                "Not a valid country",
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn url_field_requires_an_http_scheme() {
        assert_eq!(
            ok_string(submit_one(
                "url",
                false,
                json!({}),
                json!("https://example.com/x")
            )),
            "https://example.com/x"
        );
        assert!(submit_one("url", false, json!({}), json!("example.com")).is_err());
        assert!(submit_one("url", false, json!({}), json!("javascript:alert(1)")).is_err());
    }

    #[test]
    fn currency_field_enforces_bounds() {
        assert_eq!(
            ok_float(submit_one(
                "currency",
                false,
                json!({"currency": "EUR"}),
                json!(12.5)
            )),
            12.5
        );
        assert_eq!(
            err_message(submit_one("currency", false, json!({"min": 10}), json!(5))),
            "Must be at least 10"
        );
    }

    #[test]
    fn dropdowns_enforce_option_membership() {
        let options = choice_options(&["A", "B"]);
        assert_eq!(
            ok_choice(submit_one(
                "dropdown",
                false,
                options.clone(),
                json!(tag("A"))
            )),
            vec![tag("A")],
            "a single-pick answer stores a one-element resourceArray"
        );
        assert!(submit_one("dropdown", false, options.clone(), json!(tag("C"))).is_err());
        assert_eq!(
            ok_choice(submit_one(
                "dropdown-multi",
                false,
                options.clone(),
                json!([tag("A"), tag("B")])
            )),
            vec![tag("A"), tag("B")]
        );
        assert!(submit_one(
            "dropdown-multi",
            false,
            options,
            json!([tag("A"), tag("C")])
        )
        .is_err());
    }

    #[test]
    fn multi_picks_enforce_selection_bounds() {
        let mut options = choice_options(&["A", "B", "C"]);
        options["minSelected"] = json!(2);
        options["maxSelected"] = json!(3);

        assert_eq!(
            ok_choice(submit_one(
                "multi-select",
                false,
                options.clone(),
                json!([tag("A"), tag("B")])
            )),
            vec![tag("A"), tag("B")]
        );
        assert_eq!(
            err_message(submit_one(
                "multi-select",
                false,
                options.clone(),
                json!([tag("A")])
            )),
            "Please select at least 2 option(s)"
        );

        let mut capped = choice_options(&["A", "B", "C"]);
        capped["maxSelected"] = json!(2);
        assert_eq!(
            err_message(submit_one(
                "dropdown-multi",
                false,
                capped,
                json!([tag("A"), tag("B"), tag("C")])
            )),
            "At most 2 option(s) allowed"
        );

        // An unanswered question is unanswered, not short of the minimum —
        // making it mandatory is `required`'s job. An empty answer never
        // reaches `coerce_value`, so this one goes through
        // `validate_submission` rather than [submit_one].
        let definition = single_field_definition("multi-select", false, options.clone());
        let mut empty = Map::new();
        empty.insert(Q.into(), json!([]));
        assert!(
            validate_submission(&definition, &empty)
                .expect("an empty answer to an optional question is not an error")
                .is_empty(),
            "nothing is stored for an unanswered question"
        );
        assert_eq!(
            err_message(submit_one("multi-select", true, options, json!([]))),
            "This field is required"
        );

        // Junk bounds from a hand-edited bag are no bounds at all.
        let mut junk = choice_options(&["A", "B"]);
        junk["minSelected"] = json!("two");
        junk["maxSelected"] = json!(0);
        assert!(submit_one("multi-select", false, junk, json!([tag("A")])).is_ok());
    }

    #[test]
    fn likert_and_rating_are_bounded_integers() {
        assert_eq!(
            ok_integer(submit_one("likert", false, json!({"scale": 7}), json!(7))),
            7
        );
        assert_eq!(
            err_message(submit_one("likert", false, json!({"scale": 5}), json!(6))),
            "Answer must be between 1 and 5"
        );
        // An out-of-range `scale` falls back to the default rather than
        // trusting whatever the options bag says.
        assert_eq!(
            err_message(submit_one("likert", false, json!({"scale": 99}), json!(6))),
            "Answer must be between 1 and 5"
        );
        assert_eq!(
            err_message(submit_one("rating", false, json!({}), json!(0))),
            "Rating must be between 1 and 5"
        );
        assert_eq!(
            ok_integer(submit_one("rating", false, json!({"max": 10}), json!(9))),
            9
        );
    }

    #[test]
    fn picture_choice_validates_like_a_radio() {
        let options = json!({
            OPTIONS_KEY: [
                { "value": tag("Cat"), "label": "Cat", "image": "did:ad:file-a" },
                { "value": tag("Dog"), "label": "Dog", "image": "did:ad:file-b" },
            ]
        });
        assert_eq!(
            ok_choice(submit_one(
                "picture-choice",
                false,
                options.clone(),
                json!(tag("Dog"))
            )),
            vec![tag("Dog")]
        );
        assert!(submit_one("picture-choice", false, options, json!(tag("Bird"))).is_err());
    }

    #[test]
    fn choice_matrix_checks_rows_columns_and_completeness() {
        let options = json!({"rows": ["Speed", "Price"], "columns": ["Bad", "Good"]});

        assert!(submit_one(
            "choice-matrix",
            false,
            options.clone(),
            json!({"Speed": "Good"})
        )
        .is_ok());
        assert!(submit_one(
            "choice-matrix",
            false,
            options.clone(),
            json!({"Weight": "Good"})
        )
        .is_err());
        assert!(submit_one(
            "choice-matrix",
            false,
            options.clone(),
            json!({"Speed": "Amazing"})
        )
        .is_err());
        // Required means every row, not just "something was picked".
        assert_eq!(
            err_message(submit_one(
                "choice-matrix",
                true,
                options.clone(),
                json!({"Speed": "Good"})
            )),
            "Please answer every row"
        );
        assert!(submit_one(
            "choice-matrix",
            true,
            options,
            json!({"Speed": "Good", "Price": "Bad"})
        )
        .is_ok());
    }

    #[test]
    fn table_input_checks_columns_types_and_row_bounds() {
        let options = json!({
            "columns": [{"label": "Item", "type": "text"}, {"label": "Qty", "type": "number"}],
            "maxRows": 2,
        });

        assert!(submit_one(
            "table-input",
            false,
            options.clone(),
            json!([{"Item": "Bolt", "Qty": 4}])
        )
        .is_ok());
        assert_eq!(
            err_message(submit_one(
                "table-input",
                false,
                options.clone(),
                json!([{"Item": "Bolt", "Qty": "four"}])
            )),
            "'Qty' must be a number"
        );
        assert_eq!(
            err_message(submit_one(
                "table-input",
                false,
                options.clone(),
                json!([{"Nope": "x"}])
            )),
            "'Nope' is not one of the columns"
        );
        assert_eq!(
            err_message(submit_one(
                "table-input",
                false,
                options,
                json!([{"Item": "a"}, {"Item": "b"}, {"Item": "c"}])
            )),
            "At most 2 row(s) allowed"
        );
    }

    #[test]
    fn address_rejects_unknown_keys_and_enforces_core_subfields() {
        assert_eq!(
            err_message(submit_one(
                "address",
                false,
                json!({}),
                json!({"planet": "Mars"})
            )),
            "'planet' is not part of an address"
        );
        assert_eq!(
            err_message(submit_one(
                "address",
                true,
                json!({}),
                json!({"line1": "Main St 1", "city": "Utrecht"})
            )),
            "Country is required"
        );
        assert!(submit_one(
            "address",
            true,
            json!({}),
            json!({"line1": "Main St 1", "city": "Utrecht", "country": "NL"})
        )
        .is_ok());
    }

    #[test]
    fn all_empty_composites_count_as_unanswered() {
        // An untouched address / matrix / table grid must read as "not
        // answered" (so `required` fires) rather than as a partial answer.
        for (field_type, answer) in [
            ("address", json!({"line1": "", "city": ""})),
            ("choice-matrix", json!({})),
            ("table-input", json!([{"Item": ""}])),
        ] {
            assert_eq!(
                err_message(submit_one(
                    field_type,
                    true,
                    json!({"columns": [{"label": "Item"}]}),
                    answer
                )),
                "This field is required",
                "{field_type} should read as unanswered"
            );
        }
    }

    #[test]
    fn rewrite_option_images_only_touches_option_image_subjects() {
        let mut definition = single_field_definition(
            "picture-choice",
            false,
            json!({
                OPTIONS_KEY: [
                    { "value": tag("A"), "label": "A", "image": "did:ad:file-a" },
                    { "value": tag("B"), "label": "B", "image": "" },
                    { "value": tag("C"), "label": "C" },
                ]
            }),
        );

        rewrite_option_images(&mut definition, |subject| format!("/img/{subject}"));

        let FormBlock::Field { options, .. } = &definition.pages[0].blocks[0] else {
            panic!("expected a field block");
        };
        assert_eq!(
            options[OPTIONS_KEY],
            json!([
                { "value": tag("A"), "label": "A", "image": "/img/did:ad:file-a" },
                { "value": tag("B"), "label": "B", "image": "" },
                { "value": tag("C"), "label": "C" },
            ]),
            "only non-empty image subjects are rewritten; the rest is untouched"
        );
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
    fn extended_types_reuse_the_existing_summary_shapes() {
        // Deliberately no new aggregate shapes: the extended types route onto
        // the choice-count / histogram / answer-sample paths that already exist.
        let dropdown = field_summary(
            "dropdown",
            choice_options(&["A", "B"]),
            &[vec![tag("A")].into()],
            1,
        );
        assert_eq!(dropdown["counts"], json!([["A", 1], ["B", 0]]));

        let rating = field_summary(
            "rating",
            json!({"max": 5}),
            &[Value::Integer(4), Value::Integer(2)],
            2,
        );
        assert_eq!(rating["mean"], json!(3.0));
        assert!(rating.get("bins").is_some());

        let address = field_summary(
            "address",
            json!({}),
            &[Value::Json(json!({"city": "Utrecht"}))],
            1,
        );
        assert_eq!(address["answers"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn country_counts_rank_by_popularity_then_code() {
        // No configured options to zero-fill, so the codes people actually
        // picked are the buckets — most-picked first, ties alphabetical.
        let values = vec![
            Value::String("BE".into()),
            Value::String("NL".into()),
            Value::String("NL".into()),
            Value::String("DE".into()),
        ];
        let summary = field_summary("country", json!({}), &values, 5);

        assert_eq!(summary["answered"], 4);
        assert_eq!(summary["skipped"], 1);
        assert_eq!(summary["counts"], json!([["NL", 2], ["BE", 1], ["DE", 1]]));
    }

    #[test]
    fn radio_counts_preserve_option_order_and_fold_unknown() {
        let values = vec![
            vec![tag("B")].into(),
            vec![tag("A")].into(),
            vec![tag("B")].into(),
            vec![tag("stray")].into(),
        ];
        let summary = field_summary("radio", choice_options(&["A", "B", "C"]), &values, 5);

        assert_eq!(summary["answered"], 4);
        assert_eq!(summary["skipped"], 1);
        assert_eq!(
            summary["counts"],
            json!([["A", 1], ["B", 2], ["C", 0], ["Other", 1]])
        );
    }

    #[test]
    fn multi_select_counts_iterate_picked_subjects() {
        let values = vec![
            vec![tag("Red"), tag("Green")].into(),
            vec![tag("Red")].into(),
        ];
        let summary = field_summary(
            "multi-select",
            choice_options(&["Red", "Green", "Blue"]),
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

    async fn make_invite_code(store: &Db, form: &Resource, code: &str) -> Resource {
        let mut invite = Resource::new_instance(urls::FORM_INVITE_CODE, store)
            .await
            .unwrap();
        invite
            .set(
                urls::PARENT.into(),
                Value::AtomicUrl(form.get_subject().to_string().into()),
                store,
            )
            .await
            .unwrap();
        invite
            .set(urls::FORM_CODE.into(), Value::String(code.into()), store)
            .await
            .unwrap();
        invite.save_locally(store).await.unwrap();
        invite
    }

    #[tokio::test]
    async fn access_mode_defaults_to_public() {
        let store = init_store().await;
        let (mut form, _) = build_test_form(&store).await;

        assert!(!is_invite_only(&form));

        form.set(
            urls::FORM_ACCESS.into(),
            Value::String(ACCESS_INVITE_ONLY.into()),
            &store,
        )
        .await
        .unwrap();
        assert!(is_invite_only(&form));

        form.set(
            urls::FORM_ACCESS.into(),
            Value::String("public".into()),
            &store,
        )
        .await
        .unwrap();
        assert!(!is_invite_only(&form));
    }

    #[tokio::test]
    async fn invite_code_check_and_consume() {
        let store = init_store().await;
        let (form, _) = build_test_form(&store).await;
        let (other_form, _) = build_test_form(&store).await;

        make_invite_code(&store, &form, "right-code").await;
        make_invite_code(&store, &other_form, "other-form-code").await;

        // Unknown / empty codes are invalid.
        assert!(matches!(
            check_invite_code(&store, &form, "nope").await,
            InviteCodeCheck::Invalid
        ));
        assert!(matches!(
            check_invite_code(&store, &form, "").await,
            InviteCodeCheck::Invalid
        ));
        // A code belonging to a different form is invalid for this one.
        assert!(matches!(
            check_invite_code(&store, &form, "other-form-code").await,
            InviteCodeCheck::Invalid
        ));

        // Valid, and checking does NOT consume.
        let InviteCodeCheck::Valid(mut code) = check_invite_code(&store, &form, "right-code").await
        else {
            panic!("expected a valid code");
        };
        assert!(matches!(
            check_invite_code(&store, &form, "right-code").await,
            InviteCodeCheck::Valid(_)
        ));

        consume_invite_code(&store, &mut code).await.unwrap();
        assert!(matches!(
            check_invite_code(&store, &form, "right-code").await,
            InviteCodeCheck::Used
        ));

        // Revoking (destroying) an unused code makes it invalid.
        let InviteCodeCheck::Valid(mut other) =
            check_invite_code(&store, &other_form, "other-form-code").await
        else {
            panic!("expected a valid code");
        };
        other.destroy(&store).await.unwrap();
        assert!(matches!(
            check_invite_code(&store, &other_form, "other-form-code").await,
            InviteCodeCheck::Invalid
        ));
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

    #[derive(Deserialize)]
    struct ConditionFixtureFile {
        cases: Vec<ConditionFixtureCase>,
    }

    #[derive(Deserialize)]
    struct ConditionFixtureCase {
        name: String,
        pages: Vec<FormPageDefinition>,
        values: Map<String, JsonValue>,
        #[serde(rename = "visibleFields")]
        visible_fields: Vec<String>,
        #[serde(rename = "visiblePages")]
        visible_pages: Vec<usize>,
        #[serde(rename = "storedFields")]
        stored_fields: Vec<String>,
        valid: bool,
    }

    #[test]
    fn condition_fixtures_match_ts() {
        let file: ConditionFixtureFile =
            serde_json::from_str(include_str!("../../testdata/form-conditions.json"))
                .expect("form-conditions.json should parse");

        for case in file.cases {
            let definition = FormDefinition {
                version: 1,
                id: String::new(),
                name: "fixture".into(),
                settings: json!({}),
                styling: FormStyling::default(),
                honeypot_field: HONEYPOT_FIELD.into(),
                captcha: None,
                pages: case.pages,
            };
            let vis = compute_visibility(&definition, &case.values);
            assert_eq!(
                vis.fields, case.visible_fields,
                "{}: visible fields",
                case.name
            );
            assert_eq!(
                vis.page_indices, case.visible_pages,
                "{}: visible pages",
                case.name
            );

            match validate_submission(&definition, &case.values) {
                Ok(coerced) => {
                    assert!(
                        case.valid,
                        "{}: expected invalid, got stored {:?}",
                        case.name, coerced
                    );
                    let mut stored: Vec<String> = coerced.into_iter().map(|(k, _)| k).collect();
                    stored.sort();
                    let mut expected = case.stored_fields.clone();
                    expected.sort();
                    assert_eq!(stored, expected, "{}: stored fields", case.name);
                }
                Err(errors) => {
                    assert!(
                        !case.valid,
                        "{}: expected valid, got errors {:?}",
                        case.name, errors
                    );
                    // Invalid cases still record which visible fields coerced.
                    // Re-run isn't needed: the fixture's storedFields lists
                    // what would have been kept had validation passed for
                    // those keys; we only check `valid` here.
                }
            }
        }
    }

    #[tokio::test]
    async fn definition_inlines_field_conditions() {
        let store = init_store().await;
        let (form, email_prop) = build_test_form(&store).await;

        // A second optional follow-up field on the same page, shown when the
        // email equals a sentinel. Mirrors how the builder stores conditions
        // as FormCondition children listed in `form-conditions`.
        let mut follow_up = Resource::new_instance(urls::FORM_FIELD, &store)
            .await
            .unwrap();
        follow_up
            .set(urls::NAME.into(), Value::String("Follow-up".into()), &store)
            .await
            .unwrap();
        follow_up
            .set(
                urls::FORM_MAPS_TO.into(),
                Value::AtomicUrl("https://example.com/follow-up".into()),
                &store,
            )
            .await
            .unwrap();
        follow_up
            .set(
                urls::FORM_FIELD_TYPE.into(),
                Value::String("short-text".into()),
                &store,
            )
            .await
            .unwrap();
        follow_up.save_locally(&store).await.unwrap();

        let mut cond = Resource::new_instance(urls::FORM_CONDITION, &store)
            .await
            .unwrap();
        cond.set(
            urls::PARENT.into(),
            Value::AtomicUrl(follow_up.get_subject().to_string().into()),
            &store,
        )
        .await
        .unwrap();
        // The existing email FormField is the first (only) field on the page.
        let page_subject = form
            .get(urls::FORM_PAGES)
            .unwrap()
            .to_subjects(None)
            .unwrap()[0]
            .clone();
        let page = store
            .get_resource(&page_subject.clone().into())
            .await
            .unwrap();
        let email_field = page
            .get(urls::FORM_FIELDS)
            .unwrap()
            .to_subjects(None)
            .unwrap()[0]
            .clone();
        cond.set(
            urls::FORM_CONDITION_FIELD.into(),
            Value::AtomicUrl(email_field.to_string().into()),
            &store,
        )
        .await
        .unwrap();
        cond.set(
            urls::FORM_CONDITION_OPERATOR.into(),
            Value::String("equals".into()),
            &store,
        )
        .await
        .unwrap();
        cond.set(
            urls::FORM_CONDITION_VALUE.into(),
            Value::Json(json!("trigger@example.com")),
            &store,
        )
        .await
        .unwrap();
        cond.save_locally(&store).await.unwrap();

        follow_up
            .set(
                urls::FORM_CONDITIONS.into(),
                Value::ResourceArray(vec![cond.get_subject().to_string().into()]),
                &store,
            )
            .await
            .unwrap();
        follow_up.save_locally(&store).await.unwrap();

        let mut page = page;
        let existing = page
            .get(urls::FORM_FIELDS)
            .unwrap()
            .to_subjects(None)
            .unwrap();
        let mut fields: Vec<_> = existing.into_iter().map(|s| s.into()).collect();
        fields.push(follow_up.get_subject().to_string().into());
        page.set(
            urls::FORM_FIELDS.into(),
            Value::ResourceArray(fields),
            &store,
        )
        .await
        .unwrap();
        page.save_locally(&store).await.unwrap();

        let definition = build_form_definition(&store, &form).await.unwrap();
        assert_eq!(definition.pages[0].blocks.len(), 2);
        match &definition.pages[0].blocks[1] {
            FormBlock::Field {
                maps_to,
                conditions,
                ..
            } => {
                assert_eq!(maps_to, "https://example.com/follow-up");
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0].field, email_prop);
                assert_eq!(conditions[0].operator, "equals");
                assert_eq!(conditions[0].value, json!("trigger@example.com"));
            }
            other => panic!("expected a Field block, got {other:?}"),
        }
    }
}
