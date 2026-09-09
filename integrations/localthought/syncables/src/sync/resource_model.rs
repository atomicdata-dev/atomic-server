//! Deriving the resource model from `components.crudResources` — the
//! [CRUD Causality Extension](https://github.com/pondersource/openapi-extensions/tree/main/spec/crud-causality)
//! overlay's contribution to a document, and the `x-crud` block it adds to
//! each operation.
//!
//! Ported from `discoverResourceModel` in
//! [`localthought/reflector`](https://github.com/localthought/reflector)'s
//! `src/sync/resources.ts`, which is the reference for the traversal below
//! (a resource's identity binding, a collection's context parameters, and
//! how a nested collection's parent is resolved). That file also derives a
//! client-generated-id policy for Google Calendar's resources; GitHub's
//! `addedFields` are all server-assigned, so this port doesn't carry that
//! part over — see [issue #3](https://github.com/localthought/syncables-rs/issues/3).

use indexmap::IndexMap;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::openapi::types::{JsonMap, OpenApiDocument, OperationObject, SchemaObject};

// --- The raw `crudResources` shape, as the overlay declares it ------------

/// One resource declared under `components.crudResources`, keyed by its
/// resource name (e.g. `issue`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrudResourceObject {
    /// Human-readable description of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How a single item of this resource is addressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ResourceIdentityObject>,
    /// The collections that list, and are written through, this resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collections: Option<IndexMap<String, ResourceCollectionObject>>,
    /// Any other key on the resource, notably `schema`.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// A resource's single-item URL template and how its path variables map to
/// record fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceIdentityObject {
    /// Single-item URL template, e.g. `/repos/{owner}/{repo}/issues/{issue_number}`.
    #[serde(rename = "urlTemplate")]
    pub url_template: String,
    /// Path variable to record field, e.g. `issue_number` binds to `number`
    /// — the resource's URL identity need not be the payload's own `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bindings: Option<IndexMap<String, IdentityBindingObject>>,
    /// Any other key on the identity.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// One entry of a [`ResourceIdentityObject::bindings`] map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityBindingObject {
    /// The record field the path variable is read from (and reconciled
    /// against, on write).
    pub field: String,
    /// Any other key on the binding.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// One entry of a [`CrudResourceObject::collections`] map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceCollectionObject {
    /// Collection URL template, e.g. `/repos/{owner}/{repo}/issues`.
    #[serde(rename = "urlTemplate")]
    pub url_template: String,
    /// Fixed query parameters added to every list request against this
    /// collection — e.g. GitHub's issues list returns only open issues by
    /// default, so the overlay declares `{ state: all }` to include closed
    /// ones too.
    #[serde(
        rename = "x-list-query",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub list_query: Option<IndexMap<String, Value>>,
    /// Any other key on the collection.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// Reads `document.components.crudResources`, keyed by resource name.
///
/// Returns [`Error::NoCrudResources`] if the document declares none — the
/// CRUD-causality overlay hasn't been applied.
pub(super) fn crud_resources(
    document: &OpenApiDocument,
) -> Result<IndexMap<String, CrudResourceObject>> {
    let raw = document
        .components
        .as_ref()
        .and_then(|components| components.extensions.get("crudResources"))
        .ok_or(Error::NoCrudResources)?;
    serde_json::from_value(raw.clone()).map_err(Error::from)
}

// --- The derived resource model --------------------------------------------

/// One resource collection the sync engine can walk, derived from one
/// `crudResources.<resource>.collections.<name>` entry and its resource's
/// `identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCollection {
    /// The collection's key, e.g. `issues`.
    pub name: String,
    /// The resource key in `crudResources`, e.g. `issue`.
    pub resource: String,
    /// Collection URL template, e.g. `/repos/{owner}/{repo}/issues`.
    pub collection_url: String,
    /// Single-item URL template (the resource's identity), e.g.
    /// `/repos/{owner}/{repo}/issues/{issue_number}`. Empty if the resource
    /// declares no `identity`.
    pub item_url: String,
    /// Record field that carries the item's own id (from the identity
    /// binding whose path variable the item URL — not the collection
    /// URL — uses), usually `id` but not always: GitHub's issues are
    /// addressed by `number`.
    pub id_field: String,
    /// Path variables in `collection_url` that must be supplied by a
    /// parent record or a configured constant (see
    /// [issue #6](https://github.com/localthought/syncables-rs/issues/6)).
    pub context_params: Vec<String>,
    /// Path variables in `item_url` that this resource's own identity
    /// binding supplies from the record itself (e.g. `issue_number`, from
    /// `number`) — not from a constant or a parent record.
    pub identity_params: Vec<String>,
    /// Fixed query parameters to add to the list request, from the
    /// collection's `x-list-query`.
    pub list_query: IndexMap<String, String>,
}

/// How a collection's context variable is filled: enumerate `collection`
/// and read `field` off each of its records. E.g. `issue_number` is
/// provided by listing `issues` and reading each record's `number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextProvider {
    /// The collection to enumerate.
    pub collection: String,
    /// The record field whose value fills the context variable.
    pub field: String,
}

/// The resource model derived from `components.crudResources`: every
/// managed collection, and how a nested collection's unresolved context
/// variable is resolved from a parent's own records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceModel {
    /// Every managed collection, in document order.
    pub collections: Vec<ManagedCollection>,
    providers: IndexMap<String, ContextProvider>,
}

impl ResourceModel {
    /// The managed collection named `name`, if any.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&ManagedCollection> {
        self.collections
            .iter()
            .find(|collection| collection.name == name)
    }

    /// The collection+field that supplies values for context path variable
    /// `param`, if any resource's identity binds it.
    #[must_use]
    pub fn provider_for(&self, param: &str) -> Option<&ContextProvider> {
        self.providers.get(param)
    }
}

/// The path variables (`{...}` segments) in a URL template, in order.
pub(super) fn path_variables(template: &str) -> Vec<String> {
    let mut variables = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        variables.push(rest[start + 1..start + end].to_string());
        rest = &rest[start + end + 1..];
    }
    variables
}

/// Whether any of the resource's own collection URLs contains `{param}` —
/// used to tell an identity binding that names the item's own id apart
/// from one that merely repeats a parent-scoping context variable.
fn collection_url_has(resource: &CrudResourceObject, param: &str) -> bool {
    let needle = format!("{{{param}}}");
    resource
        .collections
        .iter()
        .flatten()
        .any(|(_, collection)| collection.url_template.contains(&needle))
}

/// Renders a JSON scalar the way GitHub's `x-list-query` values are meant
/// to be sent — as the literal query string value.
fn stringify(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Builds the resource model from `components.crudResources`. Each resource
/// may declare an `identity` (its single-item URL and the binding from a
/// path variable to a record field) and one or more `collections` (list
/// URLs). This emits one [`ManagedCollection`] per declared collection,
/// across every resource — nothing about issues, comments, calendars or
/// events is compiled in.
pub fn discover_resource_model(document: &OpenApiDocument) -> Result<ResourceModel> {
    let resources = crud_resources(document)?;

    let mut collections = Vec::new();
    // resource name -> its first managed collection name (used as an
    // enumeration source for that resource's own identity bindings).
    let mut collection_of_resource: IndexMap<String, String> = IndexMap::new();
    // path variable -> (resource, field), from every resource's identity bindings.
    let mut bindings: Vec<(String, String, String)> = Vec::new();

    for (resource_name, resource) in &resources {
        let item_url = resource
            .identity
            .as_ref()
            .map(|identity| identity.url_template.as_str())
            .unwrap_or_default();

        let mut id_field = "id".to_string();
        let mut identity_params = Vec::new();
        if let Some(identity_bindings) = resource
            .identity
            .as_ref()
            .and_then(|identity| identity.bindings.as_ref())
        {
            for (param, binding) in identity_bindings {
                bindings.push((param.clone(), resource_name.clone(), binding.field.clone()));
                // The variable bound in the item URL — as opposed to one
                // that merely repeats a parent-scoping context variable
                // this resource's own collections also carry — is this
                // resource's own id field.
                let is_own_identity = item_url.contains(&format!("{{{param}}}"))
                    && !collection_url_has(resource, param);
                if is_own_identity {
                    id_field.clone_from(&binding.field);
                    identity_params.push(param.clone());
                }
            }
        }

        let Some(resource_collections) = &resource.collections else {
            continue;
        };
        for (name, collection) in resource_collections {
            collection_of_resource
                .entry(resource_name.clone())
                .or_insert_with(|| name.clone());

            let list_query = collection
                .list_query
                .iter()
                .flatten()
                .map(|(key, value)| (key.clone(), stringify(value)))
                .collect();

            collections.push(ManagedCollection {
                name: name.clone(),
                resource: resource_name.clone(),
                collection_url: collection.url_template.clone(),
                item_url: item_url.to_string(),
                id_field: id_field.clone(),
                context_params: path_variables(&collection.url_template),
                identity_params: identity_params.clone(),
                list_query,
            });
        }
    }

    let mut providers = IndexMap::new();
    for (param, resource_name, field) in bindings {
        // A resource can supply a context value only if it is itself
        // enumerable (has a managed collection).
        if let Some(collection) = collection_of_resource.get(&resource_name) {
            providers.entry(param).or_insert_with(|| ContextProvider {
                collection: collection.clone(),
                field,
            });
        }
    }

    Ok(ResourceModel {
        collections,
        providers,
    })
}

// --- `x-crud`, the operation-level half of the extension -------------------

/// Which CRUD action an operation performs, from its `x-crud.action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrudAction {
    /// Lists a collection's items.
    List,
    /// Reads one item.
    Read,
    /// Creates an item.
    Create,
    /// Updates an item.
    Update,
    /// Deletes an item.
    Delete,
}

/// One field a create response adds beyond what the client sent — read back
/// from the response and merged into the record. GitHub's issue `number` is
/// server-assigned this way; the client never supplies it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddedField {
    /// The field's schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaObject>,
    /// Where the field's value comes from, e.g. `server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Any other key on the added field.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// Which collections a write affects, from `memberOf`/`removesFrom`: either
/// a fixed list of collection names, or every collection the resource
/// belongs to (`"*"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionMembership {
    /// Only the named collections.
    Named(Vec<String>),
    /// Every collection the resource belongs to.
    All,
}

impl Serialize for CollectionMembership {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            CollectionMembership::Named(names) => names.serialize(serializer),
            CollectionMembership::All => serializer.serialize_str("*"),
        }
    }
}

impl<'de> Deserialize<'de> for CollectionMembership {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::String(marker) if marker == "*" => Ok(CollectionMembership::All),
            value @ Value::Array(_) => {
                let names = Vec::<String>::deserialize(value).map_err(D::Error::custom)?;
                Ok(CollectionMembership::Named(names))
            }
            other => Err(D::Error::custom(format!(
                "expected \"*\" or an array of collection names, got {other}"
            ))),
        }
    }
}

/// The `x-crud` annotation on one operation, declaring what it does in
/// terms of the resource model rather than of any particular API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrudOperation {
    /// Which action the operation performs.
    pub action: CrudAction,
    /// The resource this operation concerns, e.g. `issue`.
    pub resource: String,
    /// The collection a `list` operation reads, or a `create` adds to via
    /// `url.source: template`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    /// How an `update` is sent — GitHub exposes PATCH and no PUT for
    /// issues, so this is `patch` rather than the default PUT semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// How a PATCH body is interpreted, e.g. `merge`.
    #[serde(
        rename = "patchFormat",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub patch_format: Option<String>,
    /// Fields a `create` response adds beyond what the client sent.
    #[serde(rename = "addedFields", default)]
    pub added_fields: IndexMap<String, AddedField>,
    /// Collections a `create` adds the new record to.
    #[serde(rename = "memberOf", default)]
    pub member_of: Vec<String>,
    /// Collections a `delete` removes the record from.
    #[serde(
        rename = "removesFrom",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub removes_from: Option<CollectionMembership>,
    /// Any other key on the annotation.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// Reads the `x-crud` annotation off one operation, if it declares one.
pub fn crud_operation(operation: &OperationObject) -> Result<Option<CrudOperation>> {
    operation
        .extensions
        .get("x-crud")
        .map(|raw| serde_json::from_value(raw.clone()).map_err(Error::from))
        .transpose()
}
