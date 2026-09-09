//! Deriving an Atomic Data ontology from the document's `crudResources`
//! extension, per [issue #8](https://github.com/localthought/syncables-rs/issues/8):
//! a Class per resource and a Property per field of that resource's schema.
//!
//! **This crate must not depend on `atomic_lib`.** Terms are handed over as
//! a neutral description — a path, a kind, a shortname, a description, an
//! optional datatype URL, and cross-references by path — not as Atomic Data
//! `Resource`s. Rendering those into `Resource`s at their public/internal
//! subjects is the host's job: see `AtomicStorage` in
//! [`localthought/reflector-rs`](https://github.com/localthought/reflector-rs)'s
//! `src/store.rs`, which is written against exactly this shape.
//!
//! The engine never invents an origin for a term's identity: [`Ontology`]
//! and [`OntologyTerm`] carry only relative paths (no leading slash), which
//! the host mints under its own `ClientConfig::ontology_base_url`.

use std::collections::HashSet;

use indexmap::IndexMap;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::openapi::types::{OpenApiDocument, SchemaObject};

use super::resource_model::{crud_resources, CrudResourceObject};

const DATATYPE_STRING: &str = "https://atomicdata.dev/datatypes/string";
const DATATYPE_INTEGER: &str = "https://atomicdata.dev/datatypes/integer";
const DATATYPE_FLOAT: &str = "https://atomicdata.dev/datatypes/float";
const DATATYPE_BOOLEAN: &str = "https://atomicdata.dev/datatypes/boolean";
const DATATYPE_TIMESTAMP: &str = "https://atomicdata.dev/datatypes/timestamp";
const DATATYPE_DATE: &str = "https://atomicdata.dev/datatypes/date";

/// Whether a term describes a Class or a Property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermKind {
    /// A resource, e.g. `issue`.
    Class,
    /// A field of a resource's schema, e.g. `title`.
    Property,
}

/// One term of the ontology derived from an OpenAPI document.
///
/// Paths are relative to a host-supplied base URL and are the term's
/// identity: `github-issues/property/title` is published (by the host, not
/// this crate) as e.g. `https://my-ontologies.com/github-issues/property/title`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyTerm {
    /// Path under the ontology's own path, without a leading slash.
    pub path: String,
    /// Whether this is a Class or a Property.
    pub kind: TermKind,
    /// Atomic Data shortname — lowercase, `-`-separated.
    pub shortname: String,
    /// Human-readable description.
    pub description: String,
    /// For a Property: the Atomic Data datatype URL its values carry.
    /// `None` for a Class, or for a Property whose schema type this crate's
    /// mapping can't place — omitted rather than guessed; the host falls
    /// back to inferring from the JSON value.
    pub datatype: Option<String>,
    /// For a Class: the paths (or absolute URLs) of its required
    /// properties, from the schema's `required` list.
    pub requires: Vec<String>,
    /// For a Class: the paths (or absolute URLs) of its recommended
    /// (present but not required) properties.
    pub recommends: Vec<String>,
}

/// The ontology derived from one OpenAPI document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ontology {
    /// Path of the ontology resource itself, e.g. `github-issues`.
    pub path: String,
    /// Atomic Data shortname for the ontology itself.
    pub shortname: String,
    /// Human-readable description.
    pub description: String,
    /// Every term the ontology declares, Classes and Properties mixed, in
    /// the order their resources appear in `crudResources`.
    pub terms: Vec<OntologyTerm>,
}

/// Normalizes an OpenAPI name into the Atomic Data shortname used by the
/// generated ontology: lowercase, `-`-separated, with every run of
/// non-alphanumeric characters collapsed to one `-` (`state_reason` →
/// `state-reason`, `updated_at` → `updated-at`).
///
/// Hosts use this when matching raw API record keys or resource names to the
/// ontology terms returned by [`derive_ontology`].
pub fn ontology_shortname(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut pending_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(ch.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    slug
}

/// Claims `original`'s slug in `claimed`, reusing the existing slug if
/// `original` already claimed one (properties are shared across every
/// resource that has a same-named field) and erroring if a *different*
/// name has already claimed the same slug.
fn claim_shortname(claimed: &mut IndexMap<String, String>, original: &str) -> Result<String> {
    let candidate = ontology_shortname(original);
    match claimed.get(&candidate) {
        Some(existing) if existing == original => Ok(candidate),
        Some(existing) => Err(Error::ShortnameCollision {
            shortname: candidate,
            first: existing.clone(),
            second: original.to_string(),
        }),
        None => {
            claimed.insert(candidate.clone(), original.to_string());
            Ok(candidate)
        }
    }
}

/// Maps a property schema's `type`/`format` to an Atomic Data datatype URL.
/// A type this mapping doesn't recognize is `None` rather than guessed.
fn datatype_url(schema: &SchemaObject) -> Option<String> {
    match (schema.schema_type.as_deref(), schema.format.as_deref()) {
        (Some("string"), Some("date-time")) => Some(DATATYPE_TIMESTAMP.to_string()),
        (Some("string"), Some("date")) => Some(DATATYPE_DATE.to_string()),
        (Some("string"), _) => Some(DATATYPE_STRING.to_string()),
        (Some("integer"), _) => Some(DATATYPE_INTEGER.to_string()),
        (Some("number"), _) => Some(DATATYPE_FLOAT.to_string()),
        (Some("boolean"), _) => Some(DATATYPE_BOOLEAN.to_string()),
        _ => None,
    }
}

/// A property schema's own `description`, if the document gives one — not
/// a typed field on [`SchemaObject`], so it's read from the catch-all.
fn schema_description(schema: &SchemaObject) -> Option<String> {
    schema
        .extensions
        .get("description")?
        .as_str()
        .map(str::to_string)
}

/// Resolves a `crudResources.<resource>.schema` to the [`SchemaObject`] it
/// names. The overlay declares it as a `$ref` (`{ $ref: '#/components/schemas/issue' }`)
/// — added to the document *after* `resolve_refs` already ran (overlays
/// apply on top of an already-resolved document), so it's never inlined
/// automatically and has to be resolved here by name instead. An inline
/// schema (no `$ref`) is also accepted.
fn resource_schema(
    document: &OpenApiDocument,
    resource: &CrudResourceObject,
) -> Option<SchemaObject> {
    let raw = resource.extensions.get("schema")?;
    if let Some(pointer) = raw.get("$ref").and_then(Value::as_str) {
        let name = pointer.strip_prefix("#/components/schemas/")?;
        document
            .components
            .as_ref()?
            .schemas
            .as_ref()?
            .get(name)
            .cloned()
    } else {
        serde_json::from_value(raw.clone()).ok()
    }
}

/// Derives the ontology from `document`'s `components.crudResources`: one
/// Class per resource, and one Property per field of that resource's
/// schema — shared across every resource that has a same-named field,
/// rather than minted again per resource.
///
/// Returns [`Error::NoCrudResources`] if the document declares none, and
/// [`Error::ShortnameCollision`] if two differently-named resources or
/// fields would normalize to the same slug.
pub fn derive_ontology(document: &OpenApiDocument) -> Result<Ontology> {
    let resources = crud_resources(document)?;

    let title = document.info.title.trim();
    let ontology_path = if title.is_empty() {
        "ontology".to_string()
    } else {
        ontology_shortname(title)
    };
    let description = if title.is_empty() {
        "Derived from an OpenAPI document.".to_string()
    } else {
        format!("Derived from the \"{title}\" OpenAPI document.")
    };

    let mut terms: Vec<OntologyTerm> = Vec::new();
    let mut class_shortnames = IndexMap::new();
    let mut property_shortnames = IndexMap::new();
    // shortname -> index into `terms`, so a field shared across resources
    // reuses its one Property term instead of minting a duplicate.
    let mut property_terms: IndexMap<String, usize> = IndexMap::new();

    for (resource_name, resource) in &resources {
        let class_shortname = claim_shortname(&mut class_shortnames, resource_name)?;
        let schema = resource_schema(document, resource);

        let required: HashSet<&str> = schema
            .as_ref()
            .and_then(|s| s.required.as_deref())
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();

        let mut requires = Vec::new();
        let mut recommends = Vec::new();
        for (field_name, field_schema) in schema.iter().flat_map(|s| s.properties.iter()).flatten()
        {
            // Validate the shortname (and any collision) before ever
            // consulting `property_terms`, so two different field names
            // that happen to normalize the same way can never be silently
            // merged into one reused term.
            let shortname = claim_shortname(&mut property_shortnames, field_name)?;
            let path = if let Some(&index) = property_terms.get(&shortname) {
                terms[index].path.clone()
            } else {
                let path = format!("{ontology_path}/property/{shortname}");
                property_terms.insert(shortname.clone(), terms.len());
                terms.push(OntologyTerm {
                    path: path.clone(),
                    kind: TermKind::Property,
                    shortname,
                    description: schema_description(field_schema)
                        .unwrap_or_else(|| format!("`{field_name}` of `{resource_name}`.")),
                    datatype: datatype_url(field_schema),
                    requires: Vec::new(),
                    recommends: Vec::new(),
                });
                path
            };
            if required.contains(field_name.as_str()) {
                requires.push(path);
            } else {
                recommends.push(path);
            }
        }

        terms.push(OntologyTerm {
            path: format!("{ontology_path}/class/{class_shortname}"),
            kind: TermKind::Class,
            shortname: class_shortname,
            description: resource
                .description
                .clone()
                .unwrap_or_else(|| format!("The `{resource_name}` resource.")),
            datatype: None,
            requires,
            recommends,
        });
    }

    Ok(Ontology {
        path: ontology_path.clone(),
        shortname: ontology_path,
        description,
        terms,
    })
}
