//! `SyncClient`: the read half of [issue #9](https://github.com/localthought/syncables-rs/issues/9)
//! — "the call reflector-rs makes." Loads the document and its overlays
//! (#2), derives the resource model (#3) and validates the configured
//! constants (#6), derives and stores the ontology (#8) before any record,
//! then walks every managed collection — following pagination to the end
//! (#4) and binding constants (#6) — putting each record into a
//! host-provided [`Storage`] (#7).
//!
//! **Local-first writes are out of scope here.** The issue explicitly
//! allows that: "Steps beyond \[the full read\] can land later." `create`/
//! `update`/`remove`, the per-record write queue and retry/backoff, and
//! reading back `x-crud`'s `addedFields` from a create response are a
//! separate, later piece of #9.
//!
//! `ClientConfig`/`SyncReport`/`SyncError` are copied field-for-field from
//! the contract [`localthought/reflector-rs`](https://github.com/localthought/reflector-rs)
//! is already written against, in its `src/syncables.rs`; that module is
//! meant to be deleted once reflector-rs points its `use`s here instead.
//! One deliberate divergence: that stub's `ClientConfig` carries no way to
//! actually reach the network, and `SyncClient::new` takes only a
//! `ClientConfig`. This crate has no HTTP client dependency (mirroring
//! [`crate::client::client`]'s existing design, where
//! [`ApiClientOptions::fetch`](crate::client::client::ApiClientOptions::fetch)
//! is the host's only extension point for making requests), so
//! [`SyncClient::new`] additionally takes a [`Fetch`] implementation.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use indexmap::IndexMap;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::{Map, Value};

use crate::client::client::{Fetch, HttpRequest};
use crate::error::Error;
use crate::openapi::overlay::load_open_api_document_with_overlays;
use crate::openapi::types::{OpenApiDocument, SchemaObject};
use crate::pagination::autodetect::resolve_effective_scheme;
use crate::pagination::items::locate_items_field;
use crate::pagination::request_builder::{build_query, next_step, PageCursor, PageStep};
use crate::pagination::response_parser::parse_pagination_state;
use crate::pagination::types::PaginationSchemeObject;

use super::constants::{bind_url, validate_constants};
use super::credentials::{base_url, Credentials};
use super::ontology::derive_ontology;
use super::resource_model::{
    discover_resource_model, ContextProvider, ManagedCollection, ResourceModel,
};
use super::storage::{Record, Storage, StorageError};

/// Everything the engine needs to derive and run a sync.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Path to the OpenAPI document describing the API.
    pub document: PathBuf,
    /// Overlays applied to that document, in order.
    pub overlays: Vec<PathBuf>,
    /// The credential sent to the API.
    pub credentials: Credentials,
    /// Values bound into the document's path and query parameters. This is
    /// what narrows a sync to one issue tracker (`owner`/`repo`) instead of
    /// every tracker the credential can reach.
    pub constants: BTreeMap<String, String>,
    /// Canonical base URL the derived ontology's terms are minted under,
    /// e.g. `https://my-ontologies.com`. No trailing slash.
    pub ontology_base_url: String,
}

/// What one [`SyncClient::sync`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Records read from the API and written to storage, per resource.
    pub read: BTreeMap<String, usize>,
    /// Ontology terms stored.
    pub ontology_terms: usize,
    /// Non-fatal problems: one collection failing does not abandon the
    /// rest of the sync.
    pub errors: Vec<String>,
}

/// Errors the engine itself raises.
#[derive(Debug)]
pub enum SyncError {
    /// The document or its overlays could not be loaded or reconciled.
    Document(String),
    /// The API rejected or failed a request.
    Transport(String),
    /// The [`Storage`] the host supplied failed.
    Storage(StorageError),
    /// This build of the engine has no behaviour behind the given call yet.
    NotImplemented(&'static str),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Document(message) => write!(f, "OpenAPI document error: {message}"),
            SyncError::Transport(message) => write!(f, "transport error: {message}"),
            SyncError::Storage(error) => write!(f, "storage error: {error}"),
            SyncError::NotImplemented(what) => write!(f, "not implemented yet: {what}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<Error> for SyncError {
    /// Every failure this crate's document/overlay/resource-model/ontology
    /// pipeline raises is, from the engine's point of view, a problem with
    /// the document or its configuration.
    fn from(error: Error) -> Self {
        SyncError::Document(error.to_string())
    }
}

/// The sync engine.
pub struct SyncClient {
    config: ClientConfig,
    fetch: Arc<dyn Fetch>,
}

impl std::fmt::Debug for SyncClient {
    /// `Fetch` implementations aren't required to be `Debug`, so this
    /// shows the configuration only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SyncClient {
    /// Builds a client for `config`, reaching the network through `fetch`.
    ///
    /// Errors if `config.ontology_base_url` is empty — ontology terms need
    /// a canonical, resolvable base URL.
    pub fn new(config: ClientConfig, fetch: Arc<dyn Fetch>) -> Result<Self, SyncError> {
        if config.ontology_base_url.is_empty() {
            return Err(SyncError::Document(
                "ontology_base_url is required: ontology terms need a canonical, resolvable base URL"
                    .to_string(),
            ));
        }
        Ok(SyncClient { config, fetch })
    }

    /// The configuration this client was built from.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Reads everything the document describes — narrowed by
    /// [`ClientConfig::constants`] — into `storage`, and stores the
    /// ontology derived from the document alongside it, before any record.
    ///
    /// One collection failing partway through — a 404, an unparseable
    /// response, a storage error — is recorded in the returned
    /// [`SyncReport::errors`] and does not abandon the rest of the sync.
    pub async fn sync(&self, storage: &dyn Storage) -> Result<SyncReport, SyncError> {
        let document = load_open_api_document_with_overlays(
            self.config.document.as_path(),
            &self.config.overlays,
        )
        .await?;
        self.sync_document(&document, storage).await
    }

    /// Sync an already loaded, resolved document without filesystem access.
    pub async fn sync_document(
        &self,
        document: &OpenApiDocument,
        storage: &dyn Storage,
    ) -> Result<SyncReport, SyncError> {
        let model = discover_resource_model(document)?;
        validate_constants(document, &model, &self.config.constants)?;

        // Fail before writing anything if there's nowhere to sync from —
        // no point minting an ontology for a sync that can't run at all.
        let base = base_url(document)
            .ok_or_else(|| SyncError::Document("document declares no servers".to_string()))?;

        let ontology = derive_ontology(document)?;
        storage
            .put_ontology(&ontology)
            .await
            .map_err(SyncError::Storage)?;

        let mut report = SyncReport {
            ontology_terms: ontology.terms.len(),
            ..SyncReport::default()
        };
        self.walk_all(document, &model, base, storage, &mut report)
            .await;
        Ok(report)
    }

    /// Walks every managed collection in dependency order: a collection
    /// whose context parameters are all constants runs once; one with a
    /// parent-record-provided parameter (see
    /// [`ResourceModel::provider_for`]) runs once per parent record
    /// already read, its own records feeding any collection nested under
    /// it in turn.
    async fn walk_all(
        &self,
        document: &OpenApiDocument,
        model: &ResourceModel,
        base: &str,
        storage: &dyn Storage,
        report: &mut SyncReport,
    ) {
        let mut records_by_collection: BTreeMap<String, Vec<Map<String, Value>>> = BTreeMap::new();
        let mut pending: Vec<&ManagedCollection> = model.collections.iter().collect();

        loop {
            let mut still_pending = Vec::new();
            let mut progressed = false;

            for collection in pending {
                let provider_params: Vec<(&str, &ContextProvider)> = collection
                    .context_params
                    .iter()
                    .filter(|param| !self.config.constants.contains_key(param.as_str()))
                    .filter_map(|param| {
                        model
                            .provider_for(param)
                            .map(|provider| (param.as_str(), provider))
                    })
                    .collect();

                let ready = provider_params
                    .iter()
                    .all(|(_, provider)| records_by_collection.contains_key(&provider.collection));
                if !ready {
                    still_pending.push(collection);
                    continue;
                }
                progressed = true;

                let mut collection_records = Vec::new();
                for values in binding_combinations(
                    &self.config.constants,
                    &provider_params,
                    &records_by_collection,
                ) {
                    match self
                        .walk_collection(document, base, collection, &values)
                        .await
                    {
                        Ok(records) => {
                            let namespace = collection
                                .context_params
                                .iter()
                                .map(|param| values.get(param).cloned().unwrap_or_default())
                                .collect::<Vec<_>>()
                                .join("/");
                            for record in &records {
                                let id = record
                                    .get(&collection.id_field)
                                    .map(json_to_string)
                                    .unwrap_or_default();
                                let stored = Record {
                                    namespace: namespace.clone(),
                                    resource: collection.resource.clone(),
                                    id,
                                    value: record.clone(),
                                };
                                if let Err(error) = storage.put(&stored).await {
                                    report.errors.push(format!("{}: {error}", collection.name));
                                }
                            }
                            collection_records.extend(records);
                        }
                        Err(message) => report
                            .errors
                            .push(format!("{}: {message}", collection.name)),
                    }
                }

                *report.read.entry(collection.resource.clone()).or_insert(0) +=
                    collection_records.len();
                records_by_collection.insert(collection.name.clone(), collection_records);
            }

            if still_pending.is_empty() {
                break;
            }
            if !progressed {
                // Unreachable once `validate_constants` has passed against
                // the same model, but never spin: report and stop rather
                // than loop forever if it somehow is.
                for collection in still_pending {
                    report.errors.push(format!(
                        "{}: could not resolve its context parameters",
                        collection.name
                    ));
                }
                break;
            }
            pending = still_pending;
        }
    }

    /// Fetches every item of one managed collection under `values`,
    /// walking every page per its resolved pagination scheme.
    async fn walk_collection(
        &self,
        document: &OpenApiDocument,
        base: &str,
        collection: &ManagedCollection,
        values: &BTreeMap<String, String>,
    ) -> std::result::Result<Vec<Map<String, Value>>, String> {
        let operation = document
            .paths
            .get(&collection.collection_url)
            .and_then(|item| item.get.as_ref())
            .ok_or_else(|| format!("{} declares no GET operation", collection.collection_url))?;

        let effective = resolve_effective_scheme(document, operation);
        let response_schema = operation
            .responses
            .get("200")
            .and_then(|response| response.content.as_ref())
            .and_then(|content| content.get("application/json"))
            .and_then(|media| media.schema.as_ref());

        let path =
            bind_url(&collection.collection_url, values).map_err(|error| error.to_string())?;

        let mut items = Vec::new();
        let mut cursor = PageCursor::default();
        let mut pages_fetched = 0usize;
        let mut next_url: Option<String> = None;

        loop {
            let request_url = if let Some(url) = next_url.take() {
                url
            } else {
                let mut query = collection.list_query.clone();
                if let Some(effective) = &effective {
                    for (name, value) in build_query(&effective.scheme, &cursor, None) {
                        query.insert(name, value);
                    }
                }
                request_url(base, &path, &query)
            };

            let mut headers = IndexMap::new();
            if let Some(authorization) = self.config.credentials.authorization_header() {
                headers.insert("Authorization".to_string(), authorization);
            }
            let diagnostic_url = redacted_request_url(&request_url);
            let response = self
                .fetch
                .fetch(HttpRequest {
                    method: "GET".to_string(),
                    url: request_url,
                    headers,
                    body: None,
                })
                .await
                .map_err(|error| error.to_string())?;

            if !(200..300).contains(&response.status) {
                return Err(format!(
                    "GET {} responded {}",
                    diagnostic_url, response.status
                ));
            }

            let body: Value =
                serde_json::from_slice(&response.body).map_err(|error| error.to_string())?;
            let page_items = response_items(
                response_schema,
                effective.as_ref().map(|e| &e.scheme),
                &body,
            )?;
            let page_count = u64::try_from(page_items.len()).unwrap_or(u64::MAX);
            items.extend(page_items);
            pages_fetched += 1;

            let Some(effective) = &effective else { break };
            let items_so_far = u64::try_from(items.len()).unwrap_or(u64::MAX);
            let state = parse_pagination_state(
                &effective.scheme,
                &body,
                &response.headers,
                Some(items_so_far),
            );
            match next_step(
                &effective.scheme,
                &cursor,
                &state,
                page_count,
                pages_fetched,
            ) {
                PageStep::Done => break,
                PageStep::NextPage(next) => cursor = next,
                PageStep::FollowLink(url) => next_url = Some(url),
            }
        }

        Ok(items)
    }
}

/// Returns a request URL that is useful in an error message without exposing
/// values sent as query parameters. Authentication normally travels in a
/// header, but OpenAPI also permits query-parameter API keys.
fn redacted_request_url(url: &str) -> String {
    match url.split_once('?') {
        Some((base, _)) => format!("{base}?<redacted>"),
        None => url.to_owned(),
    }
}

/// Every combination of constants plus one parent record's value per
/// `provider_params` entry — the cartesian product across however many
/// ancestor collections `collection` is nested under. Empty
/// `provider_params` yields exactly the constants unchanged (a root
/// collection, walked once); a provider whose collection has no records
/// yet read yields no combinations at all (nothing to nest under).
fn binding_combinations(
    constants: &BTreeMap<String, String>,
    provider_params: &[(&str, &ContextProvider)],
    records_by_collection: &BTreeMap<String, Vec<Map<String, Value>>>,
) -> Vec<BTreeMap<String, String>> {
    let mut combinations = vec![constants.clone()];
    for (param, provider) in provider_params {
        let empty = Vec::new();
        let parent_records = records_by_collection
            .get(&provider.collection)
            .unwrap_or(&empty);
        let mut next = Vec::new();
        for combination in &combinations {
            for record in parent_records {
                let Some(value) = record.get(&provider.field) else {
                    continue;
                };
                let mut extended = combination.clone();
                extended.insert((*param).to_string(), json_to_string(value));
                next.push(extended);
            }
        }
        combinations = next;
    }
    combinations
}

/// The array of item objects in a paginated response: the whole body when
/// its schema is itself an array, otherwise the property
/// [`locate_items_field`] finds.
fn response_items(
    schema: Option<&SchemaObject>,
    scheme: Option<&PaginationSchemeObject>,
    body: &Value,
) -> std::result::Result<Vec<Map<String, Value>>, String> {
    let is_bare_array = schema.and_then(|s| s.schema_type.as_deref()) == Some("array");
    let array = if is_bare_array {
        body.as_array()
    } else if let Some(field) = locate_items_field(schema, scheme) {
        body.get(&field).and_then(Value::as_array)
    } else {
        body.as_array()
    };
    let array =
        array.ok_or_else(|| "could not locate the items array in the response".to_string())?;
    Ok(array
        .iter()
        .filter_map(|item| item.as_object().cloned())
        .collect())
}

/// Renders a JSON scalar as a plain string, for use as a record id or a
/// namespace segment.
fn json_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Characters percent-encoded in a query string component — the reserved
/// characters that would otherwise be mistaken for delimiters (`&`, `=`,
/// `#`, `+`), not every non-alphanumeric character: a query parameter name
/// like `per_page` should round-trip as `per_page`, not `per%5Fpage`.
const QUERY_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'+')
    .add(b'<')
    .add(b'>')
    .add(b'=')
    .add(b'`');

/// Builds the absolute URL for one page request.
fn request_url(base: &str, path: &str, query: &IndexMap<String, String>) -> String {
    let mut url = format!("{base}{path}");
    if !query.is_empty() {
        let pairs: Vec<String> = query
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    utf8_percent_encode(name, QUERY_COMPONENT),
                    utf8_percent_encode(value, QUERY_COMPONENT)
                )
            })
            .collect();
        url.push('?');
        url.push_str(&pairs.join("&"));
    }
    url
}
