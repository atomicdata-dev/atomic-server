//! Browser Syncables bridge: catalog parsing, typed previews, no filesystem or server.
use crate::calendar_import::{scope_calendar, CalendarRange};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use syncables::{
    client::client::{Fetch, HttpRequest, HttpResponse},
    ontology_shortname, ClientConfig, Credentials, Ontology, Record, Storage, StorageError,
    SyncClient, TermKind,
};
use wasm_bindgen::prelude::*;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct BrowserFetch(js_sys::Function);
#[async_trait::async_trait(?Send)]
impl Fetch for BrowserFetch {
    async fn fetch(&self, request: HttpRequest) -> syncables::Result<HttpResponse> {
        if request.method != "GET" {
            return Err(syncables::Error::Http(
                "Browser imports only allow GET".into(),
            ));
        }
        let error =
            || syncables::Error::Http("Browser proxy request failed; reconnect if needed".into());
        let result = self
            .0
            .call1(&JsValue::NULL, &JsValue::from_str(&request.url))
            .map_err(|_| error())?;
        let value = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&result))
            .await
            .map_err(|_| error())?;
        #[derive(serde::Deserialize)]
        struct Response {
            status: u16,
            headers: BTreeMap<String, String>,
            body: String,
        }
        let value: Response =
            serde_json::from_str(&value.as_string().ok_or_else(error)?).map_err(|_| error())?;
        Ok(HttpResponse {
            status: value.status,
            headers: value.headers.into_iter().collect(),
            body: value.body.into_bytes(),
        })
    }
}
fn js_error(e: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}
async fn document(text: &str) -> std::result::Result<syncables::OpenApiDocument, JsValue> {
    let value = syncables::openapi::load::parse_yaml(text).map_err(js_error)?;
    syncables::load_open_api_document(value)
        .await
        .map_err(js_error)
}
#[wasm_bindgen(js_name = describeIntegration)]
pub async fn describe_integration(text: String) -> std::result::Result<String, JsValue> {
    let doc = document(&text).await?;
    let model = syncables::discover_resource_model(&doc).map_err(js_error)?;
    let parameters: BTreeSet<_> = model
        .collections
        .iter()
        .flat_map(|c| c.context_params.iter())
        .filter(|p| model.provider_for(p).is_none())
        .cloned()
        .collect();
    Ok(json!({"parameters": parameters, "collections": model.collections.iter().map(|c| &c.name).collect::<Vec<_>>(),
        "upstream": syncables::base_url(&doc)}).to_string())
}
#[wasm_bindgen(js_name = fetchIntegration)]
pub async fn fetch_integration(
    text: String,
    platform: String,
    constants: String,
    range: Option<String>,
    fetch: js_sys::Function,
) -> std::result::Result<String, JsValue> {
    let mut value = syncables::openapi::load::parse_yaml(&text).map_err(js_error)?;
    if let Some(range) = range {
        if platform != "google-calendar" {
            return Err(js_error("Calendar range only applies to Google Calendar"));
        }
        let range: CalendarRange = serde_json::from_str(&range).map_err(js_error)?;
        scope_calendar(&mut value, &range).map_err(js_error)?;
    }
    // Patch the raw catalog before refs are expanded into resource schemas.
    let doc = syncables::load_open_api_document(value)
        .await
        .map_err(js_error)?;
    let engine = SyncClient::new(
        ClientConfig {
            document: Default::default(),
            overlays: vec![],
            credentials: Credentials::Anonymous,
            constants: serde_json::from_str(&constants).map_err(js_error)?,
            ontology_base_url: format!("https://atomicdata.dev/integrations/{platform}"),
        },
        Arc::new(BrowserFetch(fetch)),
    )
    .map_err(js_error)?;
    let storage = PreviewStorage::default();
    let report = engine
        .sync_document(&doc, &storage)
        .await
        .map_err(js_error)?;
    if !report.errors.is_empty() {
        return Err(js_error(format!(
            "Import incomplete; no changes proposed: {}",
            report.errors.join("; ")
        )));
    }
    let ontology = storage.ontology.lock().unwrap();
    let records = storage.records.lock().unwrap();
    preview(
        ontology
            .as_ref()
            .ok_or_else(|| js_error("Missing ontology"))?,
        &records,
        &platform,
    )
    .map(|v| v.to_string())
    .map_err(js_error)
}
#[derive(Default)]
struct PreviewStorage {
    records: Mutex<Vec<Record>>,
    ontology: Mutex<Option<Ontology>>,
}
#[async_trait::async_trait(?Send)]
impl Storage for PreviewStorage {
    async fn put(&self, record: &Record) -> std::result::Result<(), StorageError> {
        let mut records = self.records.lock().unwrap();
        if records.len() >= 5000 {
            return Err(StorageError::new(
                "Import exceeds 5000 records; narrow its scope",
            ));
        }
        if record.id.is_empty()
            || records.iter().any(|r| {
                r.namespace == record.namespace
                    && r.resource == record.resource
                    && r.id == record.id
            })
        {
            return Err(StorageError::new(
                "Missing or repeated record identity; pagination may not be forwarded by the proxy",
            ));
        }
        records.push(record.clone());
        Ok(())
    }
    async fn get(
        &self,
        namespace: &str,
        resource: &str,
        id: &str,
    ) -> std::result::Result<Option<Record>, StorageError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.namespace == namespace && r.resource == resource && r.id == id)
            .cloned())
    }
    async fn list(
        &self,
        namespace: &str,
        resource: &str,
    ) -> std::result::Result<Vec<Record>, StorageError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.namespace == namespace && r.resource == resource)
            .cloned()
            .collect())
    }
    async fn delete(&self, _: &str, _: &str, _: &str) -> std::result::Result<(), StorageError> {
        Err(StorageError::new("Preview storage cannot delete records"))
    }
    async fn put_ontology(&self, ontology: &Ontology) -> std::result::Result<(), StorageError> {
        *self.ontology.lock().unwrap() = Some(ontology.clone());
        Ok(())
    }
}
fn typed_value(value: &Value, datatype: Option<&str>) -> Result<Option<Value>> {
    if value.is_null() {
        return Ok(None);
    }
    if datatype == Some("https://atomicdata.dev/datatypes/timestamp") {
        let text = value.as_str().ok_or("Expected RFC3339 timestamp")?;
        return Ok(Some(json!(chrono::DateTime::parse_from_rfc3339(text)
            .map_err(|_| "Invalid provider timestamp")?
            .timestamp_millis())));
    }
    Ok(Some(value.clone()))
}
fn preview(ontology: &Ontology, records: &[Record], platform: &str) -> Result<Value> {
    let field_terms: BTreeMap<_, _> = ontology
        .terms
        .iter()
        .filter(|t| t.kind == TermKind::Property)
        .map(|t| (t.shortname.as_str(), t))
        .collect();
    let terms: Vec<_> = ontology.terms.iter().map(|t| json!({ "path":t.path, "kind":if t.kind == TermKind::Class {"class"} else {"property"}, "shortname":t.shortname, "description":t.description, "datatype":t.datatype.as_deref().unwrap_or("https://atomicdata.dev/datatypes/json"), "requires":t.requires, "recommends":t.recommends })).collect();
    let mut output = Vec::new();
    for record in records {
        let mut values = serde_json::Map::new();
        for (key, value) in &record.value {
            let short = ontology_shortname(key);
            if let Some(term) = field_terms.get(short.as_str()) {
                if let Some(value) = typed_value(value, term.datatype.as_deref())? {
                    values.insert(short, value);
                }
            }
        }
        output.push(json!({"resource":ontology_shortname(&record.resource),"namespace":record.namespace,"id":record.id,"values":values,"name":record.value.get("title").or_else(||record.value.get("summary")).or_else(||record.value.get("name")).cloned().unwrap_or(json!(record.id))}));
    }
    Ok(
        json!({"platform":platform,"ontology":{"description":ontology.description,"terms":terms},"records":output}),
    )
}
