//! Syncables transport and preview storage. No graph writes happen while fetching.
use super::integration_proxy::{client, secret_key, Connection};
use crate::errors::AtomicServerResult as Result;
use atomic_lib::{db::plugin_secret::PluginSecret, Db};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex},
};
use syncables::{
    client::client::{Fetch, HttpRequest, HttpResponse},
    ontology_shortname, ClientConfig, Credentials, Ontology, Record, Storage, StorageError,
    SyncClient, TermKind,
};

struct ProxyTransport {
    db: Db,
    connection: Connection,
    id: String,
    upstream: url::Url,
    requests: Mutex<usize>,
}
#[async_trait::async_trait]
impl Fetch for ProxyTransport {
    async fn fetch(&self, request: HttpRequest) -> syncables::Result<HttpResponse> {
        let error = |message: &str| syncables::Error::Http(message.into());
        let target =
            url::Url::parse(&request.url).map_err(|_| error("Invalid OpenAPI request URL"))?;
        if request.method != "GET"
            || target.origin() != self.upstream.origin()
            || !target.username().is_empty()
            || target.password().is_some()
            || target.fragment().is_some()
        {
            return Err(error(
                "Only read requests to the catalog API origin are allowed",
            ));
        }
        {
            let mut count = self
                .requests
                .lock()
                .map_err(|_| error("Request counter failed"))?;
            *count += 1;
            if *count > 200 {
                return Err(error("Import exceeds 200 requests; narrow its scope"));
            }
        }
        let c = &self.connection;
        let mut proxy = url::Url::parse(&format!(
            "{}/proxy/{}{}",
            c.origin,
            c.platform,
            target.path()
        ))
        .map_err(|_| error("Invalid proxy URL"))?;
        proxy.set_query(target.query());
        let key = secret_key(c, &self.id);
        let request = client()
            .map_err(|_| error("Could not initialize proxy client"))?
            .get(proxy);
        let request = self
            .db
            .use_plugin_secret(&key, &c.origin, atomic_lib::utils::now(), |code| {
                request.bearer_auth(code)
            })
            .map_err(|_| error("Could not read connection credential"))?
            .ok_or_else(|| error("Reconnect your account before fetching again"))?;
        self.db
            .delete_plugin_secret(&key)
            .map_err(|_| error("Could not consume connection code"))?;
        self.db
            .flush()
            .map_err(|_| error("Could not persist consumed code"))?;
        let mut response = request
            .send()
            .await
            .map_err(|_| error("Proxy request failed; reconnect before retrying"))?;
        if let Some(next) = response
            .headers()
            .get("x-connection-code")
            .and_then(|v| v.to_str().ok())
        {
            self.db
                .set_plugin_secret(
                    &key,
                    &PluginSecret::new(
                        next.to_string(),
                        vec![c.origin.clone()],
                        atomic_lib::utils::now(),
                    ),
                )
                .map_err(|_| error("Could not save rotated code; reconnect"))?;
            self.db
                .flush()
                .map_err(|_| error("Could not persist rotated code; reconnect"))?;
        }
        let status = response.status().as_u16();
        // Preserve pagination headers. Never expose the rotated credential to Syncables or the browser.
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str() != "x-connection-code")
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| error("Could not read provider response"))?
        {
            if body.len() + chunk.len() > 10 * 1024 * 1024 {
                return Err(error("Provider page exceeds 10 MB"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
#[derive(Default)]
struct PreviewStorage {
    records: Mutex<Vec<Record>>,
    ontology: Mutex<Option<Ontology>>,
}
#[async_trait::async_trait]
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
pub(super) async fn sync(
    db: Db,
    c: Connection,
    id: String,
    constants: BTreeMap<String, String>,
) -> Result<Value> {
    let file = load_document(&c.origin, &c.platform).await?;
    let document = syncables::load_open_api_document(file.path())
        .await
        .map_err(|e| e.to_string())?;
    let upstream = url::Url::parse(
        syncables::base_url(&document).ok_or("OpenAPI document has no API server")?,
    )
    .map_err(|_| "Invalid OpenAPI server URL")?;
    let platform = c.platform.clone();
    let fetch = ProxyTransport {
        db,
        connection: c,
        id,
        upstream,
        requests: Mutex::new(0),
    };
    let engine = SyncClient::new(
        ClientConfig {
            document: file.path().into(),
            overlays: vec![],
            credentials: Credentials::Anonymous,
            constants,
            ontology_base_url: format!("https://atomicdata.dev/integrations/{platform}"),
        },
        Arc::new(fetch),
    )
    .map_err(|e| e.to_string())?;
    let storage = PreviewStorage::default();
    let report = tokio::time::timeout(std::time::Duration::from_secs(120), engine.sync(&storage))
        .await
        .map_err(|_| "Import timed out; no partial data was proposed")?
        .map_err(|e| e.to_string())?;
    if !report.errors.is_empty() {
        return Err(format!(
            "Import incomplete; no changes proposed: {}",
            report.errors.join("; ")
        )
        .into());
    }
    let ontology = storage.ontology.lock().unwrap();
    let records = storage.records.lock().unwrap();
    preview(
        ontology
            .as_ref()
            .ok_or("Syncables did not generate an ontology")?,
        &records,
        &platform,
    )
}

async fn load_document(base: &str, platform: &str) -> Result<tempfile::NamedTempFile> {
    let document_url = format!("{}/catalog/{}.yaml", base, platform);
    let mut response = client()?
        .get(&document_url)
        .send()
        .await
        .map_err(|_| "Could not load platform OpenAPI document")?;
    if !response.status().is_success() {
        return Err(format!(
            "Platform OpenAPI document returned HTTP {} at {document_url}",
            response.status().as_u16()
        )
        .into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Could not read OpenAPI document")?
    {
        if bytes.len() + chunk.len() > 10 * 1024 * 1024 {
            return Err("OpenAPI document exceeds 10 MB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let mut file =
        tempfile::NamedTempFile::new().map_err(|_| "Could not create temporary OpenAPI file")?;
    file.write_all(&bytes)
        .map_err(|_| "Could not store temporary OpenAPI document")?;
    Ok(file)
}

pub(super) async fn describe(base: &str, platform: &str) -> Result<Value> {
    let file = load_document(base, platform).await?;
    let doc = syncables::load_open_api_document(file.path())
        .await
        .map_err(|e| e.to_string())?;
    let model = syncables::discover_resource_model(&doc).map_err(|e| e.to_string())?;
    let parameters: std::collections::BTreeSet<_> = model
        .collections
        .iter()
        .flat_map(|c| c.context_params.iter())
        .filter(|p| model.provider_for(p).is_none())
        .cloned()
        .collect();
    let collections: Vec<_> = model.collections.iter().map(|c| c.name.clone()).collect();
    Ok(json!({"parameters": parameters, "collections": collections}))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Pages(Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl Fetch for Pages {
        async fn fetch(&self, req: HttpRequest) -> syncables::Result<HttpResponse> {
            self.0.lock().unwrap().push(req.url.clone());
            let second = req.url.ends_with("?page=2");
            let headers = if second {
                Default::default()
            } else {
                [(
                    "link".into(),
                    "<https://pets.example/pets?page=2>; rel=\"next\"".into(),
                )]
                .into()
            };
            let body = json!([{ "id": if second {2} else {1}, "name": if second {"Whiskers"} else {"Rex"}, "age":3,"vaccinated":true,"weight":2.5,"updated_at":"2026-09-09T00:00:00Z" }]);
            Ok(HttpResponse {
                status: 200,
                headers,
                body: serde_json::to_vec(&body).unwrap(),
            })
        }
    }
    #[tokio::test]
    async fn syncables_walks_catalog_pages_and_generates_typed_ontology() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(include_bytes!(
            "../../../integrations/localthought/mock-document.json"
        ))
        .unwrap();
        let transport = Arc::new(Pages(Mutex::new(vec![])));
        let client = SyncClient::new(
            ClientConfig {
                document: file.path().into(),
                overlays: vec![],
                credentials: Credentials::Anonymous,
                constants: BTreeMap::new(),
                ontology_base_url: "https://example.com/ontology".into(),
            },
            transport.clone(),
        )
        .unwrap();
        let storage = PreviewStorage::default();
        let report = client.sync(&storage).await.unwrap();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.read["pet"], 2);
        assert_eq!(
            transport.0.lock().unwrap().as_slice(),
            &[
                "https://pets.example/pets",
                "https://pets.example/pets?page=2"
            ]
        );
        let ontology = storage.ontology.lock().unwrap();
        let records = storage.records.lock().unwrap();
        let output = preview(ontology.as_ref().unwrap(), &records, "pets").unwrap();
        assert_eq!(output["records"][0]["values"]["age"], 3);
        assert_eq!(output["records"][0]["values"]["vaccinated"], true);
        assert_eq!(
            output["records"][0]["values"]["updated-at"],
            1788912000000i64
        );
        let age = output["ontology"]["terms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["shortname"] == "age")
            .unwrap();
        assert_eq!(age["datatype"], "https://atomicdata.dev/datatypes/integer");
    }
    #[tokio::test]
    async fn duplicate_pages_are_an_error_not_a_successful_partial_import() {
        let storage = PreviewStorage::default();
        let row = Record {
            namespace: "".into(),
            resource: "pet".into(),
            id: "1".into(),
            value: Default::default(),
        };
        storage.put(&row).await.unwrap();
        assert!(storage.put(&row).await.is_err());
    }
}
