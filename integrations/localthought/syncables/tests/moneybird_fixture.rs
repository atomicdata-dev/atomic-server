//! Full generated Moneybird OAD/overlay traversal fixture.
//!
//! Set `MONEYBIRD_OAD_DIR` and `MONEYBIRD_OVERLAYS_DIR` to run it. The
//! generated provider document is intentionally maintained outside this crate.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;
use syncables::client::client::{Fetch, HttpRequest, HttpResponse};
use syncables::{ClientConfig, Credentials, InMemoryStorage, SyncClient};

#[derive(Clone, Default)]
struct MoneybirdFetch {
    requests: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Fetch for MoneybirdFetch {
    async fn fetch(&self, request: HttpRequest) -> syncables::Result<HttpResponse> {
        self.requests.lock().unwrap().push(request.url.clone());
        let body = if request.url.contains("/contacts.json") {
            r#"[{"id":"contact / one"}]"#
        } else if request.url.contains("/subscriptions.json") {
            r#"[{"id":"subscription / one","contact_id":"contact / one"}]"#
        } else if request.url.contains("moneybird_payments_mandate.json")
            || request.url.contains("/verifications.json")
        {
            r#"{"status":"ok"}"#
        } else {
            r#"[{"id":"record / one"}]"#
        };
        Ok(HttpResponse {
            status: 200,
            headers: Default::default(),
            body: body.as_bytes().to_vec(),
        })
    }
}

#[tokio::test]
#[ignore = "requires external published metadata fixtures"]
async fn every_moneybird_collection_and_linked_read_is_requested() {
    let oad_dir = std::env::var("MONEYBIRD_OAD_DIR").expect("set MONEYBIRD_OAD_DIR");
    let overlays_dir = std::env::var("MONEYBIRD_OVERLAYS_DIR").expect("set MONEYBIRD_OVERLAYS_DIR");
    let document_path = PathBuf::from(oad_dir).join("openapi.yaml");
    let overlays_dir = PathBuf::from(overlays_dir);
    let overlays = [
        "crud-causality-overlay.yaml",
        "pagination-overlay.yaml",
        "auth-overlay.yaml",
    ]
    .map(|name| overlays_dir.join(name))
    .to_vec();
    let mut document =
        syncables::load_open_api_document_with_overlays(document_path.as_path(), &overlays)
            .await
            .unwrap();
    let selection: Value = serde_json::from_slice(
        &std::fs::read(overlays_dir.join("all-records-selection.json")).unwrap(),
    )
    .unwrap();
    apply_query_overrides(&mut document, &selection);
    let model = syncables::discover_resource_model(&document).unwrap();
    assert_eq!(model.collections.len(), 32);
    assert_eq!(
        model.root_parameters(),
        ["administration_id".to_string()].into_iter().collect()
    );
    assert!(model
        .reads
        .iter()
        .any(|read| read.resource == "verification"));
    assert!(model
        .reads
        .iter()
        .any(|read| read.resource == "moneybird_payments_mandate"));

    let fetch = MoneybirdFetch::default();
    let requests = fetch.requests.clone();
    let client = SyncClient::new(
        ClientConfig {
            document: document_path,
            overlays,
            credentials: Credentials::Anonymous,
            constants: BTreeMap::from([(
                "administration_id".to_string(),
                "admin / one".to_string(),
            )]),
            ontology_base_url: "https://ontology.example/moneybird".to_string(),
        },
        Arc::new(fetch),
    )
    .unwrap();
    let report = client
        .sync_document(&document, &InMemoryStorage::new())
        .await
        .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let requests = requests.lock().unwrap();
    for collection in &model.collections {
        assert!(
            report.read.get(&collection.resource).copied().unwrap_or(0) > 0,
            "missing {}",
            collection.name
        );
    }
    assert!(requests
        .iter()
        .any(|url| url.contains("contact_id=contact%20%2F%20one")));
    assert!(requests
        .iter()
        .any(|url| url.contains("moneybird_payments_mandate.json")));
    assert!(requests
        .iter()
        .any(|url| url.contains("verifications.json")));
    for expected in [
        "assets.json?active=false",
        "contacts.json?include_archived=true",
        "products.json?active=false",
        "projects.json?filter=state:all",
        "contacts/contact%20%2F%20one/additional_charges.json?include_billed=true",
        "subscriptions/subscription%20%2F%20one/additional_charges.json?include_billed=true",
    ] {
        assert!(
            requests.iter().any(|url| url.contains(expected)),
            "missing selection {expected}"
        );
    }
}

fn apply_query_overrides(document: &mut syncables::OpenApiDocument, selection: &Value) {
    let overrides = selection["query_overrides"].as_array().unwrap();
    let resources = document
        .components
        .as_mut()
        .unwrap()
        .extensions
        .get_mut("crudResources")
        .unwrap()
        .as_object_mut()
        .unwrap();
    for resource in resources.values_mut() {
        let Some(collections) = resource["collections"].as_object_mut() else {
            continue;
        };
        for collection in collections.values_mut() {
            let path = collection["urlTemplate"].as_str().unwrap();
            if let Some(override_) = overrides.iter().find(|item| item["path"] == path) {
                collection
                    .as_object_mut()
                    .unwrap()
                    .insert("x-list-query".to_string(), override_["values"].clone());
            }
        }
    }
}
