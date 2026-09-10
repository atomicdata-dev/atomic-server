//! Full generated Moneybird OAD/overlay traversal fixture.
//!
//! Set `MONEYBIRD_OAD_DIR` and `MONEYBIRD_OVERLAYS_DIR` to run it. The
//! generated provider document is intentionally maintained outside this crate.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
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
async fn every_moneybird_collection_and_linked_read_is_requested() {
    let (Ok(oad_dir), Ok(overlays_dir)) = (
        std::env::var("MONEYBIRD_OAD_DIR"),
        std::env::var("MONEYBIRD_OVERLAYS_DIR"),
    ) else {
        return;
    };
    let document_path = PathBuf::from(oad_dir).join("openapi.yaml");
    let overlays_dir = PathBuf::from(overlays_dir);
    let overlays = [
        "crud-causality-overlay.yaml",
        "pagination-overlay.yaml",
        "auth-overlay.yaml",
        "all-records-selection-overlay.yaml",
    ]
    .map(|name| overlays_dir.join(name))
    .to_vec();
    let document =
        syncables::load_open_api_document_with_overlays(document_path.as_path(), &overlays)
            .await
            .unwrap();
    let model = syncables::discover_resource_model(&document).unwrap();
    assert_eq!(model.collections.len(), 32);
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
}
