//! Integration coverage for response-Link-driven collection traversal.

use async_trait::async_trait;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use syncables::client::client::{Fetch, HttpRequest, HttpResponse};
use syncables::{Credentials, InMemoryStorage, Storage, SyncClient};

#[derive(Clone, Default)]
struct RecordingFetch {
    requests: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Fetch for RecordingFetch {
    async fn fetch(&self, request: HttpRequest) -> syncables::Result<HttpResponse> {
        self.requests.lock().unwrap().push(request.url.clone());
        let body = if request.url.ends_with("/administrations.json") {
            r#"[{"id":"A/one"},{"id":"B two"}]"#
        } else if request.url.contains("/A%2Fone/contacts.json")
            || request.url.contains("/B%20two/contacts.json")
        {
            r#"[{"id":"same/id"},{"name":"missing id"}]"#
        } else if request.url.contains("/subscriptions.json?") {
            r#"[{"id":"subscription"}]"#
        } else if request.url.contains("/mandate.json") {
            if request.url.contains("A%2Fone") {
                r#"{"status":"A"}"#
            } else {
                r#"{"status":"B"}"#
            }
        } else if request.url.ends_with("/verification.json") {
            r#"{"status":"ok"}"#
        } else {
            "[]"
        };
        Ok(HttpResponse {
            status: 200,
            headers: Default::default(),
            body: body.as_bytes().to_vec(),
        })
    }
}

fn document(unknown_target: bool) -> syncables::OpenApiDocument {
    let target = if unknown_target {
        "query.typo"
    } else {
        "query.contact_id"
    };
    serde_json::from_value(json!({
        "openapi":"3.0.0", "info":{"title":"Links","version":"1"}, "servers":[{"url":"https://example.test"}],
        "paths":{
            "/administrations{format}":{"get":{"operationId":"listAdministrations","parameters":[{"name":"format","in":"path"}],"responses":{"200":{"content":{"application/json":{}},"links":{"contacts":{"operationId":"listContacts","x-for-each":{"items":"","parameters":{"path.administration_id":"/id"}}}}}}}},
            "/{administration_id}/contacts{format}":{"get":{"operationId":"listContacts","parameters":[{"name":"administration_id","in":"path"},{"name":"format","in":"path"}],"responses":{"200":{"content":{"application/json":{}},"links":{"subscriptions":{"operationId":"listSubscriptions","parameters":{"path.administration_id":"$request.path.administration_id"},"x-for-each":{"items":"","parameters":{target:"/id"}}},"mandate":{"operationId":"readMandate","parameters":{"path.administration_id":"$request.path.administration_id"},"x-for-each":{"items":"","parameters":{"path.contact_id":"/id"}}}}}}}},
            "/{administration_id}/subscriptions{format}":{"get":{"operationId":"listSubscriptions","parameters":[{"name":"administration_id","in":"path"},{"name":"format","in":"path"},{"name":"contact_id","in":"query","required":true}],"responses":{"200":{"content":{"application/json":{}}}}}},
            "/{administration_id}/contacts/{contact_id}/mandate{format}":{"get":{"operationId":"readMandate","x-crud":{"action":"read","resource":"mandate"},"parameters":[{"name":"administration_id","in":"path"},{"name":"contact_id","in":"path"},{"name":"format","in":"path"}],"responses":{"200":{"content":{"application/json":{}}}}}},
            "/verification{format}":{"get":{"operationId":"readVerification","x-crud":{"action":"read","resource":"verification"},"parameters":[{"name":"format","in":"path"}],"responses":{"200":{"content":{"application/json":{}}}}}}
        },
        "components":{"crudResources":{
            "administration":{"identity":{"urlTemplate":"/administrations/{administration_id}{format}","bindings":{"administration_id":{"field":"id"}}},"collections":{"administrations":{"urlTemplate":"/administrations{format}"}}},
            "contact":{"identity":{"urlTemplate":"/{administration_id}/contacts/{contact_id}{format}","bindings":{"contact_id":{"field":"id"}}},"collections":{"contacts":{"urlTemplate":"/{administration_id}/contacts{format}"}}},
            "subscription":{"identity":{"urlTemplate":"/{administration_id}/subscriptions/{id}{format}","bindings":{"id":{"field":"id"}}},"collections":{"subscriptions":{"urlTemplate":"/{administration_id}/subscriptions{format}"}}},
            "mandate":{"identity":{"urlTemplate":"/{administration_id}/contacts/{contact_id}/mandate{format}"}},
            "verification":{"identity":{"urlTemplate":"/verification{format}"}}
        }}
    })).unwrap()
}

fn client(fetch: RecordingFetch) -> SyncClient {
    SyncClient::new(
        syncables::ClientConfig {
            document: "unused".into(),
            overlays: vec![],
            credentials: Credentials::Anonymous,
            constants: BTreeMap::from([("format".into(), ".json".into())]),
            ontology_base_url: "https://ontology.example".into(),
        },
        Arc::new(fetch),
    )
    .unwrap()
}

#[tokio::test]
async fn links_keep_request_context_and_bind_query_only_parameter_once() {
    let fetch = RecordingFetch::default();
    let requests = fetch.requests.clone();
    let storage = InMemoryStorage::new();
    let report = client(fetch)
        .sync_document(&document(false), &storage)
        .await
        .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let requests = requests.lock().unwrap();
    let urls: Vec<_> = requests
        .iter()
        .filter(|u| u.contains("subscriptions"))
        .collect();
    assert_eq!(
        urls.len(),
        2,
        "missing item fields must not reuse stale values"
    );
    assert!(urls
        .iter()
        .any(|u| u.as_str()
            == "https://example.test/A%2Fone/subscriptions.json?contact_id=same%2Fid"));
    assert!(urls
        .iter()
        .any(|u| u.as_str()
            == "https://example.test/B%20two/subscriptions.json?contact_id=same%2Fid"));
    assert!(urls
        .iter()
        .all(|u| !u.contains("%252F") && !u.contains("contact_id=same/id")));
    let mandate_urls: Vec<_> = requests
        .iter()
        .filter(|u| u.contains("mandate.json"))
        .collect();
    assert_eq!(mandate_urls.len(), 2);
    assert_eq!(report.read.get("mandate"), Some(&2));
    assert_eq!(report.read.get("verification"), Some(&1));
    let mandates = storage
        .list("A/one/same/id/.json", "mandate")
        .await
        .unwrap();
    assert_eq!(mandates[0].id, "/A%2Fone/contacts/same%2Fid/mandate.json");
}

#[tokio::test]
async fn unknown_link_target_parameter_fails_before_http() {
    let fetch = RecordingFetch::default();
    let requests = fetch.requests.clone();
    let error = client(fetch)
        .sync_document(&document(true), &InMemoryStorage::new())
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("unknown target parameter query.typo"));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_incoming_links_do_not_repeat_target_invocations() {
    let mut document = document(false);
    let response = document
        .paths
        .get_mut("/{administration_id}/contacts{format}")
        .unwrap()
        .get
        .as_mut()
        .unwrap()
        .responses
        .get_mut("200")
        .unwrap();
    let links = response.links.as_mut().unwrap();
    links.insert(
        "subscriptionsAgain".to_string(),
        links["subscriptions"].clone(),
    );
    let fetch = RecordingFetch::default();
    let requests = fetch.requests.clone();
    let report = client(fetch)
        .sync_document(&document, &InMemoryStorage::new())
        .await
        .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|url| url.contains("subscriptions"))
            .count(),
        2
    );
}

#[test]
fn root_parameters_exclude_link_and_item_identity_bindings() {
    let model = syncables::discover_resource_model(&document(false)).unwrap();
    assert_eq!(
        model.root_parameters(),
        ["format".to_string()].into_iter().collect()
    );
}

#[test]
fn standard_link_allows_an_unqualified_unique_target_parameter() {
    let mut document = document(false);
    let links = document
        .paths
        .get_mut("/{administration_id}/contacts{format}")
        .unwrap()
        .get
        .as_mut()
        .unwrap()
        .responses
        .get_mut("200")
        .unwrap()
        .links
        .as_mut()
        .unwrap();
    let item_parameters = links["subscriptions"]
        .extensions
        .get_mut("x-for-each")
        .unwrap()["parameters"]
        .as_object_mut()
        .unwrap();
    let value = item_parameters.shift_remove("query.contact_id").unwrap();
    item_parameters.insert("contact_id".to_string(), value);
    let model = syncables::discover_resource_model(&document).unwrap();
    assert!(model.links.iter().any(|link| link
        .parameters
        .contains_key(&("query".to_string(), "contact_id".to_string()))));
}

#[derive(Clone, Default)]
struct PagingFetch {
    requests: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Fetch for PagingFetch {
    async fn fetch(&self, request: HttpRequest) -> syncables::Result<HttpResponse> {
        self.requests.lock().unwrap().push(request.url.clone());
        let page = request
            .url
            .split("page=")
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        Ok(HttpResponse {
            status: 200,
            headers: Default::default(),
            body: serde_json::to_vec(&json!({"items":[{"id":page}],"page":page,"pages":51}))?,
        })
    }
}

#[tokio::test]
async fn pagination_does_not_silently_stop_at_fifty_pages() {
    let document = serde_json::from_str(r#"{
      "openapi":"3.0.0","info":{"title":"Paging","version":"1"},"servers":[{"url":"https://example.test"}],
      "paths":{"/items":{"get":{"operationId":"listItems","parameters":[{"name":"page","in":"query"}],"x-pagination":[{"scheme":"pages"}],"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"items":{"type":"array","items":{"type":"object"}},"page":{"type":"integer"},"pages":{"type":"integer"}}}}}}}}}},
      "components":{"paginationSchemes":{"pages":{"type":"pageNumber","request":{"queryParameters":{"page":{"role":"page"}}},"response":{"bodyFields":{"page":{"role":"currentPage"},"pages":{"role":"totalPages"}}}}},"crudResources":{"item":{"identity":{"urlTemplate":"/items/{id}","bindings":{"id":{"field":"id"}}},"collections":{"items":{"urlTemplate":"/items"}}}}}
    }"#).unwrap();
    let fetch = PagingFetch::default();
    let requests = fetch.requests.clone();
    let paging_client = SyncClient::new(
        syncables::ClientConfig {
            document: "unused".into(),
            overlays: vec![],
            credentials: Credentials::Anonymous,
            constants: BTreeMap::new(),
            ontology_base_url: "https://ontology.example".into(),
        },
        Arc::new(fetch),
    )
    .unwrap();
    let result = paging_client
        .sync_document(&document, &InMemoryStorage::new())
        .await
        .unwrap();
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert_eq!(result.read.get("item"), Some(&51));
    assert_eq!(requests.lock().unwrap().len(), 51);
}
