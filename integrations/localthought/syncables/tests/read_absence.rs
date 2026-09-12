//! Declared missing-object reads must not fabricate records or hide other errors.
use async_trait::async_trait;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use syncables::{
    client::client::{Fetch, HttpRequest, HttpResponse},
    ClientConfig, Credentials, InMemoryStorage, SyncClient,
};

struct StatusFetch(u16);
#[async_trait]
impl Fetch for StatusFetch {
    async fn fetch(&self, _: HttpRequest) -> syncables::Result<HttpResponse> {
        Ok(HttpResponse {
            status: self.0,
            headers: Default::default(),
            body: b"{}".to_vec(),
        })
    }
}

#[tokio::test]
async fn declared_missing_object_is_absent_but_other_failures_are_reported() {
    for (status, declares_missing, expected_errors) in [
        (404, true, 0),
        (404, false, 1),
        (403, true, 1),
        (500, true, 1),
    ] {
        let mut document = json!({"openapi":"3.0.3","info":{"title":"Object API","version":"1"},"servers":[{"url":"https://api.example"}],"paths":{"/profile":{"get":{"operationId":"profile","x-crud":{"action":"read","resource":"profile"},"responses":{"200":{"description":"Profile","content":{"application/json":{"schema":{"type":"object"}}}}}}}},"components":{"crudResources":{"profile":{"identity":{"urlTemplate":"/profile"}}}}});
        if declares_missing {
            document["paths"]["/profile"]["get"]["responses"]["404"] =
                json!({"description":"No profile exists"});
        }
        let document = serde_json::from_value(document).unwrap();
        let client = SyncClient::new(
            ClientConfig {
                document: "unused".into(),
                overlays: vec![],
                credentials: Credentials::Anonymous,
                constants: BTreeMap::new(),
                ontology_base_url: "https://ontology.example".into(),
            },
            Arc::new(StatusFetch(status)),
        )
        .unwrap();
        let report = client
            .sync_document(&document, &InMemoryStorage::new())
            .await
            .unwrap();
        assert_eq!(
            report.errors.len(),
            expected_errors,
            "status={status}, declared={declares_missing}"
        );
        assert!(report.read.is_empty());
    }
}
