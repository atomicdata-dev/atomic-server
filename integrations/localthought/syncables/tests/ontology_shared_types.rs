//! Heterogeneous API records must retain shared fields without imposing the
//! first collection's scalar datatype on the rest of the dataset.
use serde_json::json;
use syncables::{derive_ontology, load_open_api_document};

#[tokio::test]
async fn shared_fields_use_json_when_resource_datatypes_disagree() {
    let doc = load_open_api_document(json!({
        "openapi":"3.0.3", "info":{"title":"Mixed records","version":"1"},
        "paths":{}, "components":{
            "schemas":{
                "invoice":{"type":"object","properties":{
                    "id":{"type":"string"},"amount":{"type":"string"},
                    "updated_at":{"type":"string","format":"date-time"}}},
                "entry":{"type":"object","properties":{
                    "id":{"oneOf":[{"type":"string"},{"type":"integer"}]},
                    "amount":{"type":"number"},
                    "updated_at":{"type":"string","format":"date-time"}}}
            },
            "crudResources":{
                "invoice":{"schema":{"$ref":"#/components/schemas/invoice"}},
                "entry":{"schema":{"$ref":"#/components/schemas/entry"}}
            }
        }
    }))
    .await
    .unwrap();
    let ontology = derive_ontology(&doc).unwrap();
    for name in ["id", "amount"] {
        let term = ontology.terms.iter().find(|t| t.shortname == name).unwrap();
        assert_eq!(
            term.datatype, None,
            "{name} must retain both representations as JSON"
        );
    }
    let updated = ontology
        .terms
        .iter()
        .find(|t| t.shortname == "updated-at")
        .unwrap();
    assert_eq!(
        updated.datatype.as_deref(),
        Some("https://atomicdata.dev/datatypes/timestamp")
    );
}
