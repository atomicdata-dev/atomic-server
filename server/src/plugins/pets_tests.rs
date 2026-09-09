use super::js_runtime::{embedded_runtime, PluginHost};
use serde_json::{json, Value};
struct Host;
#[async_trait::async_trait]
impl PluginHost for Host {
    async fn fetch(&mut self, _: String) -> Result<String, String> {
        panic!("Pets is a static demo and must never contact a provider")
    }
    async fn get_resource(&mut self, _: String) -> Result<String, String> {
        Err("unused".into())
    }
    async fn query(&mut self, _: String, _: String) -> Result<String, String> {
        Ok("[]".into())
    }
}
#[actix_rt::test]
async fn demo_pets_are_proposed_in_the_real_sandbox() {
    let keys = ["species", "breed", "age", "mood", "source-id"];
    let properties: serde_json::Map<String, Value> = keys
        .into_iter()
        .map(|key| (format!("pet-{key}"), json!(format!("https://test/{key}"))))
        .collect();
    let input = json!({"config":{"table":"https://test/table", "rowClass":"https://test/pet", "properties":properties}, "trigger":{"kind":"manual","at":1}});
    let result = embedded_runtime()
        .unwrap()
        .run(
            include_str!("../../../integrations/pets/plugin.js"),
            &input.to_string(),
            Host,
        )
        .await
        .unwrap()
        .unwrap();
    let result: Value = serde_json::from_str(&result).unwrap();
    let intents = result["intents"].as_array().unwrap();
    assert_eq!(intents.len(), 5);
    assert!(intents
        .iter()
        .all(|intent| intent["op"] == "create" && intent["parent"] == "https://test/table"));
    let rex = intents
        .iter()
        .find(|intent| intent["set"]["https://atomicdata.dev/properties/name"] == "Rex")
        .unwrap();
    assert_eq!(rex["set"]["https://test/species"], "Dog");
    assert_eq!(rex["set"]["https://test/source-id"], "pets:demo:1");
    let missing_config = json!({"config":{"table":"", "rowClass":"", "properties":{}}, "trigger":{"kind":"manual","at":1}});
    let result = embedded_runtime()
        .unwrap()
        .run(
            include_str!("../../../integrations/pets/plugin.js"),
            &missing_config.to_string(),
            Host,
        )
        .await
        .unwrap();
    assert!(result.unwrap_err().contains("Configure the connection"));
}
