use super::js_runtime::{embedded_runtime, PluginHost};
use serde_json::{json, Value};
struct Host;
#[async_trait::async_trait]
impl PluginHost for Host {
    async fn fetch(&mut self, _: String) -> Result<String, String> {
        panic!("MT940 must never contact a provider")
    }
    async fn get_resource(&mut self, _: String) -> Result<String, String> {
        Err("unused".into())
    }
    async fn query(&mut self, _: String, _: String) -> Result<String, String> {
        Ok("[]".into())
    }
}
#[actix_rt::test]
async fn bank_statement_proposes_exact_nested_transactions() {
    let keys = [
        "account",
        "currency",
        "amount",
        "value-date",
        "booking-date",
        "description",
        "reference",
        "transaction-code",
        "statement",
        "source-id",
        "fingerprint",
    ];
    let properties: serde_json::Map<String, Value> = keys
        .into_iter()
        .map(|key| (format!("bank-{key}"), json!(format!("https://test/{key}"))))
        .collect();
    let input = json!({"text":include_str!("../../../integrations/mt940/fixtures/synthetic.mt940"), "config":{"table":"https://test/table", "rowClass":"https://test/transaction", "properties":properties}, "trigger":{"kind":"manual","at":1}});
    let result = embedded_runtime()
        .unwrap()
        .run(
            include_str!("../../../integrations/mt940/plugin.js"),
            &input.to_string(),
            Host,
        )
        .await
        .unwrap()
        .unwrap();
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["intents"].as_array().unwrap().len(), 2);
    assert_eq!(result["intents"][0]["parent"], "https://test/table");
    assert_eq!(result["intents"][0]["set"]["https://test/amount"], "-12.34");
    let invalid = input.to_string().replace("107,66", "107,67");
    let result = embedded_runtime()
        .unwrap()
        .run(
            include_str!("../../../integrations/mt940/plugin.js"),
            &invalid,
            Host,
        )
        .await
        .unwrap();
    assert!(result.unwrap_err().contains("does not reconcile"));
}
