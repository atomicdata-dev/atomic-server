use super::js_runtime::{embedded_runtime, PluginHost};
use serde_json::{json, Value};
struct Host;
#[async_trait::async_trait]
impl PluginHost for Host {
    async fn fetch(&mut self, request: String) -> Result<String, String> {
        let r: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(r["method"], "GET");
        assert_eq!(r["headers"]["X-Api-Key"], "secret:clockify");
        let body = match r["operation"].as_str().unwrap() {
            "user" => {
                json!({"id":"bbbbbbbbbbbbbbbbbbbbbbbb", "name":"Test Person", "email":"private@example.test"})
            }
            "workspaces" => {
                json!([{"id":"aaaaaaaaaaaaaaaaaaaaaaaa", "name":"Test workspace", "memberships":["private"]}])
            }
            "projects" => json!([{ "id": "cccccccccccccccccccccccc", "name": "Project" }]),
            "entries" => {
                json!([{ "id": "dddddddddddddddddddddddd", "userId": "bbbbbbbbbbbbbbbbbbbbbbbb", "projectId": "cccccccccccccccccccccccc", "description": "Fixture entry", "billable": true, "timeInterval": {"start": "2026-09-02T08:00:00Z", "end": "2026-09-02T09:00:00Z"} }])
            }
            _ => return Err("undeclared fixture operation".into()),
        };
        Ok(json!({"status": 200, "body": body.to_string()}).to_string())
    }
    async fn get_resource(&mut self, _: String) -> Result<String, String> {
        Err("unused".into())
    }
    async fn query(&mut self, _: String, _: String) -> Result<String, String> {
        Ok("[]".into())
    }
}
#[actix_rt::test]
async fn completed_entries_are_proposals_in_the_real_sandbox() {
    let config = json!({"workspace":"aaaaaaaaaaaaaaaaaaaaaaaa", "user":"bbbbbbbbbbbbbbbbbbbbbbbb", "userName":"Test Person", "drive":"https://test/drive", "table":"https://test/table", "rowClass":"https://test/row", "projectClass":"https://test/project", "personClass":"https://test/person", "start":"2026-09-01T00:00:00Z", "end":"2026-09-08T00:00:00Z", "properties":{"start":"start","end":"end","project":"project","person":"person","billable":"billable","identity":"identity"}});
    let source = format!(
        "{}\nconst settings={config};",
        include_str!("../../../integrations/clockify/plugin.js")
    );
    let result = embedded_runtime()
        .unwrap()
        .run(&source, r#"{"trigger":{"kind":"manual","at":1}}"#, Host)
        .await
        .unwrap()
        .unwrap();
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["intents"].as_array().unwrap().len(), 3);
    let row = result["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["localId"] == "entry-dddddddddddddddddddddddd")
        .unwrap();
    assert_eq!(
        row["set"]["project"],
        "local:project-cccccccccccccccccccccccc"
    );
    assert_eq!(
        row["set"]["end"].as_i64().unwrap() - row["set"]["start"].as_i64().unwrap(),
        3_600_000
    );
}

#[actix_rt::test]
async fn discovery_runs_in_the_real_sandbox_and_minimizes_output() {
    let output = embedded_runtime()
        .unwrap()
        .run(
            include_str!("../../../integrations/clockify/plugin.js"),
            r#"{"phase":"discover","trigger":{"kind":"manual","at":1}}"#,
            Host,
        )
        .await
        .unwrap()
        .unwrap();
    let output: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(output["intents"], json!([]));
    assert_eq!(
        output["discovery"],
        json!({
            "user":{"id":"bbbbbbbbbbbbbbbbbbbbbbbb", "name":"Test Person"},
            "workspaces":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaa", "name":"Test workspace"}],
        })
    );
}
