//! `GET /history-attribution?subject=` — the signed-envelope attribution of a
//! resource's history (`atomic_lib::envelopes`), read-gated like the resource.
//!
//! Run: cargo test -p atomic-server --test it history_attribution

use atomic_lib::{client::connected::Client, errors::AtomicResult};

use crate::common::{start_server, wait_for_server};

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn fetch_attribution(
    server_url: &str,
    subject: &str,
    agent: Option<&atomic_lib::agents::Agent>,
) -> AtomicResult<(u16, serde_json::Value)> {
    let url = format!(
        "{server_url}/history-attribution?subject={}",
        url_encode(subject)
    );
    let mut req = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json");
    if let Some(agent) = agent {
        for (k, v) in atomic_lib::client::get_authentication_headers(&url, agent)? {
            req = req.header(k, v);
        }
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}

#[tokio::test]
async fn history_attribution_names_the_verified_signer_and_gates_on_read() -> AtomicResult<()> {
    let port = start_server("history_attribution");
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{port}");

    let client = Client::new(&server_url).await?;
    let alice = client.new_agent("Alice").await?;
    // A private drive: only Alice may read what is in it.
    let drive = client.new_drive(&alice, "Attribution Drive").await?;

    let mut resource = client.new_resource(&drive)?;
    resource.set_name("Attributed")?;
    resource.set_unsafe(
        atomic_lib::urls::IS_A.into(),
        atomic_lib::Value::ResourceArray(vec![atomic_lib::urls::CLASS.into()]),
    )?;
    resource.set_unsafe(
        atomic_lib::urls::SHORTNAME.into(),
        atomic_lib::Value::Slug("attributed".into()),
    )?;
    resource.set_unsafe(
        atomic_lib::urls::DESCRIPTION.into(),
        atomic_lib::Value::String("signed by Alice".into()),
    )?;
    let subject = resource.save_remote(client.store()).await?;

    // The signer sees her own envelope, verified by the server.
    let (status, report) = fetch_attribution(&server_url, &subject, Some(&alice)).await?;
    assert_eq!(status, 200, "owner may read attribution: {report}");
    let attributions = report["attributions"]
        .as_array()
        .expect("attributions array");
    assert!(!attributions.is_empty(), "the genesis envelope is retained");
    let last = attributions.last().unwrap();
    assert_eq!(last["signer"], alice.subject.to_string());
    assert_eq!(last["verified"], true);
    assert_eq!(report["retention"], "latest");
    assert!(
        last["tokens"].as_array().is_some_and(|t| !t.is_empty()),
        "the envelope names the Loro change it introduced: {last}"
    );

    // A stranger is refused, exactly like the resource itself.
    let mallory = client.new_agent("Mallory").await?;
    let (status, _) = fetch_attribution(&server_url, &subject, Some(&mallory)).await?;
    assert_ne!(
        status, 200,
        "a stranger must not read a private resource's attribution"
    );

    // So is an anonymous request.
    let (status, _) = fetch_attribution(&server_url, &subject, None).await?;
    assert_ne!(
        status, 200,
        "anonymous must not read a private resource's attribution"
    );

    Ok(())
}
