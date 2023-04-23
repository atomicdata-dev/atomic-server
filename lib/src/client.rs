//! Functions for interacting with an Atomic Server
use crate::{
    agents::Agent,
    commit::sign_message,
    errors::AtomicResult,
    parse::{parse_json_ad_resource, ParseOpts},
    Resource, Storelike,
};

/// Fetches a resource, makes sure its subject matches.
/// Checks the datatypes for the Values.
/// Ignores all atoms where the subject is different.
/// WARNING: Calls store methods, and is called by store methods, might get stuck in a loop!
#[tracing::instrument(skip(store), level = "info")]
pub fn fetch_resource(
    subject: &str,
    store: &impl Storelike,
    for_agent: Option<Agent>,
) -> AtomicResult<Resource> {
    let body = fetch_body(subject, crate::parse::JSON_AD_MIME, for_agent)?;
    let resource = parse_json_ad_resource(&body, store, &ParseOpts::default())
        .map_err(|e| format!("Error parsing body of {}. {}", subject, e))?;
    Ok(resource)
}

/// Returns the various x-atomic authentication headers, includign agent signature
pub fn get_authentication_headers(url: &str, agent: &Agent) -> AtomicResult<Vec<(String, String)>> {
    let mut headers = Vec::new();
    let now = crate::utils::now().to_string();
    let message = format!("{} {}", url, now);
    let signature = sign_message(
        &message,
        agent
            .private_key
            .as_ref()
            .ok_or("No private key in agent")?,
        &agent.public_key,
    )?;
    headers.push(("x-atomic-public-key".into(), agent.public_key.to_string()));
    headers.push(("x-atomic-signature".into(), signature));
    headers.push(("x-atomic-timestamp".into(), now));
    headers.push(("x-atomic-agent".into(), agent.subject.to_string()));
    Ok(headers)
}

/// Fetches a URL, returns its body.
/// Uses the store's Agent agent (if set) to sign the request.
#[tracing::instrument(level = "info")]
pub fn fetch_body(url: &str, content_type: &str, for_agent: Option<Agent>) -> AtomicResult<String> {
    if !url.starts_with("http") {
        return Err(format!("Could not fetch url '{}', must start with http.", url).into());
    }
    if let Some(agent) = for_agent {
        get_authentication_headers(url, &agent)?;
    }

    let agent = ureq::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .get(url)
        .set("Accept", content_type)
        .call()
        .map_err(|e| format!("Error when server tried fetching {} : {}", url, e))?;
    let status = resp.status();
    let body = resp
        .into_string()
        .map_err(|e| format!("Could not parse HTTP response for {}: {}", url, e))?;
    if status != 200 {
        return Err(format!(
            "Could not fetch url '{}'. Status: {}. Body: {}",
            url, status, body
        )
        .into());
    };
    Ok(body)
}

/// Posts a Commit to the endpoint of the Subject from the Commit
pub fn post_commit(commit: &crate::Commit, store: &impl Storelike) -> AtomicResult<()> {
    let server_url = crate::utils::server_url(commit.get_subject())?;
    // Default Commit endpoint is `https://example.com/commit`
    let endpoint = format!("{}commit", server_url);
    post_commit_custom_endpoint(&endpoint, commit, store)
}

/// Posts a Commit to an endpoint
/// Default commit endpoint is `https://example.com/commit`
pub fn post_commit_custom_endpoint(
    endpoint: &str,
    commit: &crate::Commit,
    store: &impl Storelike,
) -> AtomicResult<()> {
    let json = commit.into_resource(store)?.to_json_ad()?;

    let agent = ureq::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build();

    let resp = agent
        .post(endpoint)
        .set("Content-Type", "application/json")
        .send_string(&json)
        .map_err(|e| format!("Error when posting commit to {} : {}", endpoint, e))?;

    if resp.status() != 200 {
        Err(format!(
            "Failed applying commit to {}. Status: {} Body: {}",
            endpoint,
            resp.status(),
            resp.into_string()?
        )
        .into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore]
    fn fetch_resource_basic() {
        let store = crate::Store::init().unwrap();
        let resource = fetch_resource(crate::urls::SHORTNAME, &store, None).unwrap();
        let shortname = resource.get(crate::urls::SHORTNAME).unwrap();
        assert!(shortname.to_string() == "shortname");
    }

    #[test]
    #[ignore]
    fn post_commit_basic() {
        // let store = Store::init().unwrap();
        // // TODO actually make this work
        // let commit = crate::commit::CommitBuilder::new("subject".into())
        //     .sign(&agent)
        //     .unwrap();
        // post_commit(&commit).unwrap();
    }
}
