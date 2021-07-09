//! Functions for interacting with an Atomic Server
use url::Url;

use crate::{Resource, Storelike, errors::AtomicResult, parse::parse_json_ad_resource};

/// Fetches a resource, makes sure its subject matches.
/// Checks the datatypes for the Values.
/// Ignores all atoms where the subject is different.
/// WARNING: Calls store methods, and is called by store methods, might get stuck in a loop!
pub fn fetch_resource(subject: &str, store: &impl Storelike) -> AtomicResult<Resource> {
    let body = fetch_body(subject, crate::parse::JSON_AD_MIME)?;
    let resource = parse_json_ad_resource(&body, store).map_err(|e| format!("Error parsing body of {}: {}", subject, e))?;
    Ok(resource)
}

/// Fetches a URL, returns its body
pub fn fetch_body(url: &str, content_type: &str) -> AtomicResult<String> {
    if !url.starts_with("http") {
        return Err(format!("Could not fetch url '{}', must start with http.", url).into());
    }
    let resp = ureq::get(&url)
        .set("Accept", content_type)
        .timeout_read(2000)
        .call();
    if resp.status() != 200 {
        return Err(format!("Could not fetch url '{}'. Status: {}", url, resp.status()).into());
    };
    let body = resp
        .into_string()
        .map_err(|e| format!("Could not parse response {}: {}", url, e))?;
    Ok(body)
}

/// Uses a TPF endpoint, fetches the atoms.
pub fn fetch_tpf(
    endpoint: &str,
    q_subject: Option<&str>,
    q_property: Option<&str>,
    q_value: Option<&str>,
) -> AtomicResult<String> {
    let mut url = Url::parse(endpoint)?;
    if let Some(val) = q_subject {
        url.query_pairs_mut().append_pair("subject", val);
    }
    if let Some(val) = q_property {
        url.query_pairs_mut().append_pair("property", val);
    }
    if let Some(val) = q_value {
        url.query_pairs_mut().append_pair("value", val);
    }
    fetch_body(url.as_str(), "application/n-triples")
}

/// Posts a Commit to the endpoint of the Subject from the Commit
pub fn post_commit(commit: &crate::Commit, store: &impl Storelike) -> AtomicResult<()> {
    let base_url = crate::url_helpers::base_url(commit.get_subject())?;
    // Default Commit endpoint is `https://example.com/commit`
    let endpoint = format!("{}commit", base_url);
    post_commit_custom_endpoint(&endpoint, commit, store)
}

/// Posts a Commit to an endpoint
/// Default commit endpoint is `https://example.com/commit`
pub fn post_commit_custom_endpoint(
    endpoint: &str,
    commit: &crate::Commit,
    store: &impl Storelike,
) -> AtomicResult<()> {
    let json = commit.clone().into_resource(store)?.to_json_ad()?;

    let resp = ureq::post(&endpoint)
        .set("Content-Type", "application/json")
        .timeout_read(2000)
        .send_string(&json);

    if resp.error() {
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
        let resource = fetch_resource(crate::urls::SHORTNAME, &store).unwrap();
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
