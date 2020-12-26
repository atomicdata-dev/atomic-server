//! Functions for interacting with an Atomic Server
use url::Url;

use crate::{errors::AtomicResult, parse::parse_ad3, ResourceString};

fn fetch_basic(url: &str) -> AtomicResult<Vec<crate::Atom>> {
    let resp = ureq::get(&url)
        .set("Accept", crate::parse::AD3_MIME)
        .timeout_read(2000)
        .call();
    if resp.status() != 200 {
        return Err(format!("Could not fetch {}. Status: {}", url, resp.status()).into());
    };
    let body = &resp
        .into_string()
        .map_err(|e| format!("Could not parse response {}: {}", url, e))?;
    let atoms = parse_ad3(body).map_err(|e| format!("Error parsing body of {}: {}", url, e))?;
    Ok(atoms)
}

/// Fetches a resource, makes sure its subject matches.
/// Ignores all atoms where the subject is different.
pub fn fetch_resource(subject: &str) -> AtomicResult<ResourceString> {
    let atoms = fetch_basic(subject)?;

    let mut resource = ResourceString::new();
    for atom in atoms {
        if atom.subject == subject {
            resource.insert(atom.property, atom.value);
        }
    }
    if resource.is_empty() {
        return Err("No valid atoms in resource".into());
    }
    Ok(resource)
}

/// Uses a TPF endpoint, fetches the atoms.
pub fn fetch_tpf(
    endpoint: &str,
    q_subject: Option<&str>,
    q_property: Option<&str>,
    q_value: Option<&str>,
) -> AtomicResult<Vec<crate::Atom>> {
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
    // let url = "https://atomicdata.dev/tpf?subject=&property=&value=1";
    fetch_basic(url.as_str())
}

/// Posts a Commit to the endpoint of the Subject from the Commit
pub fn post_commit(commit: &crate::Commit) -> AtomicResult<()> {
    let base_url = crate::url_helpers::base_url(commit.get_subject())?;
    // Default Commit endpoint is `https://example.com/commit`
    let endpoint = format!("{}commit", base_url);
    post_commit_custom_endpoint(&endpoint, commit)
}

/// Posts a Commit to an endpoint
/// Default commit endpoint is `https://example.com/commit`
pub fn post_commit_custom_endpoint(endpoint: &str, commit: &crate::Commit) -> AtomicResult<()> {
    let json = serde_json::to_string(commit)?;

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
        let resource = fetch_resource(crate::urls::SHORTNAME).unwrap();
        let shortname = resource.get(crate::urls::SHORTNAME).unwrap();
        assert!(shortname == "shortname");
    }

    #[test]
    #[ignore]
    fn post_commit_basic() {
        // This fails - needs actual key
        let agent = crate::agents::Agent {
            subject: "test".into(),
            key: "test".into(),
        };
        let commit = crate::commit::CommitBuilder::new("subject".into())
            .sign(&agent)
            .unwrap();
        post_commit(&commit).unwrap();
    }
}
