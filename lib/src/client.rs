//! Functions for interacting with an Atomic Server
use url::Url;

use crate::{Resource, ResourceString, Storelike, errors::AtomicResult, parse::parse_ad3};

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
/// Checks the datatypes for the Values.
/// Ignores all atoms where the subject is different.
/// WARNING: Calls store methods, and is called by store methods, might get stuck in a loop!
pub fn fetch_resource(subject: &str, store: &impl Storelike) -> AtomicResult<Resource> {
    let atoms = fetch_basic(subject)?;
    let mut resource = Resource::new(subject.into());
    println!("!!!!!!!!!!!!! inside fetch {}", subject);
    for atom in atoms {
        if atom.subject == subject {
            resource.set_propval_string(atom.property, &atom.value, store)?;
        }
    }
    if resource.get_propvals().is_empty() {
        return Err("No valid atoms in resource".into());
    }
    println!("!!!!!!!!!!!!! outside fetch {}", subject);
    Ok(resource)
}

/// Fetches a resource, makes sure its subject matches.
/// Checks the datatypes for the Values.
/// Ignores all atoms where the subject is different.
pub fn fetch_resource_string(subject: &str) -> AtomicResult<ResourceString> {
    let atoms = fetch_basic(subject)?;
    let mut resource = ResourceString::new();
    println!("inside fetch {}", subject);
    for atom in atoms {
        if atom.subject == subject {
            resource.insert(atom.property, atom.value);
        }
    }
    if resource.is_empty() {
        return Err("No valid atoms in resource".into());
    }
    println!("done fetch {}", subject);
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
        let store = crate::Store::init().unwrap();
        let resource = fetch_resource(crate::urls::SHORTNAME, &store).unwrap();
        let shortname = resource.get(crate::urls::SHORTNAME).unwrap();
        assert!(shortname.to_string() == "shortname");
    }

    #[test]
    #[ignore]
    fn post_commit_basic() {

        // let store = Store::init().unwrap();
        // TODO actually make this work
        // let commit = crate::commit::CommitBuilder::new("subject".into())
        //     .sign(&agent)
        //     .unwrap();
        // post_commit(&commit).unwrap();
    }
}
