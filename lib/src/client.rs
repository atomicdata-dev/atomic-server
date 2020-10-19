//! Functions for interacting with an Atomic Server
use crate::{errors::AtomicResult, parse::parse_ad3, ResourceString};

/// Fetches a resource, makes sure its subject matches.
/// Ignores all atoms where the subject is different.
pub fn fetch_resource(subject: &str) -> AtomicResult<ResourceString> {
    let resp = ureq::get(&subject)
        .set("Accept", crate::parse::AD3_MIME)
        .timeout_read(2000)
        .call();
    if resp.status() != 200 {
        return Err(format!("Could not fetch {}. Status: {}", subject, resp.status()).into());
    }
    let body = &resp
        .into_string()
        .map_err(|e| format!("Could not parse response {}: {}", subject, e))?;
    let atoms = parse_ad3(body).map_err(|e| format!("Error parsing body of {}: {}", subject, e))?;
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

/// Posts a Commit to an endpoint
pub fn post_commit(endpoint: &str, commit: &crate::Commit) -> AtomicResult<()> {
    let json = serde_json::to_string(commit)?;

    let resp = ureq::post(&endpoint)
        .set("Content-Type", "application/json")
        .timeout_read(2000)
        .send_string(&json);

    if resp.error() {
        Err(format!("Failed sending commit. Status: {} Body: {}", resp.status(), resp.into_string()?).into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test] #[ignore]
    fn fetch_resource_basic() {
        let resource = fetch_resource(crate::urls::SHORTNAME).unwrap();
        let shortname = resource.get(crate::urls::SHORTNAME).unwrap();
        assert!(shortname == "shortname");
    }

    #[test] #[ignore]
    fn post_commit_basic() {
        let commit = crate::commit::CommitBuilder::new("subject".into(), "actor".into()).sign("private_key").unwrap();
        post_commit("https://atomicdata.dev/commit", &commit).unwrap();
    }
}
