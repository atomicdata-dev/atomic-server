use crate::{Commit, Resource, Storelike, endpoints::Endpoint, errors::AtomicResult, urls};

pub fn handle_version_request(url: url::Url, store: &impl Storelike) -> AtomicResult<Resource> {
    let params = url.query_pairs();

    let mut commit_url = None;

    for (k, v) in params {
        if let "commit" = k.as_ref() { commit_url = Some(v.to_string()) };
    }

    if commit_url.is_none() {
        // return Err("No commit query param has been passed".into())
        return versioning_endpoint().to_resource(store)
    }

    construct_version(&commit_url.unwrap(), store)
}

pub fn versioning_endpoint() -> Endpoint {

    let params = Vec::new();
    // params.push();

    Endpoint {
        path: "/versioning".to_string(),
        params,
        description: "Constructs a version of a resource from a commit".to_string(),
        shortname: "versioning".to_string(),
        // handler: handle_version_request,
    }
}

/// Searches the local store for all commits with this subject
pub fn get_commits_for_resource(
    subject: &str,
    store: &impl Storelike,
) -> AtomicResult<Vec<Commit>> {
    let commit_atoms = store.tpf(None, Some(urls::SUBJECT), Some(subject))?;
    let mut commit_resources = Vec::new();
    for atom in commit_atoms {
        let commit = crate::Commit::from_resource(store.get_resource(&atom.subject)?)?;
        commit_resources.push(commit)
    }
    Ok(commit_resources)
}

// /// Returns a list of all version_urls for a resource. Uses the `/versioning` api
// pub fn get_version_list(store: &impl Storelike, subject: &str) -> AtomicResult<Vec<String>> {
//   let commits = get_commits_for_resource(store, subject)?;
//   for com
//   Ok(subjects)
// }

/// Constructs a Resource version for a specific Commit
/// Only works if the current store has the required Commits
pub fn construct_version(commit_url: &str, store: &impl Storelike) -> AtomicResult<Resource> {
    let commit = store.get_resource(commit_url)?;
    // Get all the commits for the subject of that Commit
    let subject = &commit.get(urls::SUBJECT)?.to_string();
    let mut commits = get_commits_for_resource(subject, store)?;
    // Sort all commits by date
    commits.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    // We create a backup of the current resource.
    let backup = store.get_resource(subject)?;
    // Warning: if the below code returns an error while stuck mid-commit, we currently fail to put our backup back!
    // try {
    store.remove_resource(subject)?;
    for commit in commits {
        if let Some(current_commit) = commit.url.clone() {
            // We skip unnecassary checks
            // TODO: maybe do some caching here? Seems more logical than caching the get_version. Maybe this function will become recursive.
            commit.apply_unsafe(store)?;
            // Stop iterating when the target commit has been applied.
            if current_commit == commit_url {
                break;
            }
        }
    }
    let version = store.get_resource(&subject.to_string())?;
// }
    // Put back the backup
    store.add_resource(&backup)?;
    Ok(version)
}

/// Gets a version of a Resource by Commit.
/// Tries cached version, constructs one if there is no cached version.
pub fn get_version(commit_url: &str, store: &impl Storelike) -> AtomicResult<Resource> {
    let version_url = format!("{}/versioning?commit={}", store.get_base_url(), commit_url);
    match store.get_resource(&version_url) {
        Ok(cached) => Ok(cached),
        Err(_not_cached) => {
            let version = construct_version(commit_url, store)?;
            // Store constructed version for caching
            store.add_resource(&version)?;
            Ok(version)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{Resource, Store};
    use super::*;

    #[test]
    fn gets_all_versions() {
        let store = Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent("my_agent").unwrap();
        store.set_default_agent(agent.clone());
        store.get_resource(&agent.subject).unwrap();
        let subject = "http://localhost/myresource";
        let mut resource = Resource::new(subject.to_string());
        let first_val = "Hi world";
        resource
            .set_propval_string(crate::urls::DESCRIPTION.into(), first_val, &store)
            .unwrap();
        let first_commit = resource.save_locally(&store).unwrap();

        let second_val = "Hello universe";
        resource
            .set_propval_string(crate::urls::DESCRIPTION.into(), second_val, &store)
            .unwrap();
        let second_commit = resource.save_locally(&store).unwrap();
        let commits = get_commits_for_resource(&subject, &store).unwrap();
        assert_eq!(commits.len(), 2);

        let first_version = construct_version(first_commit.get_subject(), &store).unwrap();
        assert_eq!(
            first_version
                .get_shortname("description", &store)
                .unwrap()
                .to_string(),
            first_val
        );

        let second_version = construct_version(second_commit.get_subject(), &store).unwrap();
        assert_eq!(
            second_version
                .get_shortname("description", &store)
                .unwrap()
                .to_string(),
            second_val
        );
    }
}
