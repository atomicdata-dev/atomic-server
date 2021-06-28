use crate::{
    collections::CollectionBuilder, endpoints::Endpoint, errors::AtomicResult, urls, Commit,
    Resource, Storelike,
};

pub fn version_endpoint() -> Endpoint {
    Endpoint {
        path: "/version".to_string(),
        params: [urls::SUBJECT.to_string()].into(),
        description: "Constructs a version of a resource from a Commit URL.".to_string(),
        shortname: "versions".to_string(),
        handle: handle_version_request,
    }
}

pub fn all_versions_endpoint() -> Endpoint {
    Endpoint {
        path: "/all-versions".to_string(),
        params: [urls::SUBJECT.to_string()].into(),
        description: "Shows all versions for some resource. Constructs these using Commits."
            .to_string(),
        shortname: "all-versions".to_string(),
        handle: handle_all_versions_request,
    }
}

fn handle_version_request(url: url::Url, store: &impl Storelike) -> AtomicResult<Resource> {
    let params = url.query_pairs();
    let mut commit_url = None;
    for (k, v) in params {
        if let "commit" = k.as_ref() {
            commit_url = Some(v.to_string())
        };
    }
    if commit_url.is_none() {
        return version_endpoint().to_resource(store);
    }
    let mut resource = construct_version(&commit_url.unwrap(), store)?;
    resource.set_subject(url.to_string());
    Ok(resource)
}

fn handle_all_versions_request(url: url::Url, store: &impl Storelike) -> AtomicResult<Resource> {
    let params = url.query_pairs();
    let mut target_subject = None;
    for (k, v) in params {
        if let "subject" = k.as_ref() {
            target_subject = Some(v.to_string())
        };
    }
    if target_subject.is_none() {
        return all_versions_endpoint().to_resource(store);
    }
    let collection_builder = CollectionBuilder {
        subject: url.to_string(),
        property: Some(urls::SUBJECT.into()),
        value: Some(target_subject.unwrap()),
        sort_by: None,
        sort_desc: false,
        current_page: 0,
        page_size: 20,
    };
    let mut collection = collection_builder.into_collection(store)?;
    let new_members = collection
        .members
        .iter_mut()
        .map(|commit_url| construct_version_endpoint_url(store, commit_url))
        .collect();
    collection.members = new_members;
    collection.to_resource(store)
}

/// Searches the local store for all commits with this subject
fn get_commits_for_resource(subject: &str, store: &impl Storelike) -> AtomicResult<Vec<Commit>> {
    let commit_atoms = store.tpf(None, Some(urls::SUBJECT), Some(subject), false)?;
    let mut commit_resources = Vec::new();
    for atom in commit_atoms {
        let commit = crate::Commit::from_resource(store.get_resource(&atom.subject)?)?;
        commit_resources.push(commit)
    }
    Ok(commit_resources)
}

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

/// Creates the versioning URL for some specific Commit
fn construct_version_endpoint_url(store: &impl Storelike, commit_url: &str) -> String {
    format!(
        "{}/versioning?commit={}",
        store.get_base_url(),
        urlencoding::encode(commit_url)
    )
}

/// Gets a version of a Resource by Commit.
/// Tries cached version, constructs one if there is no cached version.
pub fn get_version(commit_url: &str, store: &impl Storelike) -> AtomicResult<Resource> {
    let version_url = construct_version_endpoint_url(store, commit_url);
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
    use super::*;
    use crate::{Resource, Store};

    #[test]
    fn constructs_versions() {
        let store = Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent(None).unwrap();
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
