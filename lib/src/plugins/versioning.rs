use tracing::warn;

use crate::{
    agents::ForAgent,
    collections::CollectionBuilder,
    endpoints::{Endpoint, HandleGetContext},
    errors::AtomicResult,
    urls, AtomicError, Commit, Query, Resource, Storelike,
};

pub fn version_endpoint() -> Endpoint {
    Endpoint {
        path: "/version".to_string(),
        params: [urls::SUBJECT.to_string()].into(),
        description: "Constructs a version of a resource from a Commit URL.".to_string(),
        shortname: "versions".to_string(),
        handle: Some(handle_version_request),
        handle_post: None,
    }
}

pub fn all_versions_endpoint() -> Endpoint {
    Endpoint {
        path: "/all-versions".to_string(),
        params: [urls::SUBJECT.to_string()].into(),
        description: "Shows all versions for some resource. Constructs these using Commits."
            .to_string(),
        shortname: "all-versions".to_string(),
        handle: Some(handle_all_versions_request),
        handle_post: None,
    }
}

#[tracing::instrument]
fn handle_version_request(context: HandleGetContext) -> AtomicResult<Resource> {
    let params = context.subject.query_pairs();
    let mut commit_url = None;
    for (k, v) in params {
        if let "commit" = k.as_ref() {
            commit_url = Some(v.to_string())
        };
    }
    if commit_url.is_none() {
        return version_endpoint().to_resource(context.store);
    }
    let mut resource = construct_version(&commit_url.unwrap(), context.store, context.for_agent)?;
    resource.set_subject(context.subject.to_string());
    Ok(resource)
}

#[tracing::instrument]
fn handle_all_versions_request(context: HandleGetContext) -> AtomicResult<Resource> {
    let HandleGetContext {
        store,
        for_agent,
        subject,
    } = context;
    let params = subject.query_pairs();
    let mut target_subject = None;
    for (k, v) in params {
        if let "subject" = k.as_ref() {
            target_subject = Some(v.to_string())
        };
    }
    if target_subject.is_none() {
        return all_versions_endpoint().to_resource(store);
    }
    let target = target_subject.unwrap();
    let collection_builder = CollectionBuilder {
        subject: subject.to_string(),
        property: Some(urls::SUBJECT.into()),
        value: Some(target.clone()),
        sort_by: None,
        sort_desc: false,
        current_page: 0,
        page_size: 20,
        name: Some(format!("Versions of {}", target)),
        include_nested: false,
        include_external: false,
    };
    let mut collection = collection_builder.into_collection(store, for_agent)?;
    let new_members = collection
        .members
        .iter_mut()
        .map(|commit_url| construct_version_endpoint_url(store, commit_url))
        .collect();
    collection.members = new_members;
    collection.to_resource(store)
}

/// Searches the local store for all commits with this subject, returns sorted from old to new.
#[tracing::instrument(skip(store))]
fn get_commits_for_resource(subject: &str, store: &impl Storelike) -> AtomicResult<Vec<Commit>> {
    let mut q = Query::new_prop_val(urls::SUBJECT, subject);
    q.sort_by = Some(urls::CREATED_AT.into());
    let result = store.query(&q)?;

    let filtered: Vec<Commit> = result
        .resources
        .iter()
        .filter_map(|r| crate::Commit::from_resource(r.clone()).ok())
        .collect();

    Ok(filtered)
}

#[tracing::instrument(skip(store))]
pub fn get_initial_commit_for_resource(
    subject: &str,
    store: &impl Storelike,
) -> AtomicResult<Commit> {
    let commits = get_commits_for_resource(subject, store)?;
    if commits.is_empty() {
        return Err(AtomicError::not_found(
            "No commits found for this resource".to_string(),
        ));
    }
    Ok(commits.first().unwrap().clone())
}

/// Constructs a Resource version for a specific Commit
/// Only works if the current store has the required Commits
#[tracing::instrument(skip(store))]
pub fn construct_version(
    commit_url: &str,
    store: &impl Storelike,
    for_agent: &ForAgent,
) -> AtomicResult<Resource> {
    let commit = store.get_resource(commit_url)?;
    // Get all the commits for the subject of that Commit
    let subject = &commit.get(urls::SUBJECT)?.to_string();
    let current_resource = store.get_resource(subject)?;
    crate::hierarchy::check_read(store, &current_resource, for_agent)?;
    let commits = get_commits_for_resource(subject, store)?;
    let mut version = Resource::new(subject.into());
    for commit in commits {
        if let Some(current_commit) = commit.url.clone() {
            let applied = commit.apply_changes(version, store)?;
            version = applied.resource_new;
            // Stop iterating when the target commit has been applied.
            if current_commit == commit_url {
                break;
            }
        }
    }
    Ok(version)
}

/// Creates the versioning URL for some specific Commit
fn construct_version_endpoint_url(store: &impl Storelike, commit_url: &str) -> String {
    format!(
        "{}/versioning?commit={}",
        store.get_server_url(),
        urlencoding::encode(commit_url)
    )
}

/// Gets a version of a Resource by Commit.
/// Tries cached version, constructs one if there is no cached version.
pub fn get_version(
    commit_url: &str,
    store: &impl Storelike,
    for_agent: &ForAgent,
) -> AtomicResult<Resource> {
    let version_url = construct_version_endpoint_url(store, commit_url);
    match store.get_resource(&version_url) {
        Ok(cached) => Ok(cached),
        Err(_not_cached) => {
            let version = construct_version(commit_url, store, for_agent)?;
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
            .set_string(crate::urls::DESCRIPTION.into(), first_val, &store)
            .unwrap();
        let first_result = resource.save_locally(&store).unwrap();
        let first_commit = first_result.commit_resource;

        let second_val = "Hello universe";
        resource
            .set_string(crate::urls::DESCRIPTION.into(), second_val, &store)
            .unwrap();
        let commit_resp = resource.save_locally(&store).unwrap();
        let second_commit = commit_resp.commit_resource;
        let commits = get_commits_for_resource(subject, &store).unwrap();
        assert_eq!(commits.len(), 2, "We should have two commits");

        let first_version =
            construct_version(first_commit.get_subject(), &store, &ForAgent::Sudo).unwrap();
        assert_eq!(
            first_version
                .get_shortname("description", &store)
                .unwrap()
                .to_string(),
            first_val
        );

        let second_version =
            construct_version(second_commit.get_subject(), &store, &ForAgent::Sudo).unwrap();
        assert_eq!(
            second_version
                .get_shortname("description", &store)
                .unwrap()
                .to_string(),
            second_val
        );
    }
}
