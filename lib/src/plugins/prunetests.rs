use crate::{
    endpoints::{Endpoint, HandleGetContext, HandlePostContext},
    errors::AtomicResult,
    urls, Query, Resource, Storelike, Value,
};

pub fn prune_tests_endpoint() -> Endpoint {
    Endpoint {
        path: urls::PATH_PRUNE_TESTS.into(),
        params: [].into(),
        description: "Deletes all drives with 'testdrive-' in their name.".to_string(),
        shortname: "prunetests".to_string(),
        handle: Some(handle_get),
        handle_post: Some(handle_prune_tests_request),
    }
}

pub fn handle_get(context: HandleGetContext) -> AtomicResult<Resource> {
    prune_tests_endpoint().to_resource(context.store)
}

// Delete all drives with 'testdrive-' in their name. (These drive are generated with each e2e test run)
fn handle_prune_tests_request(context: HandlePostContext) -> AtomicResult<Resource> {
    let HandlePostContext { store, .. } = context;

    let mut query = Query::new_class(urls::DRIVE);
    query.for_agent = context.for_agent.clone();
    let mut deleted_drives = 0;

    if let Ok(mut query_result) = store.query(&query) {
        println!(
            "Received prune request, deleting {} drives",
            query_result.resources.len()
        );

        let total_drives = query_result.resources.len();

        for resource in query_result.resources.iter_mut() {
            if let Value::String(name) = resource
                .get(urls::NAME)
                .unwrap_or(&Value::String("".to_string()))
            {
                if name.contains("testdrive-") {
                    resource.destroy(store)?;
                    deleted_drives += 1;

                    if (deleted_drives % 10) == 0 {
                        println!("Deleted {} of {} drives", deleted_drives, total_drives);
                    }
                }
            }
        }

        println!("Done pruning drives");
    } else {
        println!("Received prune request but there are no drives to prune");
    }

    let resource = build_response(store, 200, format!("Deleted {} drives", deleted_drives));
    Ok(resource)
}

fn build_response(store: &impl Storelike, status: i32, message: String) -> Resource {
    let mut resource = Resource::new_generate_subject(store);
    resource.set_class(urls::ENDPOINT_RESPONSE);
    resource.set_unsafe(urls::STATUS.to_string(), status.into());
    resource.set_unsafe(urls::RESPONSE_MESSAGE.to_string(), message.into());
    resource
}
