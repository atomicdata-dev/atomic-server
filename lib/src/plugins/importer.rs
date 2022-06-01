/*!
Importers allow users to (periodically) import JSON-AD files from a remote source.
*/

use crate::{errors::AtomicResult, urls, Resource, Storelike};

/// When an importer is shown, we list a bunch of Paramaters and a list of previously imported items.
#[tracing::instrument(skip(store, query_params))]
pub fn construct_importer(
    store: &impl Storelike,
    query_params: url::form_urlencoded::Parse,
    invite_resource: &mut Resource,
    for_agent: Option<&str>,
) -> AtomicResult<Resource> {
    let requested_subject = invite_resource.get_subject().to_string();
    let mut url = None;
    let mut json = None;
    for (k, v) in query_params {
        match k.as_ref() {
            "json" | urls::IMPORTER_URL => url = Some(v.to_string()),
            "url" | urls::IMPORTER_JSON => json = Some(v.to_string()),
            _ => {}
        }
    }
    parse

    Ok(redirect)
}
