/*!
Importers allow users to (periodically) import JSON-AD files from a remote source.
*/

use crate::{errors::AtomicResult, storelike::Query, urls, Resource, Storelike};

/// When an importer is shown, we list a bunch of Paramaters and a list of previously imported items.
#[tracing::instrument(skip(store, query_params))]
pub fn construct_importer(
    store: &impl Storelike,
    query_params: url::form_urlencoded::Parse,
    resource: &mut Resource,
    for_agent: Option<&str>,
) -> AtomicResult<Resource> {
    let requested_subject = resource.get_subject().to_string();
    let mut url = None;
    let mut json = None;
    for (k, v) in query_params {
        match k.as_ref() {
            "json" | urls::IMPORTER_URL => json = Some(v.to_string()),
            "url" | urls::IMPORTER_JSON => url = Some(v.to_string()),
            _ => {}
        }
    }

    if let Some(fetch_url) = url {
        json = Some(
            crate::client::fetch_body(&fetch_url, crate::parse::JSON_AD_MIME, None)
                .map_err(|e| format!("Error while fetching {}: {}", fetch_url, e))?,
        );
    }

    let parse_opts = crate::parse::ParseOpts {
        // We sign the importer Commits with the default agent,
        // not the one performing the import, because we don't have their private key.
        for_agent: Some(store.get_default_agent()?),
        importer: Some(requested_subject.clone()),
        create_commits: true,
        add: true,
    };

    if let Some(json_string) = json {
        store.import(&json_string, &parse_opts)?;
    }

    // TODO: generate list of imported resources

    let q = Query {
        property: Some(urls::PARENT.into()),
        value: Some(requested_subject.into()),
        limit: Some(10),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_nested: true,
        include_external: false,
        for_agent: for_agent.map(|s| s.to_string()),
    };
    let results = store.query(&q)?;

    resource.set_propval_unsafe(urls::ENDPOINT_RESULTS.into(), results.resources.into());
    resource.set_propval(
        urls::ENDPOINT_PARAMETERS.into(),
        vec![urls::IMPORTER_JSON, urls::IMPORTER_URL].into(),
        store,
    )?;
    Ok(resource.clone())
}
