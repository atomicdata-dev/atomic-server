/*!
Importers allow users to (periodically) import JSON-AD files from a remote source.
*/

use crate::{
    agents::ForAgent,
    endpoints::{Endpoint, HandleGetContext, HandlePostContext},
    errors::AtomicResult,
    urls, Resource, Storelike,
};

pub fn import_endpoint() -> Endpoint {
    Endpoint {
        path: "/import".to_string(),
        params: [
            urls::IMPORTER_OVERWRITE_OUTSIDE.to_string(),
            urls::IMPORTER_PARENT.to_string(),
            urls::IMPORTER_URL.to_string(),
        ].into(),
        description: "Imports one or more Resources to some parent. POST your JSON-AD and add a `parent` query param to the URL. See https://docs.atomicdata.dev/create-json-ad.html".to_string(),
        shortname: "path".to_string(),
        // Not sure if we need this, or if we should derive it from `None` here.
        handle: Some(handle_get),
        handle_post: Some(handle_post),
    }
}

pub fn handle_get(context: HandleGetContext) -> AtomicResult<Resource> {
    import_endpoint().to_resource(context.store)
}

/// When an importer is shown, we list a bunch of Parameters and a list of previously imported items.
#[tracing::instrument]
pub fn handle_post(context: HandlePostContext) -> AtomicResult<Resource> {
    let HandlePostContext {
        store,
        body,
        for_agent,
        subject,
    } = context;
    let mut url = None;
    let mut json = None;
    let mut parent_maybe = None;
    let mut overwrite_outside = false;
    for (k, v) in subject.query_pairs() {
        match k.as_ref() {
            "json" | urls::IMPORTER_URL => return Err("JSON must be POSTed in the body".into()),
            "url" | urls::IMPORTER_JSON => url = Some(v.to_string()),
            "parent" | urls::IMPORTER_PARENT => parent_maybe = Some(v.to_string()),
            "overwrite-outside" | urls::IMPORTER_OVERWRITE_OUTSIDE => {
                overwrite_outside = v == "true"
            }
            _ => {}
        }
    }

    let parent = parent_maybe.ok_or("No parent specified for importer")?;

    if !body.is_empty() {
        json =
            Some(String::from_utf8(body).map_err(|e| {
                format!("Error while decoding body, expected a JSON string: {}", e)
            })?);
    }

    if let Some(fetch_url) = url {
        json = Some(
            crate::client::fetch_body(&fetch_url, crate::parse::JSON_AD_MIME, None)
                .map_err(|e| format!("Error while fetching {}: {}", fetch_url, e))?,
        );
    }

    let parse_opts = crate::parse::ParseOpts {
        for_agent: for_agent.clone(),
        importer: Some(parent),
        overwrite_outside,
        // We sign the importer Commits with the default agent,
        // not the one performing the import, because we don't have their private key.
        signer: Some(store.get_default_agent()?),
        save: crate::parse::SaveOpts::Commit,
    };

    if let Some(json_string) = json {
        if for_agent == &ForAgent::Public {
            return Err("No agent specified for importer".to_string().into());
        }
        store.import(&json_string, &parse_opts)?;
    } else {
        return Err(
            "No JSON specified for importer. Pass a `url` query param, or post a JSON-AD body."
                .to_string()
                .into(),
        );
    }

    import_endpoint().to_resource(context.store)
}
