//! Creates a new Drive and optionally also an Agent.

use crate::{agents::Agent, endpoints::Endpoint, errors::AtomicResult, urls, Resource, Storelike};

pub fn register_endpoint() -> Endpoint {
    Endpoint {
      path: "/register".to_string(),
      params: [
        urls::INVITE_PUBKEY.to_string(),
        urls::NAME.to_string(),
      ].into(),
      description: "Allows new users to easily, in one request, make both an Agent and a Drive. This drive will be created at the subdomain of `name`.".to_string(),
      shortname: "register".to_string(),
      handle: Some(construct_register_redirect),
  }
}

#[tracing::instrument(skip(store))]
pub fn construct_register_redirect(
    url: url::Url,
    store: &impl Storelike,
    for_agent: Option<&str>,
) -> AtomicResult<Resource> {
    let requested_subject = url.to_string();
    let mut pub_key = None;
    let mut name_option = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "public-key" | urls::INVITE_PUBKEY => pub_key = Some(v.to_string()),
            "name" | urls::NAME => name_option = Some(v.to_string()),
            _ => {}
        }
    }
    if pub_key.is_none() && name_option.is_none() {
        return register_endpoint().to_resource(store);
    }

    let name = if let Some(n) = name_option {
        n
    } else {
        return Err("No name provided".into());
    };

    let mut new_agent = None;

    let drive_creator_agent: String = if let Some(key) = pub_key {
        let new = Agent::new_from_public_key(store, &key)?.subject;
        new_agent = Some(new.clone());
        new
    } else if let Some(agent) = for_agent {
        agent.to_string()
    } else {
        return Err("No `public-key` provided".into());
    };

    // Create the new Drive
    let drive = crate::populate::create_drive(store, Some(&name), &drive_creator_agent, false)?;

    // Construct the Redirect Resource, which might provide the Client with a Subject for his Agent.
    let mut redirect = Resource::new_instance(urls::REDIRECT, store)?;
    redirect.set_propval_string(urls::DESTINATION.into(), drive.get_subject(), store)?;
    if let Some(agent) = new_agent {
        redirect.set_propval(
            urls::REDIRECT_AGENT.into(),
            crate::Value::AtomicUrl(agent),
            store,
        )?;
    }
    // The front-end requires the @id to be the same as requested
    redirect.set_subject(requested_subject);
    Ok(redirect)
}
