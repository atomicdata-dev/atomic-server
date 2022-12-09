/*!
Reset email
*/

use crate::{endpoints::Endpoint, errors::AtomicResult, urls, Db, Resource};

pub fn request_email_pubkey_reset() -> Endpoint {
    Endpoint {
        path: urls::PATH_RESET_PUBKEY.to_string(),
        params: [urls::TOKEN.to_string(), urls::INVITE_PUBKEY.to_string()].into(),
        description: "Requests an email to set a new PublicKey to an Agent.".to_string(),
        shortname: "request-pubkey-reset".to_string(),
        handle: Some(construct_reset_pubkey),
    }
}

pub fn confirm_pubkey_reset() -> Endpoint {
    Endpoint {
        path: urls::PATH_CONFIRM_RESET.to_string(),
        params: [urls::TOKEN.to_string(), urls::INVITE_PUBKEY.to_string()].into(),
        description: "Requests an email to set a new PublicKey to an Agent.".to_string(),
        shortname: "request-pubkey-reset".to_string(),
        handle: Some(construct_confirm_reset_pubkey),
    }
}

#[tracing::instrument(skip(store))]
pub fn construct_confirm_reset_pubkey(
    url: url::Url,
    store: &Db,
    for_agent: Option<&str>,
) -> AtomicResult<Resource> {
    let mut token_opt: Option<String> = None;
    let mut pubkey_option = None;

    println!("url: {:?}", url);
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "token" | urls::TOKEN => token_opt = Some(v.to_string()),
            "public-key" | urls::INVITE_PUBKEY => pubkey_option = Some(v.to_string()),
            _ => {}
        }
    }
    let Some(token) = token_opt else {
        return confirm_pubkey_reset().to_resource(store);
    };
    let pubkey = pubkey_option.ok_or("No public-key provided")?;

    // Parse and verify the JWT token
    let confirmation = crate::token::verify_claim::<MailConfirmation>(store, &token)?.custom;

    // Add the drive to the Agent's list of drives
    let mut agent = store.get_resource(&drive_creator_agent)?;
    agent.push_propval(
        urls::USED_PUBKEYS.into(),
        SubResource::Subject(drive.get_subject().into()),
        true,
    )?;
    agent.save_locally(store)?;

    // Construct the Redirect Resource, which might provide the Client with a Subject for his Agent.
    let mut redirect = Resource::new_instance(urls::REDIRECT, store)?;
    redirect.set_propval_string(urls::DESTINATION.into(), drive.get_subject(), store)?;
    redirect.set_propval(
        urls::REDIRECT_AGENT.into(),
        crate::Value::AtomicUrl(drive_creator_agent),
        store,
    )?;
    Ok(redirect)
}
