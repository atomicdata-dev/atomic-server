/*!
Sends users a link to add a new public key to their account.
Useful when a users loses their private key.
*/

use serde::{Deserialize, Serialize};

use crate::{
    agents::Agent,
    email::{EmailAddress, MailAction, MailMessage},
    endpoints::{Endpoint, HandleGetContext},
    errors::AtomicResult,
    plugins::utils::return_success,
    urls, Resource, Storelike,
};

pub fn request_email_add_pubkey() -> Endpoint {
    Endpoint {
        path: urls::PATH_ADD_PUBKEY.to_string(),
        params: [urls::TOKEN.to_string(), urls::INVITE_PUBKEY.to_string()].into(),
        description: "Requests an email to add a new PublicKey to an Agent.".to_string(),
        shortname: "request-pubkey-reset".to_string(),
        handle: Some(handle_request_email_pubkey),
        handle_post: None,
    }
}

pub fn confirm_add_pubkey() -> Endpoint {
    Endpoint {
        path: urls::PATH_CONFIRM_PUBKEY.to_string(),
        params: [urls::TOKEN.to_string(), urls::INVITE_PUBKEY.to_string()].into(),
        description: "Confirms a token to add a new Public Key.".to_string(),
        shortname: "request-pubkey-reset".to_string(),
        handle: Some(handle_confirm_add_pubkey),
        handle_post: None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AddPubkeyToken {
    agent: String,
}

pub fn handle_request_email_pubkey(context: HandleGetContext) -> AtomicResult<Resource> {
    let HandleGetContext {
        subject,
        store,
        for_agent: _,
    } = context;
    let mut email_option: Option<EmailAddress> = None;
    for (k, v) in subject.query_pairs() {
        match k.as_ref() {
            "email" => email_option = Some(EmailAddress::new(v.to_string())?),
            _ => {}
        }
    }
    // by default just return the Endpoint
    let Some(email) = email_option else {
        return request_email_add_pubkey().to_resource(store);
    };

    // Find the agent by their email
    let agent = Agent::from_email(&email.to_string(), store)?;

    // send the user an e-mail to confirm sign up
    let store_clone = store.clone();
    let confirmation_token_struct = AddPubkeyToken {
        agent: agent.subject,
    };
    let token = crate::token::sign_claim(store, confirmation_token_struct)?;
    let mut confirm_url = store
        .get_server_url()
        .clone()
        .set_path(urls::PATH_CONFIRM_PUBKEY)
        .url();
    confirm_url.set_query(Some(&format!("token={}", token)));
    let message = MailMessage {
        to: email,
        subject: "Add a new Passphrase to your account".to_string(),
        body: "You've requested adding a new Passphrase. Click the link below to do so!"
            .to_string(),
        action: Some(MailAction {
            name: "Add new Passphrase to account".to_string(),
            url: confirm_url.into(),
        }),
    };
    // async, because mails are slow
    tokio::spawn(async move {
        store_clone
            .send_email(message)
            .await
            .unwrap_or_else(|e| tracing::error!("Error sending email: {}", e));
    });

    return_success()
}

#[tracing::instrument]
pub fn handle_confirm_add_pubkey(context: HandleGetContext) -> AtomicResult<Resource> {
    let HandleGetContext {
        subject,
        store,
        for_agent: _,
    } = context;
    let mut token_opt: Option<String> = None;
    let mut pubkey_option = None;

    for (k, v) in subject.query_pairs() {
        match k.as_ref() {
            "token" | urls::TOKEN => token_opt = Some(v.to_string()),
            "public-key" | urls::INVITE_PUBKEY => pubkey_option = Some(v.to_string()),
            _ => {}
        }
    }
    let pubkey = pubkey_option.ok_or("No public-key provided")?;

    let Some(token) = token_opt else {
        return confirm_add_pubkey().to_resource(store);
    };

    // Parse and verify the JWT token
    let confirmation = crate::token::verify_claim::<AddPubkeyToken>(store, &token)?.custom;

    // Add the key to the agent
    let mut agent = store.get_resource(&confirmation.agent)?;
    agent.push_propval(urls::ACTIVE_KEYS, pubkey.into(), true)?;
    agent.save(store)?;

    return_success()
}
