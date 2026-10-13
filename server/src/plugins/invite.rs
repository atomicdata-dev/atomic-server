use atomic_lib::{
    class_extender::BoxFuture,
    endpoints::{Endpoint, HandleGetContext, HandlePostContext},
    errors::AtomicResult,
    storelike::ResourceResponse,
    urls,
    utils::check_valid_url,
    Resource, Storelike, Subject, Value,
};

use crate::invite_token::{acceptance_lock, InviteToken};

fn read_token_from_subject(subject: &url::Url) -> Option<String> {
    for (k, v) in subject.query_pairs() {
        if k.as_ref() == "token" {
            return Some(v.to_string());
        }
    }

    None
}

pub fn invite_endpoint() -> Endpoint {
    Endpoint::builder(urls::PATH_INVITE)
        .shortname("invites")
        .params(["token"])
        .description("Stateless invite endpoint that accepts user-signed tokens.")
        .handle(handle_invite_request)
        .handle_post(handle_invite_post)
        .build()
}

pub fn handle_invite_request<'a>(
    context: HandleGetContext<'a>,
) -> BoxFuture<'a, AtomicResult<ResourceResponse>> {
    Box::pin(async move {
        let HandleGetContext {
            subject,
            store,
            for_agent: _for_agent,
        } = context;

        let token_str = match read_token_from_subject(&subject) {
            Some(t) => t,
            None => {
                return invite_endpoint()
                    .to_resource_response(store, subject.as_str())
                    .await;
            }
        };

        let token = InviteToken::decode(&token_str)?;
        token.verify(store).await?;

        // GET is preview mode only: return a virtual Invite resource so users can review before accepting
        let mut invite = Resource::new_instance(urls::INVITE, store).await?;
        invite.set_subject(subject.to_string());
        // `invite/target` is required on class Invite (`lib/defaults/default_store.json`).
        // If we skip it, the client-side WASM validator rejects the PUT into
        // OPFS, the resource never lands in the store, and the invite page
        // spins on "loading…" forever.
        invite
            .set(
                urls::TARGET.into(),
                Value::AtomicUrl(token.target.clone()),
                store,
            )
            .await?;
        invite
            .set(urls::WRITE_BOOL.into(), Value::Boolean(token.write), store)
            .await?;
        invite
            .set(
                urls::EXPIRES_AT.into(),
                Value::Timestamp(token.expires_at),
                store,
            )
            .await?;

        // Let the page say so up front when nobody can use this link anymore.
        if let Some(left) = token.usages_left(store)? {
            invite
                .set(urls::USAGES_LEFT.into(), Value::Integer(left), store)
                .await?;
        }

        let target_resource = store.get_resource(&token.target.clone()).await?;
        let title = target_resource
            .get(urls::NAME)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| token.target.to_string());
        invite
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown(format!(
                    "Stateless invite to {} the resource: {}",
                    if token.write { "edit" } else { "view" },
                    title
                )),
                store,
            )
            .await?;

        Ok(invite.into())
    })
}

pub fn handle_invite_post<'a>(
    context: HandlePostContext<'a>,
) -> BoxFuture<'a, AtomicResult<ResourceResponse>> {
    Box::pin(async move {
        let HandlePostContext {
            subject,
            store,
            for_agent,
            ..
        } = context;

        let token_str = match read_token_from_subject(&subject) {
            Some(t) => t,
            None => {
                return invite_endpoint()
                    .to_resource_response(store, subject.as_str())
                    .await;
            }
        };

        let token = InviteToken::decode(&token_str)?;
        token.verify(store).await?;

        let agent = match for_agent {
            atomic_lib::agents::ForAgent::AgentSubject(s) => s.to_owned(),
            atomic_lib::agents::ForAgent::Sudo => {
                return Err("Sudo agent cannot accept invites.".into());
            }
            atomic_lib::agents::ForAgent::Public => {
                return Err("Accepting invite requires an authenticated agent.".into());
            }
        };

        // Check and record under one lock, so two people opening a one-use link
        // at the same moment cannot both get in.
        let _guard = acceptance_lock().lock().await;
        token.check_usages(store, agent.as_str())?;

        if atomic_lib::identifiers::is_agent_id(agent.as_str())
            && store.get_resource(&agent.as_str().into()).await.is_err()
        {
            let mut new_agent = Resource::new_instance(urls::AGENT, store).await?;
            new_agent.set_subject(agent.to_string());
            if let Some(pk) = atomic_lib::identifiers::agent_public_key(agent.as_str()) {
                new_agent
                    .set_string(urls::PUBLIC_KEY.into(), pk, store)
                    .await?;
            }
            new_agent.save_locally(store).await?;
        }

        add_rights(agent.as_str(), token.target.as_str(), token.write, store).await?;
        if token.write {
            add_rights(agent.as_str(), token.target.as_str(), false, store).await?;
        }

        token.record_acceptance(store, agent.as_str())?;

        let mut redirect = Resource::new_instance(urls::REDIRECT, store).await?;
        redirect
            .set(
                urls::DESTINATION.into(),
                Value::AtomicUrl(token.target.clone()),
                store,
            )
            .await?;
        redirect.set_subject(subject.to_string());

        Ok(redirect.into())
    })
}

/// Adds the requested rights to the target resource.
/// Overwrites the target resource to include the new rights.
/// Checks if the Agent has a valid URL.
/// Will not throw an error if the Agent already has the rights.
#[tracing::instrument(skip(store))]
pub async fn add_rights(
    agent: &str,
    target: &str,
    write: bool,
    store: &impl Storelike,
) -> AtomicResult<()> {
    let agent_subject = Subject::from_raw(agent, store.get_base_domain().as_deref());
    if !agent_subject.is_did() {
        check_valid_url(agent)?;
    }
    // Get the Resource that the user is being invited to
    let mut target = store.get_resource(&target.into()).await?;
    let right = if write { urls::WRITE } else { urls::READ };

    target.push(right, agent.into(), true)?;
    target
        .save_locally(store)
        .await
        .map_err(|e| format!("Unable to save updated target resource. {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::agents::Agent;

    #[tokio::test]
    async fn accepting_twice_adds_rights_once() {
        let store = atomic_lib::test_utils::init_store().await;
        let drive = atomic_lib::test_utils::create_test_drive(&store)
            .await
            .unwrap();
        let agent = Agent::new(None).unwrap().subject.to_string();

        for _ in 0..3 {
            add_rights(&agent, drive.as_str(), true, &store)
                .await
                .unwrap();
            add_rights(&agent, drive.as_str(), false, &store)
                .await
                .unwrap();
        }

        let drive = store.get_resource(&drive).await.unwrap();
        for prop in [urls::READ, urls::WRITE] {
            let count = drive
                .get(prop)
                .map(|v| match v {
                    Value::ResourceArray(a) => a.iter().filter(|s| s.to_string() == agent).count(),
                    _ => 0,
                })
                .unwrap_or(0);
            assert_eq!(count, 1, "{prop} should list the agent once");
        }
    }

    async fn accept(
        store: &atomic_lib::Db,
        token: &InviteToken,
        agent: &Agent,
    ) -> AtomicResult<ResourceResponse> {
        let mut subject = url::Url::parse("http://localhost/invites").unwrap();
        subject
            .query_pairs_mut()
            .append_pair("token", &token.encode().unwrap());
        let for_agent = atomic_lib::agents::ForAgent::AgentSubject(agent.subject.clone());

        handle_invite_post(HandlePostContext {
            subject,
            store,
            for_agent: &for_agent,
            body: Vec::new(),
        })
        .await
    }

    #[tokio::test]
    async fn one_use_invite_admits_one_agent() {
        let store = atomic_lib::test_utils::init_store().await;
        let drive = atomic_lib::test_utils::create_test_drive(&store)
            .await
            .unwrap();
        let issuer = store.get_default_agent().unwrap();
        let token = InviteToken::new(
            drive.to_string(),
            false,
            atomic_lib::utils::now() + 100_000,
            &issuer,
            Some(1),
        )
        .unwrap();
        let first = Agent::new(None).unwrap();
        let second = Agent::new(None).unwrap();

        accept(&store, &token, &first).await.unwrap();
        // Opening the link again is harmless for someone already let in.
        accept(&store, &token, &first).await.unwrap();

        let err = match accept(&store, &token, &second).await {
            Ok(_) => panic!("a second agent got in on a one-use invite"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("no usages left"), "{err}");

        let drive = store.get_resource(&drive).await.unwrap();
        let readers = drive.get(urls::READ).unwrap().to_string();
        assert!(readers.contains(first.subject.as_str()));
        assert!(
            !readers.contains(second.subject.as_str()),
            "a rejected accept must not grant rights"
        );
    }
}
