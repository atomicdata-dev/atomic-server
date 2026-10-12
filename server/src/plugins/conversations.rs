//! Endpoint: the Conversations on this server that the requester is in.
//!
//! A conversation is its own drive, created by whoever starts it. The other
//! members are only named in its `read` list, so nothing in their own data
//! points at it yet. This is how their app finds it: the reference index
//! already maps every `read` entry back to the resource carrying it, and the
//! query re-checks read rights per member. Nothing is stored for this.
//!
//! Only what this server hosts. A conversation hosted elsewhere reaches its
//! members by invite link, until cross-server delivery exists
//! (`planning/notifications.md`).

use atomic_lib::{
    agents::ForAgent,
    endpoints::{BoxFuture, Endpoint, HandleGetContext},
    errors::AtomicResult,
    storelike::{Query, ResourceResponse},
    urls, Resource, Storelike, Subject, Value,
};

pub fn conversations_endpoint() -> Endpoint {
    Endpoint::builder(urls::PATH_CONVERSATIONS)
        .shortname("conversations")
        .description(
            "Lists the Conversations (encrypted chats) on this server that the signed-in agent is a member of.",
        )
        .handle(handle_conversations_request)
        .build()
}

#[tracing::instrument(skip(context))]
fn handle_conversations_request<'a>(
    context: HandleGetContext<'a>,
) -> BoxFuture<'a, AtomicResult<ResourceResponse>> {
    Box::pin(async move {
        let HandleGetContext {
            subject,
            store,
            for_agent,
        } = context;

        let mut resource = Resource::new(subject.to_string());
        resource.set_class(urls::ENDPOINT_RESPONSE)?;
        // `status` and `response-message` are required on an endpoint
        // response; clients refuse the resource without them.
        resource.set_unsafe(urls::STATUS.to_string(), 200.into())?;
        resource.set_unsafe(urls::RESPONSE_MESSAGE.to_string(), "OK".to_string().into())?;
        resource
            .set_string(
                urls::DESCRIPTION.into(),
                "The Conversations on this server you are a member of.",
                store,
            )
            .await?;

        let agent = match for_agent {
            ForAgent::AgentSubject(agent) => agent.clone(),
            // Nobody is a member of anything when signed out.
            ForAgent::Public | ForAgent::Sudo => {
                resource
                    .set(
                        urls::CONVERSATIONS.into(),
                        Value::from(Vec::<Subject>::new()),
                        store,
                    )
                    .await?;
                return Ok(ResourceResponse::Resource(resource));
            }
        };

        let query = Query {
            property: Some(urls::READ.into()),
            value: Some(Value::AtomicUrl(agent)),
            include_nested: true,
            for_agent: for_agent.clone(),
            ..Query::new()
        };
        let result = store.query(&query).await?;

        let conversations: Vec<Resource> = result
            .resources
            .into_iter()
            .filter(|r| {
                r.get(urls::IS_A)
                    .ok()
                    .and_then(|v| v.to_subjects(None).ok())
                    .is_some_and(|classes| classes.iter().any(|c| c == urls::CONVERSATION))
            })
            .collect();
        let subjects: Vec<Subject> = conversations
            .iter()
            .map(|r| r.get_subject().clone())
            .collect();

        resource
            .set(urls::CONVERSATIONS.into(), Value::from(subjects), store)
            .await?;

        Ok(ResourceResponse::ResourceWithReferenced(
            resource,
            conversations,
        ))
    })
}
