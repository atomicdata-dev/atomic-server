/*!
# ChatRoom
These are similar to Channels in Slack or Discord.
They list a bunch of Messages.
*/

use atomic_lib::{
    class_extender::{BoxFuture, ClassExtender, GetExtenderContext},
    db::drive_prefix_from_subject,
    errors::AtomicResult,
    storelike::{Query, QueryResult, ResourceResponse},
    urls::{self, PARENT},
    utils, Storelike, Value,
};

// Find the messages for the ChatRoom.
#[tracing::instrument(skip(context))]
pub fn construct_chatroom<'a>(
    context: GetExtenderContext<'a>,
) -> BoxFuture<'a, AtomicResult<ResourceResponse>> {
    Box::pin(async move {
        let GetExtenderContext {
            store,
            url,
            db_resource: resource,
            for_agent,
        } = context;

        // TODO: From range
        let mut start_val = utils::now();
        for (k, v) in url.query_pairs() {
            if k.as_ref() == "before-timestamp" {
                start_val = v.parse::<i64>()?;
            }
        }

        let page_limit = 50;

        // First, find all children
        let query_children = Query {
            property: Some(PARENT.into()),
            value: Some(Value::AtomicUrl(resource.get_subject().clone())),
            filters: Vec::new(),
            // We fetch one extra to see if there are more, so we can create a next-page URL
            limit: Some(page_limit + 1),
            start_val: None,
            end_val: Some(Value::Timestamp(start_val)),
            offset: 0,
            sort_by: Some(urls::CREATED_AT.into()),
            sort_desc: true,
            include_external: false,
            include_nested: true,
            for_agent: for_agent.clone(),
            drive: Some(drive_prefix_from_subject(resource.get_subject())),
            aggregation: None,
            expression_filters: Vec::new(),
        };

        let QueryResult {
            mut subjects,
            resources,
            count,
            ..
        } = store.query(&query_children).await?;

        // An attempt at creating a `next_page` URL on the server. But to be honest, it's probably better to do this in the front-end.
        if count > page_limit {
            let last_subject = resources
                .last()
                .ok_or("There are more messages than the page limit")?
                .get_subject();
            let last_resource = store.get_resource(last_subject).await?;
            let last_timestamp = last_resource.get(urls::CREATED_AT)?;
            let next_page_url = url::Url::parse_with_params(
                resource.get_subject().as_str(),
                &[("before-timestamp", last_timestamp.to_string())],
            )?;
            resource
                .set(
                    urls::NEXT_PAGE.into(),
                    Value::AtomicUrl(next_page_url.to_string().into()),
                    store,
                )
                .await?;
        }

        // Clients expect messages to appear from old to new
        subjects.reverse();

        resource
            .set(urls::MESSAGES.into(), subjects.into(), store)
            .await?;

        Ok(ResourceResponse::ResourceWithReferenced(
            resource.to_owned(),
            resources,
        ))
    })
}

pub fn build_chatroom_extender() -> ClassExtender {
    ClassExtender::builder()
        .id("chatroom".to_string())
        .classes(vec![urls::CHATROOM.to_string()])
        .on_resource_get(ClassExtender::wrap_get_handler(construct_chatroom))
        .build()
}

pub fn build_message_extender() -> ClassExtender {
    ClassExtender::builder()
        .id("message".to_string())
        .classes(vec![urls::MESSAGE.to_string()])
        .build()
}

#[tokio::test]
async fn test_ws_push_chatroom() {
    use atomic_lib::commit::CommitOpts;
    use atomic_lib::{commit::CommitBuilder, urls, values::SubResource, Db, Storelike, Value};

    let test_dir = std::env::temp_dir().join("atomic-test-db-chat");
    let uploads_dir = test_dir.join("uploads");
    let mut db = Db::init_redb_file(&test_dir, Some("http://localhost".into()), &uploads_dir)
        .await
        .unwrap();

    db.add_class_extender(build_chatroom_extender()).unwrap();
    db.add_class_extender(build_message_extender()).unwrap();

    let agent = db.create_agent(Some("agent")).await.unwrap();
    db.set_default_agent(agent.clone());

    let mut chatroom = atomic_lib::Resource::new("http://localhost/chat".into());
    chatroom.set_class(urls::CHATROOM).unwrap();
    let mut chatroom_builder = CommitBuilder::new(chatroom.get_subject().clone());
    chatroom_builder
        .push_propval(urls::IS_A, SubResource::Subject(urls::CHATROOM.into()))
        .unwrap();
    let chatroom_commit = chatroom_builder.sign(&agent, &db, &chatroom).await.unwrap();

    db.apply_commit(chatroom_commit, &CommitOpts::no_validations_no_index())
        .await
        .unwrap();

    let fetched = db
        .get_resource(&"http://localhost/chat".into())
        .await
        .unwrap();
    println!("Fetched chatroom: {}", fetched.get_subject());

    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    db.set_handle_commit(Box::new(move |resp| {
        let _ = tx.try_send(resp.clone());
    }));

    let mut message = atomic_lib::Resource::new("http://localhost/msg1".into());
    message.set_class(urls::MESSAGE).unwrap();
    message
        .set_unsafe(
            urls::PARENT.into(),
            Value::AtomicUrl("http://localhost/chat".into()),
        )
        .unwrap();

    let mut message_builder = CommitBuilder::new(message.get_subject().clone());
    message_builder
        .push_propval(urls::IS_A, SubResource::Subject(urls::MESSAGE.into()))
        .unwrap();

    message_builder.set(
        urls::PARENT.to_string(),
        Value::AtomicUrl("http://localhost/chat".into()),
    );

    let message_commit = message_builder.sign(&agent, &db, &message).await.unwrap();

    println!("All subjects in Sled:");
    for item in db.all_resources(true) {
        println!(" - {}", item.get_subject());
    }

    db.apply_commit(message_commit, &CommitOpts::no_validations_no_index())
        .await
        .unwrap();

    while let Ok(resp) = rx.try_recv() {
        println!("Received commit for: {}", resp.commit.subject);
        println!(
            "JSON: {}",
            resp.commit_resource
                .to_json_ad(Some("http://localhost"))
                .unwrap()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::{agents::ForAgent, storelike::ResourceResponse, Db, Resource, Storelike};

    async fn room_with_messages(id: &str, n: usize) -> (Db, Resource, Vec<String>) {
        let store = Db::init_temp(id).await.unwrap();
        store.add_class_extender(build_chatroom_extender()).unwrap();
        store.add_class_extender(build_message_extender()).unwrap();
        let mut room = Resource::new_instance(urls::CHATROOM, &store)
            .await
            .unwrap();
        room.set(urls::NAME.into(), Value::String("room".into()), &store)
            .await
            .unwrap();
        room.save_locally(&store).await.unwrap();

        let mut subjects = Vec::new();
        for i in 0..n {
            let mut message = Resource::new_instance(urls::MESSAGE, &store).await.unwrap();
            message
                .set(
                    urls::PARENT.into(),
                    Value::AtomicUrl(room.get_subject().to_string().into()),
                    &store,
                )
                .await
                .unwrap();
            message
                .set(
                    urls::DESCRIPTION.into(),
                    Value::Markdown(format!("message {i}")),
                    &store,
                )
                .await
                .unwrap();
            message
                .set(
                    urls::CREATED_AT.into(),
                    Value::Timestamp(1_000 + i as i64),
                    &store,
                )
                .await
                .unwrap();
            message.save_locally(&store).await.unwrap();
            subjects.push(message.get_subject().to_string());
        }
        (store, room, subjects)
    }

    async fn get(store: &Db, subject: &str, agent: &ForAgent) -> (Resource, Vec<Resource>) {
        let subject = atomic_lib::Subject::from_raw(subject, None);
        match store
            .get_resource_extended(&subject, false, agent)
            .await
            .unwrap()
        {
            ResourceResponse::ResourceWithReferenced(r, refs) => (r, refs),
            ResourceResponse::Resource(r) => (r, Vec::new()),
            ResourceResponse::Redirect(_) => panic!("unexpected redirect"),
        }
    }

    fn messages_of(room: &Resource) -> Vec<String> {
        room.get(urls::MESSAGES).unwrap().to_subjects(None).unwrap()
    }

    #[tokio::test]
    async fn a_chatroom_lists_its_messages_old_to_new_with_their_bodies() {
        let (store, room, sent) = room_with_messages("chatroom-short", 3).await;
        let (served, referenced) = get(&store, room.get_subject().as_str(), &ForAgent::Sudo).await;

        assert_eq!(messages_of(&served), sent);
        assert!(served.get(urls::NEXT_PAGE).is_err(), "one page, no next");
        let mut bodies: Vec<_> = referenced
            .iter()
            .map(|r| r.get_subject().to_string())
            .collect();
        bodies.sort();
        let mut want = sent.clone();
        want.sort();
        assert_eq!(bodies, want);
    }

    #[tokio::test]
    async fn a_long_chatroom_pages_backwards_with_before_timestamp() {
        let (store, room, sent) = room_with_messages("chatroom-long", 60).await;
        let (page1, _) = get(&store, room.get_subject().as_str(), &ForAgent::Sudo).await;

        // The newest 51 (one more than a page, to find the boundary), old to new.
        assert_eq!(messages_of(&page1), sent[9..].to_vec());
        let next = page1.get(urls::NEXT_PAGE).unwrap().to_string();
        assert!(next.contains("before-timestamp=1009"), "{next}");

        let (page2, _) = get(&store, &next, &ForAgent::Sudo).await;
        assert_eq!(messages_of(&page2), sent[..10].to_vec());
        assert!(page2.get(urls::NEXT_PAGE).is_err());
    }

    #[tokio::test]
    async fn the_public_cannot_read_a_private_chatroom() {
        let (store, room, _) = room_with_messages("chatroom-rights", 2).await;
        // The room is not public: the public agent is refused before any extender runs.
        let result = store
            .get_resource_extended(
                &atomic_lib::Subject::from_raw(room.get_subject().as_str(), None),
                false,
                &ForAgent::Public,
            )
            .await;
        assert!(result.is_err());
    }
}
