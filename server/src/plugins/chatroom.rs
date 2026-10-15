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
            exclude_trashed: false,
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
