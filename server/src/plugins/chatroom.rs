/*!
# ChatRoom
These are similar to Channels in Slack or Discord.
They list a bunch of Messages.

A built-in app on the host ABI (`planning/host-abi.md`, step 7): the same
`on-get` hook and the same `store` import a component gets, compiled in
(`NativeHooks`) and registered like a module. It reads the messages with
`store.query`, so what the reader may see is decided by the host's `Grant`,
not by code in here.
*/

#[cfg(feature = "wasm-plugins")]
mod module {
    use std::sync::Arc;

    use atomic_lib::{
        class_extender::{BoxFuture, ClassExtender},
        urls, utils, Db,
    };

    use crate::plugins::host_abi::{
        bindings::atomic::host::{
            store::{Filter, FilterOp, Host as _, QuerySpec},
            types::{PropVal, Resource, Value},
        },
        code, error,
        module_bindings::exports::atomic::host::hooks::GetAnswer,
        HostAbiRegistry, ModuleParts, NativeHooks, ServerModule,
    };
    use crate::plugins::host_abi::{AbiState, HostError};

    /// A page is this many messages; one more is fetched to know there is a next.
    const PAGE: u32 = 50;

    struct ChatRoom;

    fn link(property: &str, subject: String) -> PropVal {
        PropVal {
            property: property.into(),
            value: Value::Link(subject),
        }
    }

    impl NativeHooks for ChatRoom {
        fn classes(&self) -> Vec<String> {
            vec![urls::CHATROOM.to_string()]
        }

        fn on_get<'a>(
            &'a self,
            imports: &'a mut AbiState,
            room: Resource,
            _agent: String,
            query: Vec<(String, String)>,
        ) -> BoxFuture<'a, Result<Option<GetAnswer>, HostError>> {
            Box::pin(async move {
                // TODO: From range
                let mut before = utils::now();
                for (k, v) in &query {
                    if k == "before-timestamp" {
                        before = v.parse::<i64>().map_err(|e| {
                            error(code::INVALID_ARGUMENT, format!("before-timestamp: {e}"))
                        })?;
                    }
                }

                let page = imports
                    .query(QuerySpec {
                        class: None,
                        parent: Some(room.subject.clone()),
                        filters: vec![Filter {
                            property: urls::CREATED_AT.into(),
                            op: FilterOp::Lte,
                            value: Some(Value::Integer(before)),
                        }],
                        sort_by: Some(urls::CREATED_AT.into()),
                        sort_desc: true,
                        limit: Some(PAGE + 1),
                        cursor: None,
                        with_resources: true,
                    })
                    .await?;

                let mut propvals: Vec<PropVal> = room
                    .propvals
                    .iter()
                    .filter(|pv| pv.property != urls::MESSAGES && pv.property != urls::NEXT_PAGE)
                    .cloned()
                    .collect();

                // The oldest one fetched marks where the next page starts.
                if page.subjects.len() > PAGE as usize {
                    let created = page.resources.last().and_then(|last| {
                        last.propvals.iter().find_map(|pv| match pv.value {
                            Value::Integer(t) if pv.property == urls::CREATED_AT => Some(t),
                            _ => None,
                        })
                    });
                    if let Some(created) = created {
                        let next = url::Url::parse_with_params(
                            &room.subject,
                            &[("before-timestamp", created.to_string())],
                        )
                        .map_err(|e| error(code::INTERNAL, e.to_string()))?;
                        propvals.push(link(urls::NEXT_PAGE, next.to_string()));
                    }
                }

                // Clients expect messages to appear from old to new
                let mut messages = page.subjects;
                messages.reverse();
                propvals.push(PropVal {
                    property: urls::MESSAGES.into(),
                    value: Value::ResourceArray(messages.clone()),
                });

                Ok(Some(GetAnswer {
                    resource: Resource { propvals, ..room },
                    referenced: messages,
                }))
            })
        }
    }

    /// Find the messages for the ChatRoom.
    pub fn build_chatroom_extender(db: &Db, registry: Arc<HostAbiRegistry>) -> ClassExtender {
        ServerModule::native(
            Arc::new(ChatRoom),
            db,
            ModuleParts {
                file_name: "chatroom".into(),
                scope: atomic_lib::class_extender::ClassExtenderScope::Global,
                installation: None,
                agent: None,
                storage_dir: None,
                manifest: None,
                registry,
            },
        )
        .into_class_extender()
    }
}

#[cfg(feature = "wasm-plugins")]
pub use module::build_chatroom_extender;

use atomic_lib::{class_extender::ClassExtender, urls};

pub fn build_message_extender() -> ClassExtender {
    ClassExtender::builder()
        .id("message".to_string())
        .classes(vec![urls::MESSAGE.to_string()])
        .build()
}

#[cfg(feature = "wasm-plugins")]
#[tokio::test]
async fn test_ws_push_chatroom() {
    use atomic_lib::commit::CommitOpts;
    use atomic_lib::{commit::CommitBuilder, urls, values::SubResource, Db, Storelike, Value};
    use std::sync::Arc;

    let test_dir = std::env::temp_dir().join("atomic-test-db-chat");
    let uploads_dir = test_dir.join("uploads");
    let mut db = Db::init_redb_file(&test_dir, Some("http://localhost".into()), &uploads_dir)
        .await
        .unwrap();

    db.add_class_extender(build_chatroom_extender(&db, Arc::default()))
        .unwrap();
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

#[cfg(all(test, feature = "wasm-plugins"))]
mod tests {
    use super::*;
    use atomic_lib::Value;
    use atomic_lib::{agents::ForAgent, storelike::ResourceResponse, Db, Resource, Storelike};
    use std::sync::Arc;

    async fn room_with_messages(id: &str, n: usize) -> (Db, Resource, Vec<String>) {
        let store = Db::init_temp(id).await.unwrap();
        store
            .add_class_extender(build_chatroom_extender(&store, Arc::default()))
            .unwrap();
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
