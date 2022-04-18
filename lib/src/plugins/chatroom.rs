/*!
# ChatRoom
These are similar to Channels in Slack or Discord.
They list a bunch of Messages.
*/

use crate::{
    errors::AtomicResult,
    storelike::Query,
    urls::{self, PARENT},
    Resource, Storelike, Value,
};

// Find the messages for the ChatRoom
#[tracing::instrument(skip(store, _query_params))]
pub fn construct_chatroom(
    store: &impl Storelike,
    _query_params: url::form_urlencoded::Parse,
    resource: &mut Resource,
    for_agent: Option<&str>,
) -> AtomicResult<Resource> {
    // TODO: From range
    // for (k, v) in query_params {
    //     match k.as_ref() {
    //         _ => {}
    //     }
    // }

    // First, find all children
    let query_children = Query {
        property: Some(PARENT.into()),
        value: Some(Value::AtomicUrl(resource.get_subject().clone())),
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(urls::CREATED_AT.into()),
        sort_desc: false,
        include_external: false,
        include_nested: false,
        for_agent: for_agent.map(|s| s.to_string()),
    };

    let messages_unfiltered = store.query(&query_children)?.subjects;

    resource.set_propval(urls::MESSAGES.into(), messages_unfiltered.into(), store)?;
    Ok(resource.to_owned())
}

/// Update the ChatRoom with the new message, make sure this is sent to all Subscribers
pub fn before_apply_commit(
    store: &impl Storelike,
    _commit: &crate::Commit,
    resource_new: &Resource,
) -> AtomicResult<()> {
    // Get the related ChatRoom
    let parent_subject = resource_new
        .get(urls::PARENT)
        .map_err(|_e| "Message must have a Parent!")?
        .to_string();

    // We need to push the Appended messages to all listeners of the ChatRoom.
    // We do this by pushing the message, and saving the Commit.
    // It is then sent to all subscribers.
    let mut chat_room = store.get_resource(&parent_subject)?;

    chat_room.push_propval(
        urls::MESSAGES,
        crate::values::SubResource::Resource(resource_new.clone()),
        false,
        store,
    )?;

    chat_room.save(store)?;
    Ok(())
}
