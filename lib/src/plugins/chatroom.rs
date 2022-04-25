/*!
# ChatRoom
These are similar to Channels in Slack or Discord.
They list a bunch of Messages.
*/

use crate::{
    errors::AtomicResult,
    storelike::Query,
    urls::{self, PARENT},
    utils, Resource, Storelike, Value,
};

// Find the messages for the ChatRoom
#[tracing::instrument(skip(store))]
pub fn construct_chatroom(
    store: &impl Storelike,
    url: url::Url,
    resource: &mut Resource,
    for_agent: Option<&str>,
) -> AtomicResult<Resource> {
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
        // We fetch one extra to see if there are more, so we can create a next-page URL
        limit: Some(page_limit + 1),
        start_val: None,
        end_val: Some(Value::Timestamp(start_val)),
        offset: 0,
        sort_by: Some(urls::CREATED_AT.into()),
        sort_desc: true,
        include_external: false,
        include_nested: true,
        for_agent: for_agent.map(|s| s.to_string()),
    };

    let mut messages_unfiltered = store.query(&query_children)?.resources;

    // An attempt at creating a `next_page` URL on the server. But to be honest, it's probably better to do this in the front-end.
    if messages_unfiltered.len() > page_limit {
        let last_subject = messages_unfiltered
            .last()
            .ok_or("There are more messages than the page limit")?
            .get_subject();
        let last_resource = store.get_resource(last_subject)?;
        let last_timestamp = last_resource.get(urls::CREATED_AT)?;
        let next_page_url = url::Url::parse_with_params(
            resource.get_subject(),
            &[("before-timestamp", last_timestamp.to_string())],
        )?;
        resource.set_propval(
            urls::NEXT_PAGE.into(),
            Value::AtomicUrl(next_page_url.to_string()),
            store,
        )?;
    }

    // Clients expect messages to appear from old to new
    messages_unfiltered.reverse();

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
