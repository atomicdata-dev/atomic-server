//! `/conversations`: how a member finds a conversation someone else started.
//!
//! The conversation is a drive created by Alice; Bob is only named in its
//! `read`. Bob must see it, and only it: not a drive that merely shares him
//! in, and not a conversation he is not part of.
//!
//! Run: cargo test -p atomic-server --test it conversations

use atomic_lib::{
    agents::Agent,
    client::connected::Client,
    conversation::{encryption_public_key, Keyring, Member},
    errors::AtomicResult,
    urls, Resource, Value,
};

use crate::common::{start_server, wait_for_server};

fn member(agent: &Agent, proof_byte: u8) -> Member {
    Member {
        agent: agent.subject.to_string(),
        encryption_key: encryption_public_key(&[proof_byte; 64]),
    }
}

async fn new_drive(
    client: &Client,
    classes: &[&str],
    members: &[&Agent],
    keyring: Option<&Keyring>,
) -> AtomicResult<String> {
    let mut drive = Resource::new("did:ad:placeholder".into());
    drive.set_unsafe(
        urls::IS_A.into(),
        Value::ResourceArray(classes.iter().map(|c| (*c).into()).collect()),
    )?;
    drive.set_name("Conversation")?;
    let member_subjects = Value::ResourceArray(
        members
            .iter()
            .map(|a| a.subject.to_string().into())
            .collect(),
    );
    drive.set_unsafe(urls::READ.into(), member_subjects.clone())?;
    drive.set_unsafe(urls::APPEND.into(), member_subjects)?;
    if keyring.is_none() {
        drive.set_unsafe(
            urls::WRITE.into(),
            Value::ResourceArray(vec![members[0].subject.to_string().into()]),
        )?;
    }
    if let Some(keyring) = keyring {
        drive.set_unsafe(
            urls::CONVERSATION_KEYS.into(),
            Value::String(keyring.to_json()?),
        )?;
    }
    let subject = drive.save_remote(client.store()).await?;
    if keyring.is_some() {
        // A conversation has no writer. The server grants the creator `write`
        // at genesis, and that reaches every message in the drive, so the
        // creator gives it up straight away.
        let mut created = client.get_resource(&subject).await?;
        created.remove_propval(urls::WRITE)?;
        created.save_remote(client.store()).await?;
    }
    Ok(subject)
}

fn listed(resource: &Resource) -> Vec<String> {
    resource
        .get(urls::CONVERSATIONS)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default()
}

#[tokio::test]
async fn a_member_finds_the_conversations_they_are_in() -> AtomicResult<()> {
    let port = start_server("conversations");
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{}", port);
    let endpoint = format!("{server_url}{}", urls::PATH_CONVERSATIONS);

    let alice_client = Client::new(&server_url).await?;
    let carol_client = Client::new(&server_url).await?;
    let bob_client = Client::new(&server_url).await?;
    let carol = carol_client.new_agent("Carol").await?;
    let bob = bob_client.new_agent("Bob").await?;
    let alice = alice_client.new_agent("Alice").await?;

    let mut with_bob = Keyring::default();
    with_bob.add_epoch(&[member(&alice, 1), member(&bob, 2)])?;
    let dm = new_drive(
        &alice_client,
        &[urls::DRIVE, urls::CONVERSATION],
        &[&alice, &bob],
        Some(&with_bob),
    )
    .await?;

    let mut with_carol = Keyring::default();
    with_carol.add_epoch(&[member(&alice, 1), member(&carol, 3)])?;
    let other_dm = new_drive(
        &alice_client,
        &[urls::DRIVE, urls::CONVERSATION],
        &[&alice, &carol],
        Some(&with_carol),
    )
    .await?;

    // Shared with Bob, but a workspace, not a conversation.
    let workspace = new_drive(&alice_client, &[urls::DRIVE], &[&alice, &bob], None).await?;

    let for_bob = listed(&bob_client.get_resource(&endpoint).await?);
    assert_eq!(
        for_bob,
        vec![dm.clone()],
        "Bob sees exactly his conversation"
    );
    assert!(!for_bob.contains(&workspace));
    assert!(!for_bob.contains(&other_dm));

    let mut for_alice = listed(&alice_client.get_resource(&endpoint).await?);
    for_alice.sort();
    let mut expected = vec![dm, other_dm];
    expected.sort();
    assert_eq!(
        for_alice, expected,
        "Alice sees both conversations she started"
    );

    Ok(())
}

#[tokio::test]
async fn signed_out_lists_nothing() -> AtomicResult<()> {
    let port = start_server("conversations_public");
    wait_for_server(port).await;
    let endpoint = format!("http://localhost:{}{}", port, urls::PATH_CONVERSATIONS);
    let body = reqwest::get(&endpoint)
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    assert!(
        !body.contains("did:ad:"),
        "no conversation leaks to a public request: {body}"
    );
    Ok(())
}

async fn post_message(client: &Client, conversation: &str, agent: &Agent) -> AtomicResult<String> {
    let mut message = client.new_resource(conversation)?;
    message.set_unsafe(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::SEALED_MESSAGE.into()]),
    )?;
    message.set_unsafe(urls::SEALED.into(), Value::String("ciphertext".into()))?;
    message.set_unsafe(
        urls::WRITE.into(),
        Value::ResourceArray(vec![agent.subject.to_string().into()]),
    )?;
    message.save_remote(client.store()).await
}

/// The rights a conversation relies on: members may post (`append`), each
/// message stays its author's, and nobody outside gets in.
#[tokio::test]
async fn members_post_and_outsiders_cannot() -> AtomicResult<()> {
    let port = start_server("conversations_rights");
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{}", port);

    let alice_client = Client::new(&server_url).await?;
    let bob_client = Client::new(&server_url).await?;
    let carol_client = Client::new(&server_url).await?;
    let alice = alice_client.new_agent("Alice").await?;
    let bob = bob_client.new_agent("Bob").await?;
    let carol = carol_client.new_agent("Carol").await?;

    let mut keyring = Keyring::default();
    keyring.add_epoch(&[member(&alice, 1), member(&bob, 2)])?;
    let dm = new_drive(
        &alice_client,
        &[urls::DRIVE, urls::CONVERSATION],
        &[&alice, &bob],
        Some(&keyring),
    )
    .await?;

    let from_bob = post_message(&bob_client, &dm, &bob).await?;
    let read_back = alice_client.get_resource(&from_bob).await?;
    assert_eq!(
        read_back.get(urls::SEALED)?.to_string(),
        "ciphertext",
        "Alice reads what Bob posted"
    );

    assert!(
        post_message(&carol_client, &dm, &carol).await.is_err(),
        "Carol is not a member and cannot post"
    );
    assert!(
        carol_client.get_resource(&from_bob).await.is_err(),
        "Carol cannot read a message"
    );

    // Nobody rewrites what someone else said, the one who started it included.
    let mut as_alice = alice_client.get_resource(&from_bob).await?;
    as_alice.set_unsafe(urls::SEALED.into(), Value::String("forged".into()))?;
    assert!(
        as_alice.save_remote(alice_client.store()).await.is_err(),
        "Alice cannot change Bob's message"
    );
    let mut as_bob_message = bob_client.get_resource(&from_bob).await?;
    as_bob_message.set_unsafe(urls::SEALED.into(), Value::String("edited".into()))?;
    as_bob_message.save_remote(bob_client.store()).await?;

    // Bob may only append: he cannot change the conversation itself.
    let mut as_bob = bob_client.get_resource(&dm).await?;
    as_bob.set_name("Renamed by Bob")?;
    assert!(
        as_bob.save_remote(bob_client.store()).await.is_err(),
        "Bob cannot change the conversation"
    );

    Ok(())
}
