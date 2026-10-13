//! The server rule for `ChatLog` pages: entries are append-only per author.
//! See planning/chat-log.md.
//! Run: cargo test -p atomic_lib --features db-redb --test chat_log
#![cfg(feature = "db-redb")]

use atomic_lib::{
    agents::{Agent, ForAgent},
    chat_log::{Entry, MAX_FUTURE_MS},
    commit::{CommitBuilder, CommitOpts},
    hierarchy::{check_rights, Right},
    loro::AtomicLoroDoc,
    urls, Commit, Db, Storelike, Subject, Value,
};

fn opts(agent: &Agent) -> CommitOpts {
    CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    }
}

fn grant(res: &mut atomic_lib::Resource, prop: &str, agents: &[&Agent]) {
    res.set_unsafe(
        prop.into(),
        Value::ResourceArray(
            agents
                .iter()
                .map(|a| a.subject.to_string().into())
                .collect(),
        ),
    )
    .unwrap();
}

struct World {
    db: Db,
    chat: String,
    alice: Agent,
    bob: Agent,
    eve: Agent,
    carol: Agent,
}

/// Alice owns the drive; Bob and Eve may append to the chat; Carol may write to it.
async fn world(id: &str) -> World {
    let db = Db::init_temp(id).await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();
    let bob = db.create_agent(Some("Bob")).await.unwrap();
    let eve = db.create_agent(Some("Eve")).await.unwrap();
    let carol = db.create_agent(Some("Carol")).await.unwrap();
    let chat = db
        .create_resource(urls::CHATROOM, &drive, "Chat", None)
        .await
        .unwrap();
    let mut chat_res = db.get_resource(&Subject::from(chat.clone())).await.unwrap();
    grant(&mut chat_res, urls::APPEND, &[&bob, &eve]);
    grant(&mut chat_res, urls::READ, &[&bob, &eve, &carol]);
    grant(&mut chat_res, urls::WRITE, &[&carol]);
    db.add_resource_opts(&chat_res, false, true, true)
        .await
        .unwrap();
    World {
        db,
        chat,
        alice,
        bob,
        eve,
        carol,
    }
}

fn entry(agent: &Agent, text: &str) -> Entry {
    Entry::new(agent.subject.to_string(), text, atomic_lib::utils::now())
}

/// Creates a page as `agent`, with the given entries already in its genesis.
async fn create_page(
    w: &World,
    agent: &Agent,
    entries: &[Entry],
) -> Result<(Subject, Vec<String>), atomic_lib::errors::AtomicError> {
    let doc = AtomicLoroDoc::new();
    let keys: Vec<String> = entries.iter().map(|e| doc.add_entry(e).unwrap()).collect();
    let mut builder = CommitBuilder::new("placeholder".into());
    // With a preset `loroUpdate` the builder's `set` only feeds the genesis
    // certificate (parent, drive); the state comes from the doc.
    let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
    let parent = Value::AtomicUrl(w.chat.clone().into());
    doc.set_property(urls::IS_A, &is_a).unwrap();
    doc.set_property(urls::PARENT, &parent).unwrap();
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = Commit::create_did(builder, agent, &w.db).await?;
    let subject = commit.subject.clone();
    w.db.apply_commit(commit, &opts(agent)).await?;
    Ok((subject, keys))
}

/// Edits the page's doc as `agent` and sends the delta as a normal commit.
async fn edit(
    w: &World,
    agent: &Agent,
    page: &Subject,
    f: impl FnOnce(&AtomicLoroDoc),
) -> Result<(), atomic_lib::errors::AtomicError> {
    let resource = w.db.get_resource(page).await.unwrap();
    let doc = resource.build_state_doc().unwrap();
    let vv = doc.oplog_vv();
    f(&doc);
    doc.commit();
    let mut builder = CommitBuilder::new(page.clone());
    builder.set_loro_update(doc.export_updates_since(&vv));
    let commit = builder.sign(agent, &w.db, &resource).await?;
    w.db.apply_commit(commit, &opts(agent)).await?;
    Ok(())
}

async fn stored_doc(w: &World, page: &Subject) -> AtomicLoroDoc {
    w.db.get_resource(page)
        .await
        .unwrap()
        .build_state_doc()
        .unwrap()
}

#[tokio::test]
async fn author_adds_edits_and_deletes_own_entry() {
    let w = world("chat_log_own").await;
    let (page, _) = create_page(&w, &w.bob, &[]).await.unwrap();

    let key = new_key();
    edit(&w, &w.bob, &page, |d| {
        d.put_entry(&key, &entry(&w.bob, "hi")).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(stored_doc(&w, &page).await.list_entries().len(), 1);

    let mut edited = entry(&w.bob, "hi, edited");
    edited.edited_at = Some(atomic_lib::utils::now());
    edit(&w, &w.bob, &page, |d| d.put_entry(&key, &edited).unwrap())
        .await
        .unwrap();
    let doc = stored_doc(&w, &page).await;
    assert_eq!(
        atomic_lib::chat_log::entry_text(&doc.get_entry(&key).unwrap()),
        Some("hi, edited")
    );

    edit(&w, &w.bob, &page, |d| d.remove_entry(&key).unwrap())
        .await
        .unwrap();
    assert!(stored_doc(&w, &page).await.list_entries().is_empty());
}

fn new_key() -> String {
    atomic_lib::chat_log::new_entry_key(atomic_lib::utils::now())
}

#[tokio::test]
async fn member_cannot_edit_or_delete_anothers_entry() {
    let w = world("chat_log_others").await;
    let (page, keys) = create_page(&w, &w.bob, &[entry(&w.bob, "bob says")])
        .await
        .unwrap();
    let key = keys[0].clone();

    // Eve may append her own entry ...
    edit(&w, &w.eve, &page, |d| {
        d.put_entry(&new_key(), &entry(&w.eve, "eve says")).unwrap()
    })
    .await
    .unwrap();

    // ... but not rewrite, claim or remove Bob's.
    let err = edit(&w, &w.eve, &page, |d| {
        d.put_entry(&key, &entry(&w.eve, "bob says nothing"))
            .unwrap()
    })
    .await
    .expect_err("editing someone else's entry (even claiming it) must fail");
    assert!(err.to_string().contains("not yours"), "{err}");

    let err = edit(&w, &w.eve, &page, |d| {
        d.put_entry(&key, &entry(&w.bob, "forged")).unwrap()
    })
    .await
    .expect_err("forging an entry in someone else's name over their key must fail");
    assert!(err.to_string().contains("not yours"), "{err}");

    edit(&w, &w.eve, &page, |d| d.remove_entry(&key).unwrap())
        .await
        .expect_err("deleting someone else's entry must fail");

    // A new entry in someone else's name fails too.
    edit(&w, &w.eve, &page, |d| {
        d.put_entry(&new_key(), &entry(&w.bob, "bob, allegedly"))
            .unwrap()
    })
    .await
    .expect_err("an entry authored by another agent must fail");

    let doc = stored_doc(&w, &page).await;
    assert_eq!(doc.list_entries().len(), 2);
    assert_eq!(
        atomic_lib::chat_log::entry_text(&doc.get_entry(&key).unwrap()),
        Some("bob says")
    );
}

#[tokio::test]
async fn member_cannot_change_page_properties() {
    let w = world("chat_log_props").await;
    let (page, _) = create_page(&w, &w.bob, &[]).await.unwrap();

    for (prop, val) in [
        (urls::NAME, Value::String("Mine now".into())),
        (
            urls::WRITE,
            Value::ResourceArray(vec![w.bob.subject.to_string().into()]),
        ),
        (
            urls::READ,
            Value::ResourceArray(vec![urls::PUBLIC_AGENT.to_string().into()]),
        ),
    ] {
        edit(&w, &w.bob, &page, |d| {
            d.set_property(prop, &val).unwrap();
            d.put_entry(&new_key(), &entry(&w.bob, "sneaky")).unwrap();
        })
        .await
        .expect_err("a member must not change page properties");
    }
    assert!(stored_doc(&w, &page).await.list_entries().is_empty());
}

#[tokio::test]
async fn writer_on_the_chat_can_delete_anyones_entry() {
    let w = world("chat_log_moderator").await;
    let (page, keys) = create_page(&w, &w.bob, &[entry(&w.bob, "spam")])
        .await
        .unwrap();
    edit(&w, &w.carol, &page, |d| d.remove_entry(&keys[0]).unwrap())
        .await
        .expect("a writer on the parent moderates");
    assert!(stored_doc(&w, &page).await.list_entries().is_empty());
    // The drive owner (write inherited from the drive) can too.
    let key = new_key();
    edit(&w, &w.bob, &page, |d| {
        d.put_entry(&key, &entry(&w.bob, "again")).unwrap()
    })
    .await
    .unwrap();
    edit(&w, &w.alice, &page, |d| d.remove_entry(&key).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn page_genesis_grants_no_write_and_needs_append() {
    let w = world("chat_log_genesis").await;
    let (page, _) = create_page(&w, &w.bob, &[entry(&w.bob, "first")])
        .await
        .unwrap();
    let res = w.db.get_resource(&page).await.unwrap();
    assert!(res.get(urls::WRITE).is_err(), "no write grant at genesis");
    let bob = ForAgent::AgentSubject(w.bob.subject.clone());
    check_rights(&w.db, &res, &bob, Right::Write)
        .await
        .expect_err("the creator has no write on the page");
    check_rights(&w.db, &res, &bob, Right::Append)
        .await
        .expect("but appends via the chat");

    // A stranger without append on the chat cannot create a page.
    let stranger = w.db.create_agent(Some("Stranger")).await.unwrap();
    create_page(&w, &stranger, &[])
        .await
        .expect_err("genesis needs append on the chat");
}

#[tokio::test]
async fn genesis_entries_must_be_the_creators() {
    let w = world("chat_log_genesis_authors").await;
    create_page(&w, &w.bob, &[entry(&w.eve, "forged")])
        .await
        .expect_err("a genesis entry by another author must fail");
    // A writer on the chat may seed a page with anyone's entries? No: genesis is always own-entries.
    create_page(&w, &w.carol, &[entry(&w.carol, "ok")])
        .await
        .expect("own entries pass");
}

#[tokio::test]
async fn member_cannot_give_themselves_write_at_genesis() {
    let w = world("chat_log_genesis_write").await;
    let mut builder = CommitBuilder::new("placeholder".into());
    let doc = AtomicLoroDoc::new();
    let parent = Value::AtomicUrl(w.chat.clone().into());
    doc.set_property(
        urls::IS_A,
        &Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]),
    )
    .unwrap();
    doc.set_property(urls::PARENT, &parent).unwrap();
    doc.set_property(
        urls::WRITE,
        &Value::ResourceArray(vec![w.bob.subject.to_string().into()]),
    )
    .unwrap();
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = Commit::create_did(builder, &w.bob, &w.db).await.unwrap();
    w.db.apply_commit(commit, &opts(&w.bob))
        .await
        .expect_err("a member must not mint a page they can rewrite");
}

#[tokio::test]
async fn entries_from_the_far_future_are_rejected() {
    let w = world("chat_log_future").await;
    let (page, _) = create_page(&w, &w.bob, &[]).await.unwrap();
    let now = atomic_lib::utils::now();

    let mut soon = entry(&w.bob, "soon");
    soon.created_at = now + MAX_FUTURE_MS / 2;
    edit(&w, &w.bob, &page, |d| {
        d.add_entry(&soon).unwrap();
    })
    .await
    .expect("five minutes ahead is clock skew, not an attack");

    let mut late = entry(&w.bob, "late");
    late.created_at = now + MAX_FUTURE_MS + 60_000;
    edit(&w, &w.bob, &page, |d| {
        d.add_entry(&late).unwrap();
    })
    .await
    .expect_err("more than ten minutes ahead must fail");

    // Also at genesis, and also for a writer.
    create_page(&w, &w.bob, &[late.clone()])
        .await
        .expect_err("genesis too");
    let mut late_carol = late.clone();
    late_carol.author = w.carol.subject.to_string();
    edit(&w, &w.carol, &page, |d| {
        d.add_entry(&late_carol).unwrap();
    })
    .await
    .expect_err("writers too");

    // Older entries (offline sending) are fine.
    let mut old = entry(&w.bob, "old");
    old.created_at = now - 3 * 24 * 3600 * 1000;
    edit(&w, &w.bob, &page, |d| {
        d.add_entry(&old).unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn entries_survive_a_property_edit_by_a_writer() {
    let w = world("chat_log_writer_edit").await;
    let (page, _) = create_page(&w, &w.bob, &[entry(&w.bob, "keep me")])
        .await
        .unwrap();
    edit(&w, &w.carol, &page, |d| {
        d.set_property(urls::NAME, &Value::String("Renamed".into()))
            .unwrap()
    })
    .await
    .unwrap();
    let doc = stored_doc(&w, &page).await;
    assert_eq!(doc.list_entries().len(), 1);
    assert_eq!(
        w.db.get_resource(&page)
            .await
            .unwrap()
            .get(urls::NAME)
            .unwrap()
            .to_string(),
        "Renamed"
    );
}

#[tokio::test]
async fn entry_commits_leave_last_commit_at_the_genesis_value() {
    let w = world("chat_log_last_commit").await;
    let (page, _) = create_page(&w, &w.bob, &[entry(&w.bob, "first")])
        .await
        .unwrap();
    let genesis = w.db.get_resource(&page).await.unwrap();
    let stamp = genesis.get(urls::LAST_COMMIT).unwrap().to_string();

    edit(&w, &w.bob, &page, |d| {
        d.add_entry(&entry(&w.bob, "second")).unwrap();
    })
    .await
    .unwrap();
    // Another member, whose doc does not match any previousCommit.
    edit(&w, &w.eve, &page, |d| {
        d.add_entry(&entry(&w.eve, "third")).unwrap();
    })
    .await
    .unwrap();

    let now = w.db.get_resource(&page).await.unwrap();
    assert_eq!(now.get(urls::LAST_COMMIT).unwrap().to_string(), stamp);
    assert_eq!(now.build_state_doc().unwrap().list_entries().len(), 3);
}
