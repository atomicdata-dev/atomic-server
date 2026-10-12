//! The conversation migration (`conversation_migration.rs`): old
//! `SealedMessage` resources move into `ChatLog` pages with their payload
//! untouched. Run: cargo test -p atomic_lib --features db-redb --lib conversation_migration

use super::chat_migration::PAGE_SIZE;
use super::chat_migration_test::{stored_bytes, world, World};
use super::conversation_migration::CONVERSATION_DONE_KEY;
use super::trees::Tree;
use super::*;
use crate::{
    agents::Agent,
    chat_log::{entry_author, entry_created_at, migrated_entry_key},
    commit::{CommitBuilder, CommitOpts},
    conversation::{
        encryption_public_key, open_message, open_revealed_message, reveal_message_key,
        seal_message, ConversationKey, Keyring, Member,
    },
    loro::AtomicLoroDoc,
};
use loro::LoroValue;

/// Alice's and Bob's vault proofs, as far as these tests care.
const ALICE_PROOF: [u8; 64] = [1; 64];
const BOB_PROOF: [u8; 64] = [2; 64];

/// The epoch key both members share.
fn epoch_key(w: &World) -> ConversationKey {
    let mut keyring = Keyring::default();
    keyring
        .add_epoch(&[
            Member {
                agent: w.alice.subject.to_string(),
                encryption_key: encryption_public_key(&ALICE_PROOF),
            },
            Member {
                agent: w.bob.subject.to_string(),
                encryption_key: encryption_public_key(&BOB_PROOF),
            },
        ])
        .unwrap();
    keyring
        .open_current(&w.alice.subject.to_string(), &ALICE_PROOF)
        .unwrap()
}

/// An old `SealedMessage`, created the way the app did: a genesis commit with a
/// certificate, `write` limited to its author, signed by `agent`.
async fn old_sealed(db: &Db, agent: &Agent, conversation: &str, sealed: &str) -> String {
    // Distinct creation times, so the order is not a coin toss.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let doc = AtomicLoroDoc::new();
    let parent = Value::AtomicUrl(conversation.into());
    doc.set_property(
        urls::IS_A,
        &Value::ResourceArray(vec![urls::SEALED_MESSAGE.to_string().into()]),
    )
    .unwrap();
    doc.set_property(urls::PARENT, &parent).unwrap();
    doc.set_property(urls::SEALED, &Value::String(sealed.into()))
        .unwrap();
    doc.set_property(
        urls::WRITE,
        &Value::ResourceArray(vec![agent.subject.to_string().into()]),
    )
    .unwrap();
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = crate::Commit::create_did(builder, agent, db).await.unwrap();
    let subject = commit.subject.to_string();
    db.apply_commit(
        commit,
        &CommitOpts {
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        },
    )
    .await
    .unwrap();
    subject
}

/// Seals `text` and stores it as an old message; returns (subject, sealed).
async fn post(w: &World, key: &ConversationKey, from: &Agent, text: &str) -> (String, String) {
    let payload = serde_json::json!({ "text": text }).to_string();
    let sealed = seal_message(key, &w.chat, payload.as_bytes()).unwrap();
    let subject = old_sealed(&w.db, from, &w.chat, &sealed).await;
    (subject, sealed)
}

async fn pages_of(db: &Db, chat: &str) -> Vec<(String, Vec<(String, LoroValue)>)> {
    let mut found = Vec::new();
    for atom in
        find_in_prop_val_sub_index(db, urls::PARENT, Some(&Value::AtomicUrl(chat.into()))).flatten()
    {
        let page = db.get_resource(&atom.subject).await.unwrap();
        if !crate::hierarchy::is_chat_log(&page) {
            continue;
        }
        let created = page.get(urls::CREATED_AT).unwrap().to_int().unwrap();
        found.push((
            created,
            page.get_subject().pure_id(),
            page.build_state_doc().unwrap().list_entries(),
        ));
    }
    found.sort_by_key(|(c, s, _)| (*c, s.clone()));
    found.into_iter().map(|(_, s, e)| (s, e)).collect()
}

fn field_str(entry: &LoroValue, name: &str) -> Option<String> {
    match entry {
        LoroValue::Map(m) => match m.get(name) {
            Some(LoroValue::String(s)) => Some(s.to_string()),
            _ => None,
        },
        _ => None,
    }
}

async fn exists(db: &Db, subject: &str) -> bool {
    db.get_resource(&subject.into()).await.is_ok()
}

async fn sealed_count(db: &Db) -> usize {
    find_in_prop_val_sub_index(
        db,
        urls::IS_A,
        Some(&Value::AtomicUrl(urls::SEALED_MESSAGE.into())),
    )
    .flatten()
    .count()
}

#[tokio::test]
async fn messages_keep_their_payload_order_and_author_and_old_rows_go() {
    let w = world("conversation_migration_main").await;
    let db = &w.db;
    let key = epoch_key(&w);
    let mut sent = Vec::new();
    for i in 0..6 {
        let from = if i % 2 == 0 { &w.alice } else { &w.bob };
        sent.push((from, post(&w, &key, from, &format!("bericht {i}")).await));
    }
    let mut commit_rows = Vec::new();
    for (_, (subject, _)) in &sent {
        let last = db
            .get_resource(&subject.as_str().into())
            .await
            .unwrap()
            .get(urls::LAST_COMMIT)
            .unwrap()
            .to_string();
        assert!(db.get_propvals(&last).is_ok(), "premise: a genesis row");
        commit_rows.push(last);
    }
    assert_eq!(sealed_count(db).await, 6);

    db.kv
        .remove(Tree::PluginMeta, CONVERSATION_DONE_KEY)
        .unwrap();
    assert!(db.conversation_migration_pending().unwrap());
    db.migrate_conversations().await.unwrap();
    assert!(!db.conversation_migration_pending().unwrap());

    let pages = pages_of(db, &w.chat).await;
    assert_eq!(pages.len(), 1);
    let mut entries = pages[0].1.clone();
    entries.sort_by_key(|(_, e)| entry_created_at(e).unwrap());
    assert_eq!(entries.len(), 6);
    for (i, (entry_key, entry)) in entries.iter().enumerate() {
        let (from, (subject, sealed)) = &sent[i];
        let created = entry_created_at(entry).unwrap();
        assert_eq!(entry_key, &migrated_entry_key(created, subject));
        assert_eq!(
            entry_author(entry).unwrap(),
            from.subject.to_string(),
            "the original author is kept"
        );
        assert_eq!(field_str(entry, "t").as_deref(), Some(""));
        // The payload is the stored string, byte for byte...
        assert_eq!(field_str(entry, "s").as_deref(), Some(sealed.as_str()));
        // ...so it still opens, and its key still reveals just this message.
        let opened = open_message(std::slice::from_ref(&key), &w.chat, sealed).unwrap();
        assert_eq!(
            String::from_utf8(opened).unwrap(),
            format!("{{\"text\":\"bericht {i}\"}}")
        );
        let revealed = reveal_message_key(std::slice::from_ref(&key), sealed).unwrap();
        assert!(open_revealed_message(&revealed, &w.chat, sealed).is_ok());
    }

    // Old rows are gone: resources, index rows and genesis commit rows.
    for (_, (subject, _)) in &sent {
        assert!(!exists(db, subject).await);
    }
    assert_eq!(sealed_count(db).await, 0);
    for row in &commit_rows {
        assert!(db.get_propvals(row).is_err(), "{row} is still stored");
    }

    // A second run changes nothing.
    db.kv
        .remove(Tree::PluginMeta, CONVERSATION_DONE_KEY)
        .unwrap();
    db.migrate_conversations().await.unwrap();
    let again = pages_of(db, &w.chat).await;
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].1.len(), 6);
}

/// Pages hold 256 entries; a long conversation fills the first and goes on.
#[tokio::test]
async fn a_long_conversation_fills_pages_in_time_order() {
    let w = world("conversation_migration_pages").await;
    let db = &w.db;
    let key = epoch_key(&w);
    let mut sealed = Vec::new();
    for i in 0..(PAGE_SIZE + 4) {
        sealed.push(post(&w, &key, &w.bob, &format!("m{i}")).await.1);
    }
    db.kv
        .remove(Tree::PluginMeta, CONVERSATION_DONE_KEY)
        .unwrap();
    db.migrate_conversations().await.unwrap();
    let pages = pages_of(db, &w.chat).await;
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].1.len(), PAGE_SIZE);
    assert_eq!(pages[1].1.len(), 4);
    let first_page: Vec<String> = pages[0]
        .1
        .iter()
        .map(|(_, e)| field_str(e, "s").unwrap())
        .collect();
    for s in &sealed[..PAGE_SIZE] {
        assert!(first_page.contains(s));
    }
}

/// A crash after the pages are written and before the old rows are removed:
/// the next run finds the entries by key and writes nothing twice.
#[tokio::test]
async fn a_restart_between_pages_and_removal_does_not_duplicate() {
    let w = world("conversation_migration_resume").await;
    let db = &w.db;
    let key = epoch_key(&w);
    let mut subjects = Vec::new();
    for i in 0..4 {
        subjects.push(post(&w, &key, &w.alice, &format!("m{i}")).await.0);
    }
    db.migrate_conversation(&w.chat, false, None).await.unwrap();
    assert_eq!(pages_of(db, &w.chat).await[0].1.len(), 4);
    for s in &subjects {
        assert!(exists(db, s).await);
    }
    db.kv
        .remove(Tree::PluginMeta, CONVERSATION_DONE_KEY)
        .unwrap();
    db.migrate_conversations().await.unwrap();
    let pages = pages_of(db, &w.chat).await;
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].1.len(), 4);
    for s in &subjects {
        assert!(!exists(db, s).await);
    }
}

/// A browser cache of a hosted conversation writes no pages of its own, and
/// only drops the messages whose entry it already holds.
#[tokio::test]
async fn a_cache_of_a_hosted_drive_writes_nothing() {
    let w = world("conversation_migration_cache").await;
    let db = &w.db;
    let key = epoch_key(&w);
    let (message, _) = post(&w, &key, &w.alice, "hi").await;
    let hosted: HashSet<String> = HashSet::new();
    db.kv
        .remove(Tree::PluginMeta, CONVERSATION_DONE_KEY)
        .unwrap();
    let step = db
        .migrate_conversations_step(100, Some(&hosted))
        .await
        .unwrap();
    assert!(step.finished);
    assert!(pages_of(db, &w.chat).await.is_empty());
    assert!(exists(db, &message).await);
}

/// Fifty messages, before and after.
#[tokio::test]
async fn migrating_a_conversation_shrinks_the_store() {
    const N: usize = 50;
    let w = world("conversation_migration_size").await;
    let db = &w.db;
    let key = epoch_key(&w);
    let (baseline, base_trees) = stored_bytes(db);
    for i in 0..N {
        let from = if i % 2 == 0 { &w.alice } else { &w.bob };
        post(
            &w,
            &key,
            from,
            &format!("Bericht nummer {i}, een gewone zin."),
        )
        .await;
    }
    db.kv
        .remove(Tree::PluginMeta, CONVERSATION_DONE_KEY)
        .unwrap();
    let (before, _) = stored_bytes(db);
    db.migrate_conversations().await.unwrap();
    let (after, after_trees) = stored_bytes(db);
    for ((t, r0, b0), (_, r1, b1)) in base_trees.iter().zip(&after_trees) {
        println!("{t:?}: {r0} rows {b0} B -> {r1} rows {b1} B");
    }
    println!(
        "{N} sealed messages: {before} B before, {after} B after, baseline {baseline} B; \
         per message {} B -> {} B",
        (before - baseline) / N,
        (after - baseline) / N
    );
    assert!(after < before, "{before} -> {after}");
}
