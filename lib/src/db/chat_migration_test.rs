//! The chat log migration (`chat_migration.rs`): old `Message` resources move
//! into `ChatLog` pages. Run: cargo test -p atomic_lib --features db-redb --lib chat_migration

use super::chat_migration::{DONE_KEY, PAGE_SIZE};
use super::trees::Tree;
use super::*;
use crate::{
    agents::Agent,
    chat_log::{entry_author, entry_created_at, entry_text, migrated_entry_key, Entry},
    commit::{CommitBuilder, CommitOpts},
    loro::AtomicLoroDoc,
};
use loro::LoroValue;

pub(super) struct World {
    pub db: Db,
    pub alice: Agent,
    pub bob: Agent,
    pub drive: String,
    pub chat: String,
}

fn grant(res: &mut Resource, prop: &str, agents: &[&Agent]) {
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

/// Alice owns the drive. Bob may append to the chat.
pub(super) async fn world(id: &str) -> World {
    let db = Db::init_temp(id).await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();
    let bob = db.create_agent(Some("Bob")).await.unwrap();
    let chat = db
        .create_resource(urls::CHATROOM, &drive, "Chat", None)
        .await
        .unwrap();
    let mut chat_res = db.get_resource(&chat.as_str().into()).await.unwrap();
    grant(&mut chat_res, urls::APPEND, &[&bob]);
    grant(&mut chat_res, urls::READ, &[&bob]);
    db.add_resource_opts(&chat_res, false, true, true)
        .await
        .unwrap();
    World {
        db,
        alice,
        bob,
        drive,
        chat,
    }
}

struct NewMessage<'a> {
    parent: &'a str,
    about: Option<&'a str>,
    text: String,
    reply_to: Option<&'a str>,
    follow: bool,
}

impl<'a> NewMessage<'a> {
    fn new(parent: &'a str, text: impl Into<String>) -> Self {
        Self {
            parent,
            about: None,
            text: text.into(),
            reply_to: None,
            follow: false,
        }
    }
}

/// An old-style `Message` resource, created the way the app did: a genesis
/// commit with a certificate, signed by `agent`.
async fn old_message(db: &Db, agent: &Agent, m: NewMessage<'_>) -> String {
    // Distinct creation times, so the order is not a coin toss.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let mut classes: Vec<crate::values::SubResource> = vec![urls::MESSAGE.to_string().into()];
    if m.follow {
        classes.push(urls::FOLLOW_EVENT.to_string().into());
    }
    let doc = AtomicLoroDoc::new();
    let parent = Value::AtomicUrl(m.parent.into());
    doc.set_property(urls::IS_A, &Value::ResourceArray(classes))
        .unwrap();
    doc.set_property(urls::PARENT, &parent).unwrap();
    doc.set_property(urls::DESCRIPTION, &Value::Markdown(m.text))
        .unwrap();
    if let Some(about) = m.about {
        doc.set_property(urls::ABOUT, &Value::AtomicUrl(about.into()))
            .unwrap();
    }
    if let Some(reply) = m.reply_to {
        doc.set_property(urls::REPLY_TO, &Value::AtomicUrl(reply.into()))
            .unwrap();
    }
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

/// The pages of a chat (`about` for comments) with their entries, by page
/// creation time.
async fn pages(
    db: &Db,
    parent: &str,
    about: Option<&str>,
) -> Vec<(String, Vec<(String, LoroValue)>)> {
    let index = match about {
        Some(about) => {
            find_in_prop_val_sub_index(db, urls::ABOUT, Some(&Value::AtomicUrl(about.into())))
        }
        None => {
            find_in_prop_val_sub_index(db, urls::PARENT, Some(&Value::AtomicUrl(parent.into())))
        }
    };
    let mut found = Vec::new();
    for atom in index.flatten() {
        let page = db.get_resource(&atom.subject).await.unwrap();
        if !crate::hierarchy::is_chat_log(&page) {
            continue;
        }
        let created_at = page.get(urls::CREATED_AT).unwrap().to_int().unwrap();
        found.push((
            created_at,
            page.get_subject().pure_id(),
            page.build_state_doc().unwrap().list_entries(),
        ));
    }
    found.sort_by_key(|(created_at, subject, _)| (*created_at, subject.clone()));
    found.into_iter().map(|(_, s, e)| (s, e)).collect()
}

fn field(entry: &LoroValue, name: &str) -> Option<LoroValue> {
    match entry {
        LoroValue::Map(m) => m.get(name).cloned(),
        _ => None,
    }
}

fn field_str(entry: &LoroValue, name: &str) -> Option<String> {
    match field(entry, name) {
        Some(LoroValue::String(s)) => Some(s.to_string()),
        _ => None,
    }
}

async fn message_exists(db: &Db, subject: &str) -> bool {
    db.get_resource(&subject.into()).await.is_ok()
}

#[tokio::test]
async fn groups_split_at_256_keep_authors_and_map_replies() {
    let w = world("chat_migration_main").await;
    let db = &w.db;
    let other_chat = db
        .create_resource(urls::CHATROOM, &w.drive, "Other", None)
        .await
        .unwrap();
    let folder = db
        .create_resource(urls::FOLDER, &w.drive, "Comments", None)
        .await
        .unwrap();
    let item = db
        .create_resource(urls::FOLDER, &w.drive, "Commented", None)
        .await
        .unwrap();

    // 300 messages: Alice and Bob take turns.
    let mut subjects: Vec<String> = Vec::new();
    for i in 0..300 {
        let author = if i % 2 == 0 { &w.alice } else { &w.bob };
        let mut m = NewMessage::new(&w.chat, format!("message {i}"));
        if i == 10 {
            m.reply_to = Some(subjects[5].as_str());
        }
        if i == 270 {
            m.reply_to = Some(subjects[5].as_str());
        }
        if i == 271 {
            m.reply_to = Some(subjects[270].as_str());
        }
        subjects.push(old_message(db, author, m).await);
    }
    let follow = old_message(
        db,
        &w.alice,
        NewMessage {
            follow: true,
            ..NewMessage::new(&other_chat, "Started the meeting.")
        },
    )
    .await;
    let outside = format!("{}/not-a-message", w.drive);
    let replying_outside = old_message(
        db,
        &w.alice,
        NewMessage {
            reply_to: Some(&outside),
            ..NewMessage::new(&other_chat, "points elsewhere")
        },
    )
    .await;
    let comment = old_message(
        db,
        &w.bob,
        NewMessage {
            about: Some(&item),
            ..NewMessage::new(&folder, "a comment")
        },
    )
    .await;

    // The created times as the resources report them.
    let mut created = HashMap::new();
    for s in subjects
        .iter()
        .chain([&follow, &replying_outside, &comment])
    {
        let at = db
            .get_resource(&s.as_str().into())
            .await
            .unwrap()
            .get(urls::CREATED_AT)
            .unwrap()
            .to_int()
            .unwrap();
        created.insert(s.clone(), at);
    }

    let mut commit_rows = Vec::new();
    for s in subjects
        .iter()
        .chain([&follow, &replying_outside, &comment])
    {
        let last = db
            .get_resource(&s.as_str().into())
            .await
            .unwrap()
            .get(urls::LAST_COMMIT)
            .unwrap()
            .to_string();
        assert!(
            db.get_propvals(&last).is_ok(),
            "premise: a genesis commit row"
        );
        commit_rows.push(last);
    }
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    db.migrate_messages().await.unwrap();
    assert!(!db.message_migration_pending().unwrap());
    for row in &commit_rows {
        assert!(db.get_propvals(row).is_err(), "{row} is still stored");
    }

    // Group chat: 256 + 44 entries on two pages, in time order.
    let chat_pages = pages(db, &w.chat, None).await;
    assert_eq!(chat_pages.len(), 2);
    assert_eq!(chat_pages[0].1.len(), PAGE_SIZE);
    assert_eq!(chat_pages[1].1.len(), 300 - PAGE_SIZE);
    // Within a page the entries sort by key (createdAt, second precision); `c`
    // has the exact millisecond.
    let mut all: Vec<(usize, &(String, LoroValue))> = chat_pages
        .iter()
        .enumerate()
        .flat_map(|(p, (_, e))| e.iter().map(move |e| (p, e)))
        .collect();
    all.sort_by_key(|(_, (_, v))| entry_created_at(v).unwrap());
    let page_of: Vec<usize> = all.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        page_of.iter().filter(|p| **p == 0).count(),
        PAGE_SIZE,
        "the oldest 256 fill the first page"
    );
    assert!(page_of[..PAGE_SIZE].iter().all(|p| *p == 0));
    let all: Vec<&(String, LoroValue)> = all.into_iter().map(|(_, e)| e).collect();
    for (i, (key, entry)) in all.iter().enumerate() {
        let subject = &subjects[i];
        assert_eq!(key, &migrated_entry_key(created[subject], subject));
        assert_eq!(entry_text(entry), Some(format!("message {i}").as_str()));
        assert_eq!(entry_created_at(entry), Some(created[subject]));
        let expected_author = if i % 2 == 0 { &w.alice } else { &w.bob };
        assert_eq!(
            entry_author(entry),
            Some(expected_author.subject.to_string().as_str()),
            "the original author is kept"
        );
        assert!(field(entry, "k").is_none());
    }

    // Replies point at the new id, also across pages. Others stay.
    let entry_id = |i: usize| {
        let page = &chat_pages[page_of[i]].0;
        format!("{page}#{}", all[i].0)
    };
    assert_eq!(field_str(&all[10].1, "r"), Some(entry_id(5)));
    assert_eq!(field_str(&all[270].1, "r"), Some(entry_id(5)));
    assert_eq!(field_str(&all[271].1, "r"), Some(entry_id(270)));
    assert!(field(&all[0].1, "r").is_none());

    // Follow events keep their kind; replies to something else keep the subject.
    let other = pages(db, &other_chat, None).await;
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].1.len(), 2);
    assert_eq!(
        field_str(&other[0].1[0].1, "k").as_deref(),
        Some(urls::FOLLOW_EVENT)
    );
    assert_eq!(field_str(&other[0].1[1].1, "r"), Some(outside));

    // Comments: one page for the item, `about` set, under the folder.
    let comments = pages(db, &folder, Some(&item)).await;
    assert_eq!(comments.len(), 1);
    assert_eq!(
        entry_author(&comments[0].1[0].1),
        Some(w.bob.subject.to_string().as_str())
    );
    let page = db
        .get_resource(&comments[0].0.as_str().into())
        .await
        .unwrap();
    assert_eq!(page.get(urls::PARENT).unwrap().to_string(), folder);
    assert_eq!(page.get(urls::ABOUT).unwrap().to_string(), item);

    // The old resources and everything stored for them are gone.
    for s in subjects
        .iter()
        .chain([&follow, &replying_outside, &comment])
    {
        assert!(!message_exists(db, s).await, "{s} is still there");
        let pure = Subject::from(s.as_str()).pure_id();
        for tree in [Tree::Resources, Tree::LoroSnapshots] {
            assert!(db.kv.get(tree, pure.as_bytes()).unwrap().is_none());
        }
        assert!(crate::envelopes::envelopes(db, &pure).is_empty());
        let body = crate::identifiers::identifier_body(s).unwrap();
        let commit_row = crate::identifiers::commit_subject(body);
        assert!(
            db.get_propvals(&crate::identifiers::canonicalize_scheme(&commit_row))
                .is_err(),
            "the genesis commit row of {s} is still there"
        );
    }
    let still_messages = find_in_prop_val_sub_index(
        db,
        urls::IS_A,
        Some(&Value::AtomicUrl(urls::MESSAGE.into())),
    )
    .flatten()
    .count();
    assert_eq!(still_messages, 0);

    // A second run, even with the marker gone, changes nothing.
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    db.migrate_messages().await.unwrap();
    assert_eq!(pages(db, &w.chat, None).await.len(), 2);
    assert_eq!(pages(db, &other_chat, None).await.len(), 1);
}

#[tokio::test]
async fn a_run_that_stopped_after_the_pages_resumes_without_duplicates() {
    let w = world("chat_migration_resume").await;
    let db = &w.db;
    let mut subjects: Vec<String> = Vec::new();
    for i in 0..5 {
        let mut m = NewMessage::new(&w.chat, format!("m{i}"));
        if i == 3 {
            m.reply_to = Some(subjects[1].as_str());
        }
        subjects.push(old_message(db, &w.alice, m).await);
    }
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();

    // The pages were written, the process stopped before the removals.
    db.migrate_group(&w.chat, None, false, None).await.unwrap();
    assert_eq!(pages(db, &w.chat, None).await.len(), 1);
    for s in &subjects {
        assert!(message_exists(db, s).await);
    }

    // A late straggler from an old client arrives meanwhile.
    let late = old_message(db, &w.bob, NewMessage::new(&w.chat, "late")).await;

    db.migrate_messages().await.unwrap();
    let after = pages(db, &w.chat, None).await;
    let texts: Vec<String> = after
        .iter()
        .flat_map(|(_, e)| e.iter().map(|(_, v)| entry_text(v).unwrap().to_string()))
        .collect();
    let mut sorted = texts.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        ["late", "m0", "m1", "m2", "m3", "m4"],
        "no duplicates"
    );
    for s in subjects.iter().chain([&late]) {
        assert!(!message_exists(db, s).await);
    }
    // The reply still points into the first page, where its target is.
    let first = &after[0];
    let (_, reply) = first
        .1
        .iter()
        .find(|(_, v)| entry_text(v) == Some("m3"))
        .unwrap();
    let (target_key, _) = first
        .1
        .iter()
        .find(|(_, v)| entry_text(v) == Some("m1"))
        .unwrap();
    assert_eq!(
        field_str(reply, "r"),
        Some(format!("{}#{target_key}", first.0))
    );
}

#[tokio::test]
async fn steps_report_progress_and_resume_from_the_stored_state() {
    let w = world("chat_migration_steps").await;
    let db = &w.db;
    let rooms: Vec<String> = {
        let mut v = Vec::new();
        for i in 0..3 {
            v.push(
                db.create_resource(urls::CHATROOM, &w.drive, &format!("Room {i}"), None)
                    .await
                    .unwrap(),
            );
        }
        v
    };
    for room in &rooms {
        for i in 0..4 {
            old_message(db, &w.alice, NewMessage::new(room, format!("m{i}"))).await;
        }
    }
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    assert!(db.message_migration_pending().unwrap());

    let first = db.migrate_messages_step(1, None).await.unwrap();
    assert!(!first.finished);
    assert_eq!((first.done, first.total), (4, 12));

    // Same state read back: a new step carries on, no restart.
    let second = db.migrate_messages_step(1, None).await.unwrap();
    assert_eq!((second.done, second.total, second.finished), (8, 12, false));
    let last = db.migrate_messages_step(1, None).await.unwrap();
    assert!(last.finished);
    assert_eq!(last.total, 12);
    assert!(!db.message_migration_pending().unwrap());
    assert!(db.migrate_messages_step(1, None).await.unwrap().finished);

    for room in &rooms {
        let p = pages(db, room, None).await;
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].1.len(), 4);
    }
}

#[tokio::test]
async fn edited_messages_get_an_edited_time() {
    let w = world("chat_migration_edited").await;
    let db = &w.db;
    let subject = old_message(db, &w.alice, NewMessage::new(&w.chat, "first draft")).await;
    let untouched = old_message(db, &w.alice, NewMessage::new(&w.chat, "as written")).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let resource = db.get_resource(&subject.as_str().into()).await.unwrap();
    let mut b = CommitBuilder::new(subject.as_str().into());
    b.set(
        urls::DESCRIPTION.into(),
        Value::Markdown("second draft".into()),
    );
    let commit = b.sign(&w.alice, db, &resource).await.unwrap();
    db.apply_commit(
        commit,
        &CommitOpts {
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        },
    )
    .await
    .unwrap();

    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    db.migrate_messages().await.unwrap();
    let p = pages(db, &w.chat, None).await;
    let entries = &p[0].1;
    let edited = entries
        .iter()
        .find(|(_, v)| entry_text(v) == Some("second draft"))
        .expect("the edited text is migrated");
    assert!(matches!(field(&edited.1, "e"), Some(LoroValue::I64(_))));
    let plain = entries
        .iter()
        .find(|(_, v)| entry_text(v) == Some("as written"))
        .unwrap();
    assert!(field(&plain.1, "e").is_none());
    let _ = untouched;
}

/// A migrated page obeys the normal rule for later commits.
#[tokio::test]
async fn a_member_edits_own_migrated_entry_and_not_another() {
    let w = world("chat_migration_rights").await;
    let db = &w.db;
    old_message(db, &w.alice, NewMessage::new(&w.chat, "from alice")).await;
    old_message(db, &w.bob, NewMessage::new(&w.chat, "from bob")).await;
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    db.migrate_messages().await.unwrap();

    let (page, entries) = pages(db, &w.chat, None).await.remove(0);
    let page_subject = Subject::from(page.as_str());
    let key_of = |text: &str| {
        entries
            .iter()
            .find(|(_, v)| entry_text(v) == Some(text))
            .unwrap()
            .0
            .clone()
    };

    // The page grants its creator nothing.
    let resource = db.get_resource(&page_subject).await.unwrap();
    assert!(resource.get(urls::WRITE).is_err());

    let rights = |agent: &Agent| CommitOpts {
        validate_signature: true,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    async fn edit(
        db: &Db,
        agent: &Agent,
        page: &Subject,
        opts: &CommitOpts,
        f: impl FnOnce(&AtomicLoroDoc),
    ) -> AtomicResult<()> {
        let resource = db.get_resource(page).await.unwrap();
        let doc = resource.build_state_doc().unwrap();
        let vv = doc.oplog_vv();
        f(&doc);
        doc.commit();
        let mut builder = CommitBuilder::new(page.clone());
        builder.set_loro_update(doc.export_updates_since(&vv));
        let commit = builder.sign(agent, db, &resource).await?;
        db.apply_commit(commit, opts).await?;
        Ok(())
    }

    // Bob rewrites his own entry.
    let own = key_of("from bob");
    edit(db, &w.bob, &page_subject, &rights(&w.bob), |d| {
        let mut e = Entry::new(w.bob.subject.to_string(), "bob, edited", 1);
        e.created_at = entry_created_at(&d.get_entry(&own).unwrap()).unwrap();
        d.put_entry(&own, &e).unwrap();
    })
    .await
    .expect("a member may edit their own migrated entry");

    // Not Alice's.
    let theirs = key_of("from alice");
    let denied = edit(db, &w.bob, &page_subject, &rights(&w.bob), |d| {
        let e = Entry::new(w.bob.subject.to_string(), "hijacked", 1);
        d.put_entry(&theirs, &e).unwrap();
    })
    .await;
    assert!(denied.is_err(), "Bob must not change Alice's entry");
    let denied = edit(db, &w.bob, &page_subject, &rights(&w.bob), |d| {
        d.remove_entry(&theirs).unwrap();
    })
    .await;
    assert!(denied.is_err(), "Bob must not delete Alice's entry");

    // The owner of the chat can (inherited write).
    edit(db, &w.alice, &page_subject, &rights(&w.alice), |d| {
        d.remove_entry(&own).unwrap();
    })
    .await
    .expect("a moderator may remove any entry");
}

pub(super) fn stored_bytes(store: &Db) -> (usize, Vec<(Tree, usize, usize)>) {
    let trees = [
        Tree::Resources,
        Tree::LoroSnapshots,
        Tree::Envelopes,
        Tree::PropValSub,
        Tree::ValPropSub,
        Tree::QueryMembers,
        Tree::WatchedQueries,
        Tree::SearchPostings,
        Tree::SearchDocs,
        Tree::SearchTrigrams,
        Tree::DidMapping,
        Tree::DriveMapping,
        Tree::Outbox,
        Tree::PluginMeta,
    ];
    let compressed = super::compressed_kv::CompressedKv::new(store.kv.clone());
    let mut total = 0;
    let mut per_tree = Vec::new();
    for tree in trees {
        let (mut rows, mut bytes) = (0usize, 0usize);
        for kv in store.kv.iter_tree(tree) {
            let (key, val) = kv.unwrap();
            rows += 1;
            bytes += key.len()
                + if super::compressed_kv::is_compressed_tree(tree) {
                    compressed.encoded(tree, &key, &val, &[]).len()
                } else {
                    val.len()
                };
        }
        total += bytes;
        per_tree.push((tree, rows, bytes));
    }
    (total, per_tree)
}

/// The point of it all: a chat of old messages takes far less after.
#[tokio::test]
async fn migrating_a_chat_shrinks_the_store() {
    const N: usize = 200;
    let w = world("chat_migration_size").await;
    let db = &w.db;
    let (baseline, _) = stored_bytes(db);
    for i in 0..N {
        let m = NewMessage::new(
            &w.chat,
            format!("Hallo dit is bericht nummer {i}, een gewone zin."),
        );
        old_message(db, &w.alice, m).await;
    }
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    let (before, before_trees) = stored_bytes(db);
    db.migrate_messages().await.unwrap();
    let (after, after_trees) = stored_bytes(db);
    let per_before = (before - baseline) / N;
    let per_after = (after - baseline) / N;
    println!(
        "{N} messages: {before} B before, {after} B after, baseline {baseline} B; \
         per message {per_before} B -> {per_after} B"
    );
    for ((tree, rows_b, bytes_b), (_, rows_a, bytes_a)) in before_trees.iter().zip(&after_trees) {
        println!("{tree:?}: {rows_b} rows {bytes_b} B -> {rows_a} rows {bytes_a} B");
    }
    assert!(
        per_after * 10 < per_before,
        "expected at least 10x smaller per message: {per_before} -> {per_after}"
    );
}

/// A store that only caches a drive the server hosts (the browser) writes no
/// pages. It drops the old rows whose entry it already holds, nothing else.
#[tokio::test]
async fn a_cache_of_a_hosted_drive_only_drops_messages_that_have_their_entry() {
    let w = world("chat_migration_cache").await;
    let db = &w.db;
    let mut subjects: Vec<String> = Vec::new();
    for i in 0..3 {
        subjects.push(old_message(db, &w.alice, NewMessage::new(&w.chat, format!("m{i}"))).await);
    }
    let hosted: HashSet<String> = HashSet::new();

    // No page yet: nothing is created and nothing removed.
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    let step = db.migrate_messages_step(100, Some(&hosted)).await.unwrap();
    assert!(step.finished);
    assert!(pages(db, &w.chat, None).await.is_empty());
    for s in &subjects {
        assert!(message_exists(db, s).await);
    }

    // The server's pages arrive (here: written by a full migration that stops
    // before removing), then a message the pages do not have.
    db.migrate_group(&w.chat, None, false, None).await.unwrap();
    let straggler = old_message(db, &w.bob, NewMessage::new(&w.chat, "late")).await;
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    assert!(
        db.migrate_messages_step(100, Some(&hosted))
            .await
            .unwrap()
            .finished
    );
    for s in &subjects {
        assert!(!message_exists(db, s).await, "{s} has its entry: drop it");
    }
    assert!(
        message_exists(db, &straggler).await,
        "no entry for it yet: keep it"
    );
    let after = pages(db, &w.chat, None).await;
    assert_eq!(after.len(), 1, "the cache wrote no page of its own");
    assert_eq!(after[0].1.len(), 3);

    // A drive that exists only here is migrated in full.
    db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    let mut local: HashSet<String> = HashSet::new();
    local.insert(super::chat_migration::id_body(&w.drive));
    assert!(
        db.migrate_messages_step(100, Some(&local))
            .await
            .unwrap()
            .finished
    );
    assert!(!message_exists(db, &straggler).await);
    let texts: usize = pages(db, &w.chat, None)
        .await
        .iter()
        .map(|(_, e)| e.len())
        .sum();
    assert_eq!(texts, 4);
}

/// Opening a store that still has old messages moves them, and marks it done.
#[tokio::test]
async fn opening_a_store_with_old_messages_migrates_them() {
    let w = world("chat_migration_open").await;
    let chat = w.chat.clone();
    for i in 0..3 {
        old_message(&w.db, &w.alice, NewMessage::new(&chat, format!("m{i}"))).await;
    }
    // As a store from before: not marked done.
    w.db.kv.remove(Tree::PluginMeta, DONE_KEY).unwrap();
    w.db.kv.flush().unwrap();
    drop(w);

    let path = std::path::Path::new(".temp/db/chat_migration_open");
    let uploads = std::path::Path::new(".temp/db/chat_migration_open/uploads");
    let mut reopened = None;
    // The file lock can outlive the drop by a moment.
    for _ in 0..50 {
        match Db::init_redb_file(path, Some("https://localhost".into()), uploads).await {
            Ok(db) => {
                reopened = Some(db);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }
    let db = reopened.expect("the store reopens");
    assert!(!db.message_migration_pending().unwrap());
    let found = pages(&db, &chat, None).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1.len(), 3);
    let left = find_in_prop_val_sub_index(
        &db,
        urls::IS_A,
        Some(&Value::AtomicUrl(urls::MESSAGE.into())),
    )
    .flatten()
    .count();
    assert_eq!(left, 0);
}
