#[cfg(feature = "db")]
use crate::{urls, Db, Resource, Storelike, Subject, Value};
#[cfg(not(feature = "db"))]
use crate::{urls, Resource, Storelike, Subject, Value};

/// Creates a populated Store with an agent, backed by sled on disk.
#[cfg(feature = "db-sled")]
pub async fn init_store() -> Db {
    let id = format!("init_store_{}", crate::utils::random_string(10));
    let store = Db::init_temp(&id).await.unwrap();
    store.populate().await.unwrap();
    let agent = store.create_agent(None).await.unwrap();
    store.set_default_agent(agent);
    store
}

/// Creates a populated Store with an agent, backed by in-memory BTreeMap.
#[cfg(all(feature = "db", not(feature = "db-sled")))]
pub async fn init_store() -> Db {
    let store = Db::init_memory(Some("https://localhost".into()))
        .await
        .unwrap();
    store.populate().await.unwrap();
    let agent = store.create_agent(None).await.unwrap();
    store.set_default_agent(agent);
    store
}

/// Generates collections for classes, such as `/agent` and `/collection`.
pub async fn populate_collections(store: &impl Storelike) -> crate::errors::AtomicResult<()> {
    let mut query = crate::storelike::Query::new_class(urls::CLASS);
    query.include_external = true;
    let result = store.query(&query).await?;

    for subject in result.subjects {
        if subject.as_str() == urls::COMMIT {
            // Commits are signed envelopes, not a queryable class listing.
            continue;
        }
        let mut collection =
            crate::collections::create_collection_resource_for_class(store, subject.as_str())
                .await?;
        collection.save_locally(store).await?;
    }

    Ok(())
}

/// Creates a new DID-native Drive resource for tests.
pub async fn create_test_drive(store: &impl Storelike) -> crate::errors::AtomicResult<Subject> {
    let mut drive = Resource::new("did:ad:placeholder".into());
    drive
        .set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::DRIVE.into()]),
            store,
        )
        .await?;
    drive
        .set(urls::NAME.into(), Value::String("Test Drive".into()), store)
        .await?;

    let commit_res = drive.save_as_genesis(store).await?;
    Ok(commit_res.resource_new.unwrap().get_subject().clone())
}

/// Sets up a full environment for testing, including a drive and collections.
#[cfg(feature = "db")]
pub async fn setup_test_env(store: &Db) -> crate::errors::AtomicResult<()> {
    store.populate().await?;
    let drive_did = create_test_drive(store).await?;
    let drive_did_val = Value::AtomicUrl(drive_did.clone());
    store.add_drive_mapping("localhost", &drive_did_val)?;
    store.add_drive_mapping("127.0.0.1", &drive_did_val)?;

    // Grant public read rights to root
    let mut internal_root: Resource = store.get_resource_new(&"internal:/".into()).await;
    internal_root.push(urls::READ, urls::PUBLIC_AGENT.into(), true)?;
    internal_root.save_locally(store).await?;

    populate_collections(store).await?;
    Ok(())
}
