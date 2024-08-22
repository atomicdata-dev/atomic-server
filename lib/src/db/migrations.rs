/*!
# Migrations

Whenever the schema of the database changes, a newer version will not be able to read an older database.
Therefore, we need migrations to convert the old schema to the new one.

## Adding a Migration

- Write a function called `v{OLD}_to_v{NEW} that takes a [Db]. Make sure it removed the old `Tree`. Use [assert] to check if the process worked.
- In [migrate_maybe] add the key of the outdated Tree
- Add the function to the [migrate_maybe] `match` statement, select the older version of the Tree
- Update the Tree key used in [crate::db::trees]
 */

use crate::{errors::AtomicResult, resources::PropVals, Db};

const RESOURCE_TREE_V0: &str = "resources";
const RESOURCE_TREE_V1: &str = "resources_v1";
const RESOURCE_TREE_V2: &str = "resources_v2";
pub const RESOURCE_TREE_CURRENT: &str = RESOURCE_TREE_V2;

const REFERENCE_INDEX_V0: &str = "reference_index";
const REFERENCE_INDEX_V1: &str = "reference_index_v1";
pub const REFERENCE_INDEX_CURRENT: &str = REFERENCE_INDEX_V1;

/// Checks the current version(s) of the internal Store, and performs migrations if needed.
pub fn migrate_maybe(store: &Db) -> AtomicResult<()> {
    for tree in store.db.tree_names() {
        match String::from_utf8_lossy(&tree).as_ref() {
            // Add migrations for outdated Trees to this list
            RESOURCE_TREE_V0 => res_v0_to_v1(store)?,
            RESOURCE_TREE_V1 => res_v1_to_v2(store)?,
            REFERENCE_INDEX_V0 => ref_v0_to_v1(store)?,
            _other => {}
        }
    }
    Ok(())
}

/// Change the subjects from `bincode` to `.as_bytes()`
fn res_v0_to_v1(store: &Db) -> AtomicResult<()> {
    tracing::warn!("Migrating resources schema from v0 to v1...");
    let new = store.db.open_tree(RESOURCE_TREE_V1)?;
    let old_key = RESOURCE_TREE_V0;
    let old = store.db.open_tree(old_key)?;
    let mut count = 0;

    for item in old.into_iter() {
        let (subject, resource_bin) = item.expect("Unable to convert into iterable");
        let subject: String = String::from_utf8_lossy(&subject).to_string();
        new.insert(subject.as_bytes(), resource_bin)?;
        count += 1;
    }

    // TODO: Prefer transactional approach, but issue preventing me from compiling:
    // https://github.com/spacejam/sled/issues/1406
    // (&store.resources, &new)
    //     .transaction(|(old, new)| {
    //         for item in store.resources.into_iter() {
    //             let (subject, resource_bin) = item.expect("Unable to perform migration");
    //             let subject: String =
    //                 bincode::deserialize(&subject).expect("Unable to deserialize subject");
    //             new.insert(subject.as_bytes(), resource_bin)?;
    //             count += 1;
    //         }
    //         Ok(())
    //     })
    //     .expect("Unable to perform migration");

    assert_eq!(
        new.len(),
        store.resources.len(),
        "Not all resources were migrated."
    );

    assert!(
        store.db.drop_tree(old_key)?,
        "Old resources tree not properly removed."
    );

    tracing::warn!("Finished migration of {} resources", count);
    Ok(())
}

/// add a trailing slash to all "home" subjects
fn res_v1_to_v2(store: &Db) -> AtomicResult<()> {
    tracing::warn!("Migrating resources schema from v1 to v2...");
    let new = store.db.open_tree(RESOURCE_TREE_V2)?;
    let old_key = RESOURCE_TREE_V1;
    let old = store.db.open_tree(old_key)?;
    let mut count = 0;

    fn migrate_subject(subject: &str) -> String {
        let url = url::Url::parse(subject).expect("Unable to parse subject URL");
        if subject != url.to_string() {
            println!("Migrating: {} -> {}", subject, url.to_string())
        };
        url.to_string()
    }

    for item in old.into_iter() {
        let (subject, resource_bin) = item.expect("Unable to convert into iterable");
        let subject: String = String::from_utf8_lossy(&subject).to_string();

        let mut propvals: PropVals = bincode::deserialize(&resource_bin)?;

        for (_prop, val) in propvals.iter_mut() {
            match val {
                crate::Value::AtomicUrl(a) => {
                    *a = migrate_subject(a);
                }
                crate::Value::ResourceArray(arr) => {
                    for url in arr.iter_mut() {
                        match url {
                            crate::values::SubResource::Subject(s) => {
                                *s = migrate_subject(s);
                            }
                            // This skips nested resources
                            _other => {}
                        }
                    }
                }
                // This skips nested resources
                _other => {}
            };
        }
        new.insert(migrate_subject(&subject), bincode::serialize(&propvals)?)?;
        count += 1;
    }

    assert_eq!(
        new.len(),
        store.resources.len(),
        "Not all resources were migrated."
    );

    assert!(
        store.db.drop_tree(old_key)?,
        "Old resources tree not properly removed."
    );

    tracing::warn!("Rebuilding indexes due to migrating to new version...");
    store.db.drop_tree(old_key)?;
    store.build_index(true)?;
    tracing::warn!("Rebuilding index finished!");

    tracing::warn!("Finished migration of {} resources", count);
    Ok(())
}

/// Add `prop_val_sub` index
fn ref_v0_to_v1(store: &Db) -> AtomicResult<()> {
    tracing::warn!("Rebuilding indexes due to migrating to new version...");
    store.db.drop_tree("reference_index")?;
    store.build_index(true)?;
    tracing::warn!("Rebuilding index finished!");
    Ok(())
}
