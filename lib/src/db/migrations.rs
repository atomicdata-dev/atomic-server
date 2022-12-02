/*!
# Migrations

Whenever the schema of the database changes, a newer version will not be able to read an older database.
Therefore, we need migrations to convert the old schema to the new one.

## Adding a Migration

- Write a function called `v{OLD}_to_v{NEW} that takes a [Db]. Make sure it removed the old `Tree`. Use [assert] to check if the process worked.
- In [migrate_maybe] add the key of the outdated Tree
- Add the function to the [migrate_maybe] `match` statement, select the older version of the Tree
- Update the Tree key used in [Db::init]
 */

use crate::{errors::AtomicResult, Db, Storelike};

/// Checks the current version(s) of the internal Store, and performs migrations if needed.
pub fn migrate_maybe(store: &Db) -> AtomicResult<()> {
    for tree in store.db.tree_names() {
        match String::from_utf8_lossy(&tree).as_ref() {
            // Add migrations for outdated Trees to this list
            "resources" => v0_to_v1(store)?,
            "reference_index" => ref_v0_to_v1(store)?,
            _other => {}
        }
    }
    Ok(())
}

/// Change the subjects from `bincode` to `.as_bytes()`
fn v0_to_v1(store: &Db) -> AtomicResult<()> {
    tracing::warn!("Migrating resources schema from v0 to v1...");
    let new = store.db.open_tree("resources_v1")?;
    let old_key = "resources";
    let old = store.db.open_tree(old_key)?;
    let mut count = 0;

    for item in old.into_iter() {
        let (subject, resource_bin) = item.expect("Unable to convert into iterable");
        let subject: String =
            bincode::deserialize(&subject).expect("Unable to deserialize subject");
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

/// Add `prop_val_sub` index
fn ref_v0_to_v1(store: &Db) -> AtomicResult<()> {
    tracing::warn!("Rebuilding indexes due to migrating to new version...");
    store.db.drop_tree("reference_index")?;
    store.build_index(true)?;
    tracing::warn!("Rebuilding index finished!");
    Ok(())
}
