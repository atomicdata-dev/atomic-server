/*!
# Migrations

Whenever the schema of the database changes, a newer version will not be able to read an older database.
Therefore, we need migrations to convert the old schema to the new one.

## Adding a Migration

- Write a function called `v{OLD}_to_v{NEW} that takes a [Db].
- Update the relevant version key in your function
- Update [SCHEMA_RESOURCES_VERSION_APP]
- Add the function to the [migrate_maybe] `match` statement
 */

use crate::{errors::AtomicResult, Db};

static SCHEMA_RESOURCES_VERSION_APP: &str = "1";
static SCHEMA_RESOURCES_VERSION_KEY: &str = "schema_resources_version";

// Checks the current version(s) of the internal Store, and performs migrations if needed.
pub fn migrate_maybe(store: &Db) -> AtomicResult<()> {
    let schema_resource_version: String = if let Some(v) = &store
        .internal
        .get(SCHEMA_RESOURCES_VERSION_KEY.as_bytes())?
    {
        String::from_utf8_lossy(v).to_string()
    } else {
        "0".into()
    };

    match schema_resource_version.as_str() {
        // Add your migration to this list
        "0" => v0_to_v1(store),
        other => {
            if other == SCHEMA_RESOURCES_VERSION_APP {
                Ok(())
            } else {
                Err(format!(
                    "Unable to perform migration, unknown current schema version: {}",
                    other
                )
                .into())
            }
        }
    }
}

// Change the subjects from `bincode` to `.as_bytes()`
fn v0_to_v1(store: &Db) -> AtomicResult<()> {
    tracing::warn!("Migrating resources schema from v0 to v1...");
    let new = store.db.open_tree("resources_new_temp")?;
    let mut count = 0;

    // use sled::Transactional;

    // (&store.resources, &new).transaction(|(old, new)| {
    //     for item in store.resources.into_iter() {
    //         let (subject, resource_bin) = item.expect("Unable to perform migration");
    //         let subject: String =
    //             bincode::deserialize(&subject).expect("Unable to deserialize subject");
    //         new.insert(subject.as_bytes(), resource_bin)?;
    //         count += 1;
    //     }
    //     Ok(())
    // });

    for item in store.resources.into_iter() {
        let (subject, resource_bin) = item.expect("Unable to perform migration");
        let subject: String =
            bincode::deserialize(&subject).expect("Unable to deserialize subject");
        new.insert(subject.as_bytes(), resource_bin)?;
        count += 1;
    }
    assert_eq!(
        new.len(),
        store.resources.len(),
        "Not all resources were migrated."
    );
    tracing::warn!("Finished migration of {} resources", count);
    store.internal.insert(SCHEMA_RESOURCES_VERSION_KEY, b"1")?;
    Ok(())
}
