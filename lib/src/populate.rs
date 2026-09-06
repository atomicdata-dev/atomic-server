//! Populating a Store means adding resources to it.
//! Some of these are the core Atomic Data resources, such as the Property class.
//! These base models are required for having a functioning store.

use crate::{
    datatype::DataType,
    errors::AtomicResult,
    parse::{ParseOpts, SaveOpts},
    schema::{Class, Property},
    urls, Storelike, Value,
};

/// The hardcoded Properties and Classes that `populate_base_models` seeds.
/// Kept as data (rather than inline in the seeding loop) so the defaults
/// fingerprint can cover them: a base model added here must reach existing
/// stores just like a new `lib/defaults/*.json` entry.
fn base_models() -> (Vec<Property>, Vec<Class>) {
    let properties = vec![
        Property {
            class_type: None,
            data_type: DataType::Slug,
            shortname: "shortname".into(),
            description: "A short name of something. It can only contain letters, numbers and dashes `-`. Use dashes to denote spaces between words. Not case sensitive - lowercase only. Useful in programming contexts where the user should be able to type something short to identify a specific thing.".into(),
            subject: urls::SHORTNAME.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::Markdown,
            shortname: "description".into(),
            description: "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.".into(),
            subject: urls::DESCRIPTION.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::CLASS.into()),
            data_type: DataType::ResourceArray,
            shortname: "is-a".into(),
            description: "A list of Classes of which the thing is an instance of. The Classes of a Resource determine which Properties are recommended and required.".into(),
            subject: urls::IS_A.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::DATATYPE_CLASS.into()),
            data_type: DataType::AtomicUrl,
            shortname: "datatype".into(),
            description: "The Datatype of a property, such as String or Timestamp.".into(),
            subject: urls::DATATYPE_PROP.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::CLASS.into()),
            data_type: DataType::AtomicUrl,
            shortname: "classtype".into(),
            description:
                "The class-type indicates that the Atomic URL should be an instance of this class.\n\nThis can be used inside [`Property`](https://atomicdata.dev/classes/Property) instances where the [`datatype`](https://atomicdata.dev/properties/datatype) is either [`Resource`](https://atomicdata.dev/datatypes/resource) or [`ResourceArray`](https://atomicdata.dev/datatypes/resourceArray).\n\nSo for example if we have a `Property` called `friend`, the `classType` can be `Person`."
               .into(),
            subject: urls::CLASSTYPE_PROP.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::PROPERTY.into()),
            data_type: DataType::ResourceArray,
            shortname: "recommends".into(),
            description: "The Properties that are not required, but recommended for this Class.".into(),
            subject: urls::RECOMMENDS.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::PROPERTY.into()),
            data_type: DataType::ResourceArray,
            shortname: "requires".into(),
            description: "The Properties that are required for this Class.".into(),
            subject: urls::REQUIRES.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::AtomicUrl,
            shortname: "parent".into(),
            description: "The parent of a Resource sets the hierarchical structure of the Resource, and therefore also the rights / grants. It is used for both navigation, structure and authorization. Parents are the inverse of [children](https://atomicdata.dev/properties/children).".into(),
            subject: urls::PARENT.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::AtomicUrl,
            shortname: "drive".into(),
            description: "The drive (top-level resource) this Resource belongs to. Stamped at genesis from the resource's genesis certificate so authorization can resolve the drive's grant directly, without walking a parent chain that may not be materialized yet under concurrent creation. Immutable: a resource does not move between drives.".into(),
            subject: urls::DRIVE_PROP.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::ResourceArray,
            shortname: "allows-only".into(),
            description: "Restricts this Property to only the values inside this one. This essentially turns the Property into an `enum`.".into(),
            subject: urls::ALLOWS_ONLY.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::Boolean,
            shortname: "is-dynamic".into(),
            description: "If this is true, a Property is calculated server side and should therefore not appear in forms.".into(),
            subject: urls::IS_DYNAMIC.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::Boolean,
            shortname: "is-locked".into(),
            description: "If this is true, the Property should probably not be edited, because doing so could lead to serious errors.".into(),
            subject: urls::IS_LOCKED.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::Slug,
            shortname: "subdomain".into(),
            description: "The subdomain that identifies a Drive on a server. For example, in `joep.atomicdata.dev`, the subdomain is `joep`.".into(),
            subject: urls::SUBDOMAIN.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::DRIVE.into()),
            data_type: DataType::AtomicUrl,
            shortname: "initial-drive".into(),
            description: "The DID of the drive that should be mapped to the current host.".into(),
            subject: urls::INITIAL_DRIVE.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::DRIVE.into()),
            data_type: DataType::AtomicUrl,
            shortname: "personal-drive".into(),
            description: "The agent's personal (private) drive on this server. Clients use this as home and for agent-scoped data such as shared-with-me. At most one per agent.".into(),
            subject: urls::PRIVATE_DRIVE.into(),
            allows_only: None,
        },
        Property {
            class_type: None,
            data_type: DataType::ResourceArray,
            shortname: "shared-with-me".into(),
            description: "Resources this agent can access via invites or other shares. Clients often show these in a Shared with me list.".into(),
            subject: urls::SHARED_WITH_ME.into(),
            allows_only: None,
        },
        // The `genesis` property is read/written while parsing DID resources
        // (the self-verifying genesis certificate). Bootstrap it locally so a
        // base-models-only store doesn't fetch it from `atomicdata.dev`.
        Property {
            class_type: None,
            data_type: DataType::String,
            shortname: "genesis".into(),
            description: "The self-verifying genesis certificate: base64 of a compact binary cert (signer public key, createdAt, nonce, original parent, drive). The resource's DID is the creating agent's Ed25519 signature over this certificate, so authorship and identity are verifiable offline without fetching a commit. Server-managed and immutable.".into(),
            subject: urls::GENESIS.into(),
            allows_only: None,
        },
    ];
    let classes = vec![
        Class {
            requires: vec![urls::SHORTNAME.into(), urls::DATATYPE_PROP.into(), urls::DESCRIPTION.into()],
            recommends: vec![urls::CLASSTYPE_PROP.into(), urls::IS_DYNAMIC.into(), urls::IS_LOCKED.into(), urls::ALLOWS_ONLY.into()],
            shortname: "property".into(),
            description: "A Property is a single field in a Class. It's the thing that a property field in an Atom points to. An example is `birthdate`. An instance of Property requires various Properties, most notably a `datatype` (e.g. `string` or `integer`), a human readable `description` (such as the thing you're reading), and a `shortname`.".into(),
            subject: urls::PROPERTY.into(),
        },
        Class {
            requires: vec![urls::SHORTNAME.into(), urls::DESCRIPTION.into()],
            recommends: vec![urls::RECOMMENDS.into(), urls::REQUIRES.into()],
            shortname: "class".into(),
            description: "A Class describes an abstract concept, such as 'Person' or 'Blogpost'. It describes the data shape of data (which fields are required and recommended) and explains what the concept represents. It is convention to use Uppercase in its URL.Resources use the [is-a](https://atomicdata.dev/properties/isA) attribute to indicate which classes they are instances of. Note that in Atomic Data, a Resource can have several Classes - not just a single one.".into(),
            subject: urls::CLASS.into(),
        },
        Class {
            requires: vec![urls::SHORTNAME.into(), urls::DESCRIPTION.into()],
            recommends: vec![],
            shortname: "datatype".into(),
            description:
                "A Datatype describes a possible type of value, such as 'string' or 'integer'.".into(),
            subject: urls::DATATYPE_CLASS.into(),
        },
        Class {
            requires: vec![],
            recommends: vec![
                urls::PUBLIC_KEY.into(),
                urls::NAME.into(),
                urls::DESCRIPTION.into(),
                urls::PRIVATE_DRIVE.into(),
                urls::SHARED_WITH_ME.into(),
                urls::DRIVES.into(),
            ],
            shortname: "agent".into(),
            description:
                "An Agent is a user that can create or modify data. For DID-based agents (did:ad:agent:{publicKey}), the public key is derived from the subject.".into(),
            subject: urls::AGENT.into(),
        },
        // The Commit class is fundamental: commit serialization
        // (`CommitBuilder::into_resource` → `Resource::new_instance(COMMIT)`)
        // resolves this class, so it must be available locally. Without it a
        // base-models-only store (`Store::init`) would fetch it from
        // `atomicdata.dev` over the network — which strands offline and made
        // the commit-serialization tests depend on the public domain.
        Class {
            requires: vec![
                urls::CREATED_AT.into(),
                urls::SIGNATURE.into(),
                urls::SIGNER.into(),
                urls::SUBJECT.into(),
            ],
            recommends: vec![
                urls::DESTROY.into(),
                urls::IS_GENESIS.into(),
                urls::PREVIOUS_COMMIT.into(),
                urls::LORO_UPDATE.into(),
            ],
            shortname: "commit".into(),
            description: "A signed envelope wrapping a Loro CRDT update. Used to authorize writes. Not a queryable event log — current state lives in the resource's Loro document.".into(),
            subject: urls::COMMIT.into(),
        },
    ];
    (properties, classes)
}

/// Populates a store with some of the most fundamental Properties and Classes needed to bootstrap the whole.
/// This is necessary to prevent a loop where Property X (like the `shortname` Property)
/// cannot be added, because it's Property Y (like `description`) has to be fetched before it can be added,
/// which in turn has property Property X (`shortname`) which needs to be fetched before.
/// https://github.com/atomicdata-dev/atomic-server/issues/60
pub async fn populate_base_models(store: &impl Storelike) -> AtomicResult<()> {
    let (properties, classes) = base_models();

    // Only ever ADD. This runs again on a store that already holds part of the
    // vocabulary (see `bootstrap`), and on atomicdata.dev itself those
    // resources are the site's own authored content — re-seeding must not
    // replace a human-written description with the hardcoded one.
    for p in properties {
        if store.has_stored_resource(&p.subject.as_str().into()) {
            continue;
        }

        let mut resource = p.to_resource()?;
        resource.set_unsafe(
            urls::PARENT.into(),
            Value::AtomicUrl("https://atomicdata.dev/properties".into()),
        )?;
        store
            .add_resource_opts(&resource, false, true, true)
            .await?;
    }

    for c in classes {
        if store.has_stored_resource(&c.subject.as_str().into()) {
            continue;
        }

        let mut resource = c.to_resource()?;
        resource.set_unsafe(
            urls::PARENT.into(),
            Value::AtomicUrl("https://atomicdata.dev/classes".into()),
        )?;
        store
            .add_resource_opts(&resource, false, true, true)
            .await?;
    }

    Ok(())
}

/// The embedded `lib/defaults/*.json` files, in import order. Properties a
/// later file uses must be defined by an earlier one (or by the base models).
/// This list is the single source for both `populate_default_store` and
/// `defaults_fingerprint`, so a file cannot be imported without being
/// fingerprinted or vice versa.
const DEFAULT_FILES: &[(&str, &str)] = &[
    (
        "default_store.json",
        include_str!("../defaults/default_store.json"),
    ),
    ("chatroom.json", include_str!("../defaults/chatroom.json")),
    ("meeting.json", include_str!("../defaults/meeting.json")),
    ("table.json", include_str!("../defaults/table.json")),
    ("dashboard.json", include_str!("../defaults/dashboard.json")),
    (
        "ontologies.json",
        include_str!("../defaults/ontologies.json"),
    ),
    ("ai.json", include_str!("../defaults/ai.json")),
    ("plugins.json", include_str!("../defaults/plugins.json")),
    ("forks.json", include_str!("../defaults/forks.json")),
    ("i18n.json", include_str!("../defaults/i18n.json")),
];

/// Fingerprint of everything `bootstrap` seeds: the base models and the
/// embedded default JSON files, byte for byte. Computed from the compiled-in
/// data, so it is a property of the binary (or wasm bundle), and it changes
/// whenever a default is added or edited in the source tree.
///
/// `bootstrap` stores it in the `Db` and re-seeds only when it differs, which
/// is what lets a new `lib/defaults/*.json` Property or Class reach a store
/// that was seeded by an older build, without a manual `--repopulate-defaults`.
pub fn defaults_fingerprint() -> String {
    let mut hasher = blake3::Hasher::new();
    // Version the layout so a change in what is hashed cannot collide with an
    // old fingerprint by accident.
    hasher.update(b"atomic-defaults-fingerprint-v1\0");
    let (properties, classes) = base_models();
    let base_models_json =
        serde_json::to_string(&(properties, classes)).expect("base models serialize to JSON");
    hasher.update(base_models_json.as_bytes());
    hasher.update(b"\0");
    for (name, contents) in DEFAULT_FILES {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(contents.as_bytes());
        hasher.update(b"\0");
    }
    hasher.finalize().to_hex().to_string()
}

/// Imports the Atomic Data Core items (the entire atomicdata.dev Ontology / Vocabulary)
/// and the built-in app ontologies from `lib/defaults/*.json`.
///
/// Add-only: a resource that is already in the store keeps every value it
/// has (those may have been edited by a user, or are the site's own content
/// on atomicdata.dev itself); only the properties it lacks are added. See
/// [`SaveOpts::Merge`]. Consequently a *changed* value of an existing default
/// never propagates to an existing store — only new resources and new
/// properties do.
pub async fn populate_default_store(store: &impl Storelike) -> AtomicResult<()> {
    let opts = ParseOpts {
        save: SaveOpts::Merge,
        ..ParseOpts::default()
    };
    for (name, contents) in DEFAULT_FILES {
        store
            .import(contents, &opts)
            .await
            .map_err(|e| format!("Failed to import {name}: {e}"))?;
    }
    Ok(())
}

/// What [`bootstrap`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// The stored fingerprint matches this build; nothing was written.
    UpToDate,
    /// The store had no defaults yet; everything was seeded.
    Seeded,
    /// The store was seeded by a different build (or predates fingerprints);
    /// missing defaults were added, existing values left alone.
    Updated,
}

/// Bootstraps the store with core models and default ontologies.
///
/// Runs on every `Db` open. Compares [`defaults_fingerprint`] of this build
/// against the one the store recorded when it was last seeded, and does
/// nothing when they match. On a mismatch (new build, or a store from before
/// fingerprints existed) it upserts the base models and `lib/defaults/*.json`
/// add-only and records the new fingerprint. The whole thing is one DB
/// transaction (`begin_batch`/`commit_batch`), so the fingerprint is only
/// persisted together with the seed it describes.
///
/// [`repopulate_defaults`] is the forced variant that skips the comparison.
pub async fn bootstrap(store: &impl Storelike) -> AtomicResult<BootstrapOutcome> {
    let current = defaults_fingerprint();
    let stored = store.get_defaults_fingerprint()?;
    if stored.as_deref() == Some(current.as_str()) {
        tracing::debug!("populate::bootstrap: defaults up to date, skipping");
        return Ok(BootstrapOutcome::UpToDate);
    }

    // Local storage check, not `get_resource`: `get_resource` may fetch
    // external Atomic URLs and could make a fresh store look seeded.
    let outcome = if store.has_stored_resource(&urls::SHORTNAME.into()) {
        tracing::info!(
            "populate::bootstrap: store was seeded by a different build; \
             adding missing defaults (existing values are left untouched)"
        );
        BootstrapOutcome::Updated
    } else {
        tracing::info!("populate::bootstrap: seeding base models and ontologies");
        BootstrapOutcome::Seeded
    };

    seed_defaults(store, &current).await?;
    Ok(outcome)
}

/// Forced re-seed, ignoring the stored fingerprint. Same add-only semantics
/// as [`bootstrap`]: nothing that exists is overwritten or removed. Backs the
/// server's `--repopulate-defaults` flag.
pub async fn repopulate_defaults(store: &impl Storelike) -> AtomicResult<()> {
    seed_defaults(store, &defaults_fingerprint()).await
}

async fn seed_defaults(store: &impl Storelike, fingerprint: &str) -> AtomicResult<()> {
    store.begin_batch();
    populate_base_models(store).await?;
    populate_default_store(store).await?;
    store.set_defaults_fingerprint(fingerprint)?;
    store.commit_batch()?;
    Ok(())
}

#[cfg(all(test, feature = "db-redb", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::Db;

    /// A Property that only `lib/defaults/chatroom.json` defines.
    const NEW_DEFAULT: &str = "https://atomicdata.dev/properties/messages";

    fn temp_paths(id: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        (
            std::path::PathBuf::from(format!(".temp/db/{id}")),
            std::path::PathBuf::from(format!(".temp/db/{id}/uploads")),
        )
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = defaults_fingerprint();
        let b = defaults_fingerprint();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "blake3 hex");
    }

    /// A store seeded by an older build (different fingerprint) picks up a
    /// default it lacks on the next open — no `--repopulate-defaults` needed.
    #[tokio::test]
    async fn seeded_store_gains_new_default_on_reopen() {
        let id = "populate_new_default_on_reopen";
        let (db_path, uploads) = temp_paths(id);
        {
            let store = Db::init_temp(id).await.unwrap();
            assert_eq!(
                store.get_defaults_fingerprint().unwrap().as_deref(),
                Some(defaults_fingerprint().as_str())
            );
            // Make it look like a store seeded before `messages` existed and
            // by a build with a different set of defaults.
            store.remove_resource(&NEW_DEFAULT.into()).await.unwrap();
            assert!(!store.has_stored_resource(&NEW_DEFAULT.into()));
            store.set_defaults_fingerprint("older-build").unwrap();
            store.flush().unwrap();
        }

        let store = Db::init_redb_file(&db_path, Some("https://localhost".into()), &uploads)
            .await
            .unwrap();
        assert!(
            store.has_stored_resource(&NEW_DEFAULT.into()),
            "a default missing from a store seeded by another build must be added on open"
        );
        assert_eq!(
            store.get_defaults_fingerprint().unwrap().as_deref(),
            Some(defaults_fingerprint().as_str()),
            "the fingerprint is updated after the re-seed"
        );
    }

    /// Re-seeding only adds; a value the user changed on a default resource
    /// is kept, while a property the resource lost is put back.
    #[tokio::test]
    async fn user_edited_default_survives_reseed() {
        let store = Db::init_temp("populate_user_edit_survives").await.unwrap();
        let mut resource = store.get_resource(&NEW_DEFAULT.into()).await.unwrap();
        resource
            .set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String("edited by a user".into()),
            )
            .unwrap();
        resource.remove_propval(urls::IS_DYNAMIC).unwrap();
        store
            .add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();

        repopulate_defaults(&store).await.unwrap();

        let after = store.get_resource(&NEW_DEFAULT.into()).await.unwrap();
        assert_eq!(
            after.get(urls::DESCRIPTION).unwrap().to_string(),
            "edited by a user",
            "an existing propval must not be clobbered by the default"
        );
        assert!(
            after.get(urls::IS_DYNAMIC).is_ok(),
            "a propval the default has and the resource lacks is added"
        );
    }

    /// With a matching fingerprint `bootstrap` returns without writing.
    #[tokio::test]
    async fn bootstrap_is_a_noop_when_fingerprint_matches() {
        let store = Db::init_temp("populate_noop").await.unwrap();
        // If bootstrap wrote anything, this default would come back.
        store.remove_resource(&NEW_DEFAULT.into()).await.unwrap();

        let outcome = bootstrap(&store).await.unwrap();

        assert_eq!(outcome, BootstrapOutcome::UpToDate);
        assert!(
            !store.has_stored_resource(&NEW_DEFAULT.into()),
            "an up-to-date store must not be re-seeded"
        );

        // And a stale fingerprint is exactly what makes it write.
        store.set_defaults_fingerprint("older-build").unwrap();
        assert_eq!(bootstrap(&store).await.unwrap(), BootstrapOutcome::Updated);
        assert!(store.has_stored_resource(&NEW_DEFAULT.into()));
        assert_eq!(bootstrap(&store).await.unwrap(), BootstrapOutcome::UpToDate);
    }
}
