//! Populating a Store means adding resources to it.
//! Some of these are the core Atomic Data resources, such as the Property class.
//! These base models are required for having a functioning store.
//! Other populate methods help to set up an Atomic Server, by creating a basic file hierarcy and creating default collections.

use crate::{
    datatype::DataType,
    errors::AtomicResult,
    schema::{Class, Property},
    urls, Storelike,
};

/// Populates a store with some of the most fundamental Properties and Classes needed to bootstrap the whole.
/// This is necessary to prevent a loop where Property X (like the `shortname` Property)
/// cannot be added, because it's Property Y (like `description`) has to be fetched before it can be added,
/// which in turn has property Property X (`shortname`) which needs to be fetched before.
/// https://github.com/joepio/atomic/issues/60
pub fn populate_base_models(store: &impl Storelike) -> AtomicResult<()> {
    // Start with adding the most fundamental properties - the properties for Properties

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
                "The class-type indicates that the Atomic URL should be an instance of this class."
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
            class_type: Some(urls::PROPERTY.into()),
            data_type: DataType::AtomicUrl,
            shortname: "parent".into(),
            description: "The parent of a Resource sets the hierarchical structure of the Resource, and therefore also the rights / grants. It is used for both navigation, structure and authorization. Parents are the inverse of [children](https://atomicdata.dev/properties/children).".into(),
            subject: urls::PARENT.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::PROPERTY.into()),
            data_type: DataType::AtomicUrl,
            shortname: "allows-only".into(),
            description: "Restricts this Property to only the values inside this one. This essentially turns the Property into an `enum`.".into(),
            subject: urls::ALLOWS_ONLY.into(),
            allows_only: None,
        }
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
            requires: vec![urls::PUBLIC_KEY.into()],
            recommends: vec![urls::NAME.into(), urls::DESCRIPTION.into(), urls::DRIVES.into()],
            shortname: "agent".into(),
            description:
                "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The public key is used to verify signatures (on [Commits](https://atomicdata.dev/classes/Commit)) set by the of the Agent.".into(),
            subject: urls::AGENT.into(),
        }
    ];

    for p in properties {
        let resource = p.to_resource()?;
        store.add_resource_opts(&resource, false, false, true)?;
    }

    for c in classes {
        let resource = c.to_resource()?;
        store.add_resource_opts(&resource, false, false, true)?;
    }

    Ok(())
}

/// Creates a Drive resource at the base URL. Does not set rights. Use set_drive_rights for that.
pub fn create_drive(store: &impl Storelike) -> AtomicResult<()> {
    let self_url = store
        .get_self_url()
        .ok_or("No self_url set, cannot populate store with Drive")?;
    let mut drive = crate::Resource::new_instance(urls::DRIVE, store)?;
    drive.set_subject(self_url);
    let base_url = url::Url::parse(store.get_base_url())?;
    drive.set_propval_string(
        urls::NAME.into(),
        base_url.host_str().ok_or("Can't use current base URL")?,
        store,
    )?;
    drive.save_locally(store)?;
    Ok(())
}

/// Get the Drive resource (base URL), set agent as the Root user, provide write and read access to the Root user. Also, by default, makes the Root publicly visible.
pub fn set_drive_rights(store: &impl Storelike) -> AtomicResult<()> {
    // Now let's add the agent as the Root user and provide write access
    let mut drive = store.get_resource(store.get_base_url())?;
    let write_agents = vec![store.get_default_agent()?.subject];
    let mut read_agents = write_agents.clone();
    read_agents.push(urls::PUBLIC_AGENT.into());

    drive.set_propval(urls::WRITE.into(), write_agents.into(), store)?;
    drive.set_propval(urls::READ.into(), read_agents.into(), store)?;
    drive.set_propval_string(urls::DESCRIPTION.into(), &format!("## Welcome to your Atomic-Server!\n\n Register your User by visiting [`/setup`]({}/setup). After that, edit this page by pressing `edit` in the navigation bar menu.", store.get_base_url()), store)?;
    drive.save_locally(store)?;
    Ok(())
}

/// Imports the Atomic Data Core items (the entire atomicdata.dev Ontology / Vocabulary) from default_store.jsonld
pub fn populate_default_store(store: &impl Storelike) -> AtomicResult<()> {
    let json = include_str!("../defaults/default_store.json");
    store.import(json)?;
    Ok(())
}

/// Generates some nice collections for classes, such as `/agent` and `/collection`.
/// Requires a `self_url` to be set in the store.
pub fn populate_collections(store: &impl Storelike) -> AtomicResult<()> {
    use crate::collections::CollectionBuilder;

    let classes_atoms = store.tpf(
        None,
        Some("https://atomicdata.dev/properties/isA"),
        Some("https://atomicdata.dev/classes/Class"),
        true,
    )?;

    for atom in classes_atoms {
        let class = store.get_class(&atom.subject)?;
        // Can't import this for some reason - even if it's there in cargo.toml
        // let plural_name = pluralize_rs::to_plural(class.shortname);

        // Pluralize the shortname
        let pluralized = match class.shortname.as_ref() {
            "class" => "classes".to_string(),
            "property" => "properties".to_string(),
            other => format!("{}s", other).to_string(),
        };

        let collection = CollectionBuilder::class_collection(&class.subject, &pluralized, store);

        let mut collection_resource = collection.to_resource(store)?;

        collection_resource.set_propval_string(
            urls::PARENT.into(),
            &store
                .get_self_url()
                .ok_or("No self_url present in store, can't populate collections")?,
            store,
        )?;

        collection_resource.set_propval_string(urls::NAME.into(), &pluralized, store)?;

        // Should we use save_locally, which creates commits, or add_resource_unsafe, which is faster?
        collection_resource.save_locally(store)?;
    }

    Ok(())
}

#[cfg(feature = "db")]
/// Adds default Endpoints (versioning) to the Db.
/// Makes sure they are fetchable
pub fn populate_endpoints(store: &crate::Db) -> AtomicResult<()> {
    let endpoints = crate::endpoints::default_endpoints();
    for endpoint in endpoints {
        let mut resource = endpoint.to_resource(store)?;
        resource.save_locally(store)?;
    }
    Ok(())
}
