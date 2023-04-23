//! Populating a Store means adding resources to it.
//! Some of these are the core Atomic Data resources, such as the Property class.
//! These base models are required for having a functioning store.
//! Other populate methods help to set up an Atomic Server, by creating a basic file hierarcy and creating default collections.

use crate::{
    datatype::DataType,
    errors::AtomicResult,
    parse::ParseOpts,
    schema::{Class, Property},
    urls, Query, Resource, Storelike, Value,
};

/// Populates a store with some of the most fundamental Properties and Classes needed to bootstrap the whole.
/// This is necessary to prevent a loop where Property X (like the `shortname` Property)
/// cannot be added, because it's Property Y (like `description`) has to be fetched before it can be added,
/// which in turn has property Property X (`shortname`) which needs to be fetched before.
/// https://github.com/atomicdata-dev/atomic-data-rust/issues/60
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
            class_type: Some(urls::PROPERTY.into()),
            data_type: DataType::AtomicUrl,
            shortname: "parent".into(),
            description: "The parent of a Resource sets the hierarchical structure of the Resource, and therefore also the rights / grants. It is used for both navigation, structure and authorization. Parents are the inverse of [children](https://atomicdata.dev/properties/children).".into(),
            subject: urls::PARENT.into(),
            allows_only: None,
        },
        Property {
            class_type: Some(urls::PROPERTY.into()),
            data_type: DataType::ResourceArray,
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
        let mut resource = p.to_resource();
        resource.set_propval_unsafe(
            urls::PARENT.into(),
            Value::AtomicUrl("https://atomicdata.dev/properties".into()),
        );
        store.add_resource_opts(&resource, false, true, true)?;
    }

    for c in classes {
        let mut resource = c.to_resource();
        resource.set_propval_unsafe(
            urls::PARENT.into(),
            Value::AtomicUrl("https://atomicdata.dev/classes".into()),
        );
        store.add_resource_opts(&resource, false, true, true)?;
    }

    Ok(())
}

/// Creates a Drive resource at the base URL if no name is passed.
#[tracing::instrument(skip(store), level = "info")]
pub fn create_drive(
    store: &impl Storelike,
    drive_name: Option<&str>,
    for_agent: &str,
    public_read: bool,
) -> AtomicResult<Resource> {
    let self_url = if let Some(url) = store.get_self_url() {
        url.to_owned()
    } else {
        return Err("No self URL set. Cannot create drive.".into());
    };
    let drive_subject: String = if let Some(name) = drive_name {
        // Let's make a subdomain
        let mut url = self_url.url();
        let host = url.host().expect("No host in server_url");
        let subdomain_host = format!("{}.{}", name, host);
        url.set_host(Some(&subdomain_host))?;
        url.to_string()
    } else {
        self_url.to_string()
    };

    let mut drive = if let Some(drive_name_some) = drive_name {
        if store.get_resource(&drive_subject).is_ok() {
            return Err(format!("Name '{}' is already taken", drive_name_some).into());
        }
        Resource::new(drive_subject)
    } else {
        // Only for the base URL (of no drive name is passed), we should not check if the drive exists.
        // This is because we use `create_drive` in the `--initialize` command.
        store.get_resource_new(&drive_subject)
    };
    drive.set_class(urls::DRIVE);
    drive.set_propval_string(urls::NAME.into(), drive_name.unwrap_or("Main drive"), store)?;

    // Set rights
    drive.push_propval(urls::WRITE, for_agent.into(), true)?;
    drive.push_propval(urls::READ, for_agent.into(), true)?;
    if public_read {
        drive.push_propval(urls::READ, urls::PUBLIC_AGENT.into(), true)?;
    }

    if let Err(_no_description) = drive.get(urls::DESCRIPTION) {
        drive.set_propval_string(urls::DESCRIPTION.into(), &format!(r#"## Welcome to your Atomic-Server!

Register your Agent by visiting [`/setup`]({}/setup). After that, edit this page by pressing `edit` in the navigation bar menu.

Note that, by default, all resources are `public`. You can edit this by opening the context menu (the three dots in the navigation bar), and going to `share`.
"#, store.get_server_url()), store)?;
    }

    drive.save_locally(store)?;

    Ok(drive)
}

/// Imports the Atomic Data Core items (the entire atomicdata.dev Ontology / Vocabulary)
pub fn populate_default_store(store: &impl Storelike) -> AtomicResult<()> {
    store
        .import(
            include_str!("../defaults/default_store.json"),
            &ParseOpts::default(),
        )
        .map_err(|e| format!("Failed to import default_store.json: {e}"))?;
    store
        .import(
            include_str!("../defaults/chatroom.json",),
            &ParseOpts::default(),
        )
        .map_err(|e| format!("Failed to import chatroom.json: {e}"))?;
    store
        .import(
            include_str!("../defaults/table.json",),
            &ParseOpts::default(),
        )
        .map_err(|e| format!("Failed to import table.json: {e}"))?;
    Ok(())
}

/// Generates collections for classes, such as `/agent` and `/collection`.
/// Requires a `self_url` to be set in the store.
pub fn populate_collections(store: &impl Storelike) -> AtomicResult<()> {
    let mut query = Query::new_class(urls::CLASS);
    query.include_external = true;
    let result = store.query(&query)?;

    for subject in result.subjects {
        let mut collection =
            crate::collections::create_collection_resource_for_class(store, &subject)?;
        collection.save_locally(store)?;
    }

    Ok(())
}

#[cfg(feature = "db")]
/// Adds items to the SideBar as subresources.
/// Useful for helping a new user get started.
pub fn populate_sidebar_items(store: &crate::Db) -> AtomicResult<()> {
    let base = store.get_self_url().ok_or("No self_url")?;
    let mut drive = store.get_resource(base.as_str())?;
    let sidebar_items = vec![
        base.set_route(crate::atomic_url::Routes::Setup),
        base.set_route(crate::atomic_url::Routes::Import),
        base.set_route(crate::atomic_url::Routes::Collections),
    ];
    for item in sidebar_items {
        drive.push_propval(urls::SUBRESOURCES, item.to_string().into(), true)?;
    }
    drive.save_locally(store)?;
    Ok(())
}

/// Runs all populate commands. Optionally runs index (blocking), which can be slow!
#[cfg(feature = "db")]
pub fn populate_all(store: &crate::Db) -> AtomicResult<()> {
    // populate_base_models should be run in init, instead of here, since it will result in infinite loops without
    populate_default_store(store)
        .map_err(|e| format!("Failed to populate default store. {}", e))?;
    create_drive(store, None, &store.get_default_agent()?.subject, true)
        .map_err(|e| format!("Failed to create drive. {}", e))?;
    populate_collections(store).map_err(|e| format!("Failed to populate collections. {}", e))?;
    populate_sidebar_items(store)
        .map_err(|e| format!("Failed to populate sidebar items. {}", e))?;
    Ok(())
}
