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

    let shortname = Property {
        class_type: None,
        data_type: DataType::Slug,
        shortname: "shortname".into(),
        description: "A short name of something. It can only contain letters, numbers and dashes `-`. Use dashes to denote spaces between words. Not case sensitive - lowercase only. Useful in programming contexts where the user should be able to type something short to identify a specific thing.".into(),
        subject: urls::SHORTNAME.into(),
    }.to_resource()?;
    store.add_resource_unsafe(&shortname)?;

    let description = Property {
        class_type: None,
        data_type: DataType::Markdown,
        shortname: "description".into(),
        description: "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.".into(),
        subject: urls::DESCRIPTION.into(),
    }.to_resource()?;
    store.add_resource_unsafe(&description)?;

    let is_a = Property {
        class_type: Some(urls::CLASS.into()),
        data_type: DataType::ResourceArray,
        shortname: "is-a".into(),
        description: "A list of Classes of which the thing is an instance of. The Classes of a Resource determine which Properties are recommended and required.".into(),
        subject: urls::IS_A.into(),
    }.to_resource()?;
    store.add_resource_unsafe(&is_a)?;

    let datatype = Property {
        class_type: Some(urls::DATATYPE_CLASS.into()),
        data_type: DataType::AtomicUrl,
        shortname: "datatype".into(),
        description: "The Datatype of a property, such as String or Timestamp.".into(),
        subject: urls::DATATYPE_PROP.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&datatype)?;

    let classtype = Property {
        class_type: Some(urls::CLASS.into()),
        data_type: DataType::AtomicUrl,
        shortname: "classtype".into(),
        description:
            "The class-type indicates that the Atomic URL should be an instance of this class."
                .into(),
        subject: urls::CLASSTYPE_PROP.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&classtype)?;

    let recommends = Property {
        class_type: Some(urls::PROPERTY.into()),
        data_type: DataType::ResourceArray,
        shortname: "recommends".into(),
        description: "The Properties that are not required, but recommended for this Class.".into(),
        subject: urls::RECOMMENDS.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&recommends)?;

    let requires = Property {
        class_type: Some(urls::PROPERTY.into()),
        data_type: DataType::ResourceArray,
        shortname: "requires".into(),
        description: "The Properties that are required for this Class.".into(),
        subject: urls::REQUIRES.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&requires)?;

    let property = Class {
        requires: vec![urls::SHORTNAME.into()],
        recommends: vec![],
        shortname: "property".into(),
        description: "A Property is a single field in a Class. It's the thing that a property field in an Atom points to. An example is `birthdate`. An instance of Property requires various Properties, most notably a `datatype` (e.g. `string` or `integer`), a human readable `description` (such as the thing you're reading), and a `shortname`.".into(),
        subject: urls::PROPERTY.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&property)?;

    let class = Class {
        requires: vec![urls::SHORTNAME.into(), urls::DESCRIPTION.into()],
        recommends: vec![urls::RECOMMENDS.into(), urls::REQUIRES.into()],
        shortname: "class".into(),
        description: "A Class describes an abstract concept, such as 'Person' or 'Blogpost'. It describes the data shape of data and explains what the thing represents. It is convention to use Uppercase in its URL. Note that in Atomic Data, a Resource can have several Classes - not just a single one.".into(),
        subject: urls::CLASS.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&class)?;

    let datatype = Class {
        requires: vec![urls::SHORTNAME.into(), urls::DESCRIPTION.into()],
        recommends: vec![],
        shortname: "datatype".into(),
        description:
            "A Datatype describes a possible type of value, such as 'string' or 'integer'.".into(),
        subject: urls::DATATYPE_CLASS.into(),
    }
    .to_resource()?;
    store.add_resource_unsafe(&datatype)?;

    Ok(())
}

/// Imports items from default_store.ad3
pub fn populate_default_store(store: &impl Storelike) -> AtomicResult<()> {
    let ad3 = include_str!("../defaults/default_store.ad3");
    let atoms = crate::parse::parse_ad3(&String::from(ad3))?;
    store.add_atoms(atoms)?;
    Ok(())
}

/// Generates some nice collections for classes, such as `/agent` and `/collection`
pub fn populate_collections(store: &impl Storelike) -> AtomicResult<()> {
    use crate::collections::CollectionBuilder;

    let classes_atoms = store.tpf(
        None,
        Some("https://atomicdata.dev/properties/isA"),
        Some("[\"https://atomicdata.dev/classes/Class\"]"),
    )?;

    for atom in classes_atoms {
        let class = store.get_class(&atom.subject)?;
        let collection = CollectionBuilder::class_collection(&class.subject, &class.shortname, store);
        store.add_resource_unsafe(&collection.to_resource(store)?)?;
    }

    Ok(())
}

#[cfg(feature = "db")]
/// Adds default Endpoints (versioning) to the Db.
/// Makes sure they are fetchable
pub fn populate_endpoints(store: &crate::Db) -> AtomicResult<()> {
    let endpoints = crate::endpoints::default_endpoints();
    for endpoint in endpoints {
        let resource = endpoint.to_resource(store)?;
        store.add_resource(&resource)?;
    }
    Ok(())
}
