//! Collections are dynamic resources that refer to multiple resources.
//! They are constructed using a [Query]
#[cfg(feature = "db")]
use crate::class_extender::{ClassExtender, GetExtenderContext};
#[cfg(feature = "db")]
use crate::db::drive_prefix_from_subject;
use crate::{
    agents::ForAgent,
    errors::AtomicResult,
    storelike::{Query, ResourceCollection, ResourceResponse},
    urls, Resource, Storelike, Subject, Value,
};

#[cfg(feature = "db")]
pub fn get_collection_class_extender() -> ClassExtender {
    ClassExtender::builder()
        .id("collection".to_string())
        .classes(vec![urls::COLLECTION.to_string()])
        .on_resource_get(ClassExtender::wrap_get_handler(|context| {
            Box::pin(async move {
                let GetExtenderContext {
                    store,
                    url,
                    db_resource: resource,
                    for_agent,
                } = context;
                construct_collection_from_params(store, url.query_pairs(), resource, for_agent)
                    .await
            })
        }))
        .build()
}

const DEFAULT_PAGE_SIZE: usize = 30;

/// Used to construct a Collection. Does not contain results / members.
/// Has to be constructed using `Collection::new()` or `storelike.new_collection()`.
#[derive(Debug)]
pub struct CollectionBuilder {
    /// Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The property which the results are to be filtered by
    pub property: Option<String>,
    /// The value which the results are to be filtered by
    pub value: Option<String>,
    /// Extra constraints, ANDed with `property`/`value`. Lets a collection
    /// filter on multiple properties, each with its own operator.
    pub filters: Vec<crate::storelike::PropVal>,
    /// URL of the value to sort by
    pub sort_by: Option<String>,
    /// Sorts ascending by default
    pub sort_desc: bool,
    /// Current page number, defaults to 0 (first page)
    pub current_page: usize,
    /// How many items per page
    pub page_size: usize,
    /// A human readable name
    pub name: Option<String>,
    /// Whether it's children should be included as nested resources in the response
    pub include_nested: bool,
    /// Whether to include resources from other servers
    pub include_external: bool,
    /// Scope results to a specific drive. When set, the query index is drive-scoped so watched
    /// queries only trigger for resources in this drive.
    pub drive: Option<Subject>,
    /// Statistics to compute over every matching row, not just this page.
    pub aggregation: Option<crate::aggregate::Aggregation>,
    /// Constraints on values computed per row (a duration, an amount) rather than
    /// stored on it. Evaluated over the set the index narrows to.
    pub expression_filters: Vec<crate::expression::ExpressionFilter>,
}

impl CollectionBuilder {
    /// Converts a CollectionBuilder into a Resource.
    /// Note that this does not calculate any members, and it does not generate any pages.
    /// If that is what you need, use `.into_resource`
    pub async fn to_resource(&self, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        let mut resource = store.get_resource_new(&self.subject.as_str().into()).await;
        resource.set_class(urls::COLLECTION)?;
        if let Some(val) = &self.property {
            resource
                .set_string(crate::urls::COLLECTION_PROPERTY.into(), val, store)
                .await?;
        }
        if let Some(val) = &self.value {
            resource
                .set_string(crate::urls::COLLECTION_VALUE.into(), val, store)
                .await?;
        }
        if let Some(val) = &self.name {
            resource
                .set_string(crate::urls::NAME.into(), val, store)
                .await?;
        }
        if let Some(val) = &self.sort_by {
            resource
                .set_string(crate::urls::COLLECTION_SORT_BY.into(), val, store)
                .await?;
        }
        if self.include_nested {
            resource
                .set_string(crate::urls::COLLECTION_INCLUDE_NESTED.into(), "true", store)
                .await?;
        }
        if self.include_external {
            resource
                .set_string(
                    crate::urls::COLLECTION_INCLUDE_EXTERNAL.into(),
                    "true",
                    store,
                )
                .await?;
        }
        if self.sort_desc {
            resource
                .set_string(crate::urls::COLLECTION_SORT_DESC.into(), "true", store)
                .await?;
        }
        resource
            .set_string(
                crate::urls::COLLECTION_CURRENT_PAGE.into(),
                &self.current_page.to_string(),
                store,
            )
            .await?;
        resource
            .set(
                crate::urls::COLLECTION_PAGE_SIZE.into(),
                self.page_size.into(),
                store,
            )
            .await?;
        // Maybe include items directly
        Ok(resource)
    }

    /// Default CollectionBuilder for Classes. Finds all resources by class URL. Has sensible defaults.
    pub fn class_collection(
        class_url: &str,
        path: &str,
        _store: &impl Storelike,
    ) -> AtomicResult<CollectionBuilder> {
        Ok(CollectionBuilder {
            subject: format!("/{}", path),
            property: Some(urls::IS_A.into()),
            value: Some(class_url.into()),
            filters: Vec::new(),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: Some(format!("{} collection", path)),
            include_nested: true,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        })
    }

    /// Converts the CollectionBuilder into a collection, with Members
    pub async fn into_collection(
        self,
        store: &impl Storelike,
        for_agent: &ForAgent,
    ) -> AtomicResult<Collection> {
        Collection::collect_members(store, self, for_agent).await
    }
}

/// Turns a filter value that arrived over the wire back into the form the
/// store is actually keyed by.
///
/// Subjects go out localized (`internal:/x` is served as `https://example.com/x`,
/// see [crate::serialize]) but are indexed raw, so a client filtering on
/// `parent` sends back a URL that matches nothing. This is invisible on a
/// DID-era server — `did:` subjects resolve to themselves — and total on a
/// store migrated from the pre-DID era, where every subject is `internal:`:
/// the sidebar, folder listings and every other `parent=` query come back
/// empty while the resources are perfectly intact.
///
/// Gated on the property's datatype rather than on "does this look like one of
/// our URLs". Only `AtomicUrl` and `ResourceArray` hold subjects, and only
/// those are localized on the way out. A `String` or `Uri` property is stored
/// verbatim — rewriting a filter for the literal text `https://example.com/x`
/// would break a query that works today. An unknown property (or a lookup
/// failure) is left alone for the same reason.
pub async fn delocalize_filter_value(
    store: &impl Storelike,
    property: Option<&str>,
    raw: &str,
) -> Value {
    let unchanged = Value::String(raw.to_string());

    let Some(property) = property else {
        return unchanged;
    };

    let holds_subjects = matches!(
        store.get_property(property).await,
        Ok(p) if matches!(
            p.data_type,
            crate::datatype::DataType::AtomicUrl | crate::datatype::DataType::ResourceArray
        )
    );

    if !holds_subjects {
        return unchanged;
    }

    match Subject::delocalize(raw, store.get_base_domain().as_deref()) {
        Some(internal) => Value::String(internal),
        None => unchanged,
    }
}

/// Dynamic resource used for ordering, filtering and querying content.
/// Contains members / results. Use CollectionBuilder if you don't (yet) need the results.
/// Features pagination.
#[derive(Debug)]
pub struct Collection {
    /// Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The property which the results are to be filtered by
    pub property: Option<String>,
    /// The value which the results are to be filtered by
    pub value: Option<String>,
    /// The actual items that you're interested in. List the member subjects of the current page.
    pub members: Vec<String>,
    /// The members as full resources, instead of a list of subjects. Is only populated if `nested` is true.
    pub referenced_resources: Option<Vec<Resource>>,
    /// URL of the value to sort by
    pub sort_by: Option<String>,
    // Sorts ascending by default
    pub sort_desc: bool,
    /// How many items per page
    pub page_size: usize,
    /// Current page number, defaults to 0 (first page)
    pub current_page: usize,
    /// Total number of items
    pub total_items: usize,
    /// Total number of pages
    pub total_pages: usize,
    /// Human readable name of a resource
    pub name: Option<String>,
    /// Whether it's children should be included as nested resources in the response
    pub include_nested: bool,
    /// Include resources from other servers
    pub include_external: bool,
    /// The computed statistics, one per requested aggregate. Over every matching
    /// row, so these do not change as you page through.
    pub aggregates: Vec<crate::aggregate::AggregateOutcome>,
}

/// Sorts a vector or resources by some property.
#[tracing::instrument(skip_all)]
pub fn sort_resources(
    mut resources: ResourceCollection,
    sort_by: &str,
    sort_desc: bool,
) -> ResourceCollection {
    resources.sort_by(|a, b| {
        let val_a = a.get(sort_by);
        let val_b = b.get(sort_by);
        if val_a.is_err() || val_b.is_err() {
            return std::cmp::Ordering::Greater;
        };
        if val_b.unwrap().to_string() > val_a.unwrap().to_string() {
            if sort_desc {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        } else if sort_desc {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    resources
}

impl Collection {
    /// Constructs a Collection, which is a paginated list of items with some sorting applied.
    /// Gets the required data from the store.
    /// Applies sorting settings.
    #[tracing::instrument(skip_all)]
    pub async fn collect_members(
        store: &impl Storelike,
        collection_builder: crate::collections::CollectionBuilder,
        for_agent: &ForAgent,
    ) -> AtomicResult<Collection> {
        if collection_builder.page_size < 1 {
            return Err("Page size must be greater than 0".into());
        }

        // Warning: this _assumes_ that the Value is a string.
        // This will work for most datatypes, but not for things like resource arrays!
        // We could improve this by taking the datatype of the `property`, and parsing the string.
        let value_filter = match collection_builder.value.as_ref() {
            Some(val) => Some(
                delocalize_filter_value(store, collection_builder.property.as_deref(), val).await,
            ),
            None => None,
        };

        let mut filters = collection_builder.filters.clone();
        for filter in filters.iter_mut() {
            let (Some(property), Some(Value::String(raw))) =
                (filter.property.as_deref(), filter.value.as_ref())
            else {
                continue;
            };
            let raw = raw.clone();
            filter.value = Some(delocalize_filter_value(store, Some(property), &raw).await);
        }

        let q = Query {
            property: collection_builder.property.clone(),
            value: value_filter,
            filters,
            expression_filters: collection_builder.expression_filters.clone(),
            limit: Some(collection_builder.page_size),
            start_val: None,
            end_val: None,
            offset: collection_builder.page_size * collection_builder.current_page,
            sort_by: collection_builder.sort_by.clone(),
            sort_desc: collection_builder.sort_desc,
            include_external: collection_builder.include_external,
            include_nested: collection_builder.include_nested,
            for_agent: for_agent.clone(),
            drive: collection_builder.drive.clone(),
            aggregation: collection_builder.aggregation.clone(),
        };

        let query_result = store.query(&q).await?;
        let members: Vec<String> = query_result
            .subjects
            .iter()
            .map(|s| s.to_string())
            .collect();
        let referenced_resources = if collection_builder.include_nested {
            Some(query_result.resources)
        } else {
            None
        };
        let total_items = query_result.count;
        let pages_fraction = total_items as f64 / collection_builder.page_size as f64;
        let total_pages = pages_fraction.ceil() as usize;
        if collection_builder.current_page > total_pages {
            return Err(format!(
                "Page number out of bounds, got {}, max {}",
                collection_builder.current_page, total_pages
            )
            .into());
        }

        let collection = Collection {
            total_pages,
            members,
            referenced_resources,
            total_items,
            subject: collection_builder.subject,
            property: collection_builder.property,
            value: collection_builder.value,
            sort_by: collection_builder.sort_by,
            sort_desc: collection_builder.sort_desc,
            current_page: collection_builder.current_page,
            page_size: collection_builder.page_size,
            name: collection_builder.name,
            include_nested: collection_builder.include_nested,
            include_external: collection_builder.include_external,
            aggregates: query_result.aggregates,
        };
        Ok(collection)
    }

    pub async fn to_resource(&self, store: &impl Storelike) -> AtomicResult<ResourceResponse> {
        let mut resource = crate::Resource::new(self.subject.clone());
        self.add_to_resource(&mut resource, store).await
    }

    /// Adds the Collection props to an existing Resource.
    pub async fn add_to_resource(
        &self,
        resource: &mut Resource,
        store: &impl Storelike,
    ) -> AtomicResult<ResourceResponse> {
        resource
            .set(
                crate::urls::COLLECTION_MEMBERS.into(),
                self.members.clone().into(),
                store,
            )
            .await?;
        if let Some(prop) = &self.property {
            resource
                .set_string(crate::urls::COLLECTION_PROPERTY.into(), prop, store)
                .await?;
        }
        if self.include_nested {
            resource
                .set_string(crate::urls::COLLECTION_INCLUDE_NESTED.into(), "true", store)
                .await?;
        }
        if self.include_external {
            resource
                .set_string(
                    crate::urls::COLLECTION_INCLUDE_EXTERNAL.into(),
                    "true",
                    store,
                )
                .await?;
        }
        if let Some(val) = &self.value {
            resource
                .set_string(crate::urls::COLLECTION_VALUE.into(), val, store)
                .await?;
        }
        if let Some(val) = &self.name {
            resource
                .set_string(crate::urls::NAME.into(), val, store)
                .await?;
        }
        resource
            .set(
                crate::urls::COLLECTION_MEMBER_COUNT.into(),
                self.total_items.into(),
                store,
            )
            .await?;
        if !self.aggregates.is_empty() {
            // As JSON rather than a resource per statistic: these are a computed
            // read of the collection, not stored data anyone can address.
            //
            // `set_unsafe` skips the property lookup on purpose. The value is
            // already typed here, this resource is never stored or validated,
            // and a store seeded before this property existed in the defaults
            // would otherwise fail the whole query with a 404 for the property
            // instead of answering it.
            resource.set_unsafe(
                crate::urls::COLLECTION_AGGREGATES.into(),
                Value::Json(serde_json::to_value(&self.aggregates).map_err(|e| {
                    format!("Could not serialize the collection's aggregates: {e}")
                })?),
            )?;
        }
        let classes: Vec<String> = vec![crate::urls::COLLECTION.into()];
        resource
            .set(crate::urls::IS_A.into(), classes.into(), store)
            .await?;
        resource
            .set(
                crate::urls::COLLECTION_TOTAL_PAGES.into(),
                self.total_pages.into(),
                store,
            )
            .await?;
        resource
            .set(
                crate::urls::COLLECTION_CURRENT_PAGE.into(),
                self.current_page.into(),
                store,
            )
            .await?;
        resource
            .set(
                crate::urls::COLLECTION_PAGE_SIZE.into(),
                self.page_size.into(),
                store,
            )
            .await?;

        match &self.referenced_resources {
            Some(referenced_resources) => Ok(ResourceResponse::ResourceWithReferenced(
                resource.clone(),
                referenced_resources.clone(),
            )),
            None => Ok(ResourceResponse::Resource(resource.clone())),
        }
    }
}

/// Builds a collection from query params and the passed Collection resource.
/// The query params are used to override the stored Collection resource properties.
/// This also sets defaults for Collection properties when fields are missing
#[cfg(feature = "db")]
#[tracing::instrument(skip_all)]
pub async fn construct_collection_from_params(
    store: &impl Storelike,
    query_params: url::form_urlencoded::Parse<'_>,
    resource: &mut Resource,
    for_agent: &ForAgent,
) -> AtomicResult<ResourceResponse> {
    let mut sort_by = None;
    let mut sort_desc = false;
    let mut current_page = 0;
    let mut page_size = DEFAULT_PAGE_SIZE;
    let mut value = None;
    let mut property = None;
    let mut filters: Vec<crate::storelike::PropVal> = Vec::new();
    let mut name = None;
    let mut include_nested = false;
    let mut include_external = false;
    let mut drive: Option<Subject> = None;
    let mut aggregation: Option<crate::aggregate::Aggregation> = None;
    let mut expression_filters: Vec<crate::expression::ExpressionFilter> = Vec::new();

    if let Ok(val) = resource.get(urls::COLLECTION_PROPERTY) {
        property = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::COLLECTION_PAGE_SIZE) {
        page_size = val.to_int()?.try_into().unwrap_or(DEFAULT_PAGE_SIZE);
    }
    if let Ok(val) = resource.get(urls::COLLECTION_VALUE) {
        value = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::NAME) {
        name = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::COLLECTION_INCLUDE_NESTED) {
        include_nested = val.to_bool()?;
    }
    if let Ok(val) = resource.get(urls::COLLECTION_INCLUDE_EXTERNAL) {
        include_external = val.to_bool()?;
    }
    for (k, v) in query_params {
        match k.as_ref() {
            "property" => property = Some(v.to_string()),
            "value" => value = Some(v.to_string()),
            // Extra AND constraints as a JSON array, each with an optional
            // operator: `[{"property":"…","value":"…","operator":"gt"}]`.
            "filters" => {
                #[derive(serde::Deserialize)]
                struct FilterParam {
                    property: String,
                    value: String,
                    operator: Option<String>,
                }
                let parsed: Vec<FilterParam> = serde_json::from_str(v.as_ref()).map_err(|e| {
                    format!(
                        "Invalid `filters` param (expected JSON array of {{property, value, operator?}}): {e}"
                    )
                })?;
                filters = parsed
                    .into_iter()
                    .map(|f| crate::storelike::PropVal {
                        property: Some(f.property),
                        value: Some(Value::String(f.value)),
                        operator: crate::storelike::filter_operator_from_str(f.operator.as_deref()),
                    })
                    .collect();
            }
            "sort_by" => sort_by = Some(v.to_string()),
            "sort_desc" => sort_desc = v.parse::<bool>()?,
            "current_page" => current_page = v.parse::<usize>()?,
            "page_size" => page_size = v.parse::<usize>()?,
            "include_nested" => include_nested = v.parse::<bool>()?,
            "include_external" => include_external = v.parse::<bool>()?,
            "drive" => drive = Some(Subject::from(v.as_ref())),
            // Statistics over every matching row, as JSON:
            // `{"aggregates":[{"property":"…","function":"sum"}],
            //   "group_by":{"property":"…","granularity":"day","tz_offset_minutes":120}}`
            "aggregation" => {
                let parsed: crate::aggregate::Aggregation =
                    serde_json::from_str(v.as_ref()).map_err(|e| {
                        format!(
                            "Invalid `aggregation` param (expected JSON {{aggregates: [{{property?, function}}], group_by?}}): {e}"
                        )
                    })?;
                aggregation = Some(parsed);
            }
            // Constraints on computed values, as JSON:
            // `[{"expression":{"kind":"elapsed","from":"…","until":"…"},
            //    "operator":"gt","value":3600000}]`
            "expression_filters" => {
                expression_filters = serde_json::from_str(v.as_ref()).map_err(|e| {
                    format!(
                        "Invalid `expression_filters` param (expected JSON array of {{expression, operator?, value}}): {e}"
                    )
                })?;
            }
            e => {
                return Err(format!("Invalid query param: {}", e).into());
            }
        };
    }
    let collection_builder = crate::collections::CollectionBuilder {
        subject: resource.get_subject().to_string(),
        property,
        value,
        filters,
        sort_by,
        sort_desc,
        current_page,
        page_size,
        name,
        include_nested,
        include_external,
        drive: Some(drive.unwrap_or_else(|| drive_prefix_from_subject(resource.get_subject()))),
        aggregation,
        expression_filters,
    };
    let collection = Collection::collect_members(store, collection_builder, for_agent).await?;
    collection.add_to_resource(resource, store).await
}

/// Creates a Collection resource in the Store for a Class, for example `/documents`.
/// Does not save it, though.
pub async fn create_collection_resource_for_class(
    store: &impl Storelike,
    class_subject: &str,
) -> AtomicResult<Resource> {
    let class = store.get_class(class_subject).await?;

    // Pluralize the shortname
    let pluralized = match class.shortname.as_ref() {
        "class" => "classes".to_string(),
        "property" => "properties".to_string(),
        other => format!("{}s", other),
    };

    let mut collection = CollectionBuilder::class_collection(&class.subject, &pluralized, store)?;

    collection.sort_by = match class_subject {
        urls::CLASS | urls::PROPERTY => Some(urls::SHORTNAME.to_string()),
        urls::COLLECTION => Some(urls::COLLECTION_VALUE.to_string()),
        _other => None,
    };

    // Agents use DID subjects which are external, so we need to include external resources
    collection.include_external = match class_subject {
        urls::AGENT => true,
        _other => false,
    };

    let mut collection_resource = collection.to_resource(store).await?;

    let drive = "/";

    // Let the Collections collection be the top level item
    let parent = if class.subject == urls::COLLECTION {
        drive.to_string()
    } else if drive == "/" {
        "/collections".to_string()
    } else {
        format!("{}/collections", drive)
    };

    collection_resource
        .set_string(urls::PARENT.into(), &parent, store)
        .await?;

    collection_resource
        .set_string(urls::NAME.into(), &pluralized, store)
        .await?;

    // Should we use save_locally, which creates commits, or add_resource_unsafe, which is faster?
    Ok(collection_resource)
}

#[cfg(test)]
#[cfg(feature = "db")]
mod test {
    use super::*;
    use crate::urls;
    use crate::values::SubResource;
    use crate::Storelike;

    #[tokio::test]
    async fn create_collection() {
        let store = crate::Store::init().await.unwrap();
        store.populate().await.unwrap();
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            filters: Vec::new(),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: Some("Test collection".into()),
            include_nested: false,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        };
        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));
    }

    #[tokio::test]
    async fn create_collection_2() {
        let store = crate::Store::init().await.unwrap();
        store.populate().await.unwrap();
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            filters: Vec::new(),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            include_nested: false,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        };
        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));

        let resource_collection = &collection.to_resource(&store).await.unwrap().to_single();
        resource_collection
            .get(urls::COLLECTION_INCLUDE_NESTED)
            .unwrap_err();
    }

    #[tokio::test]
    async fn collection_multi_property_and_filter() {
        let store = crate::db::Db::init_temp("collection_multi_property_and_filter")
            .await
            .unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();
        store.populate().await.unwrap();

        // Two tags share `isA = Tag` but differ on `shortname`.
        let mut tag_a = Resource::new_instance(urls::TAG, &store).await.unwrap();
        tag_a
            .set(urls::SHORTNAME.into(), Value::Slug("tag-a".into()), &store)
            .await
            .unwrap();
        tag_a.save(&store).await.unwrap();

        let mut tag_b = Resource::new_instance(urls::TAG, &store).await.unwrap();
        tag_b
            .set(urls::SHORTNAME.into(), Value::Slug("tag-b".into()), &store)
            .await
            .unwrap();
        tag_b.save(&store).await.unwrap();

        // AND filter: isA = Tag AND shortname = tag-a → only tag_a.
        let drive = crate::db::drive_prefix_from_subject(tag_a.get_subject());
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::TAG.into()),
            filters: vec![crate::storelike::PropVal {
                property: Some(urls::SHORTNAME.to_string()),
                value: Some(Value::String("tag-a".to_string())),
                ..Default::default()
            }],
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            include_nested: false,
            include_external: false,
            drive: Some(drive),
            aggregation: None,
            expression_filters: Vec::new(),
        };
        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();

        assert!(
            collection
                .members
                .contains(&tag_a.get_subject().to_string()),
            "tag_a matches both constraints and should be a member: {:?}",
            collection.members
        );
        assert!(
            !collection
                .members
                .contains(&tag_b.get_subject().to_string()),
            "tag_b only matches isA, not shortname, so should be excluded: {:?}",
            collection.members
        );
    }

    /// Subjects are stored (and indexed) as `internal:/…` but served
    /// localized, so a client filtering on `parent` sends back the absolute
    /// URL it was given. Both spellings must find the same members.
    ///
    /// Regression: on a store migrated from the pre-DID era every subject is
    /// `internal:`, so this mismatch emptied the sidebar and every folder
    /// listing while the resources themselves were intact. Invisible on a
    /// DID-era server, where subjects resolve to themselves.
    #[tokio::test]
    async fn localized_subject_filter_finds_internally_stored_members() {
        let store = crate::db::Db::init_temp("delocalize_query_value")
            .await
            .unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();

        let mut child = Resource::new_instance(urls::TAG, &store).await.unwrap();
        child
            .set(urls::SHORTNAME.into(), Value::Slug("child".into()), &store)
            .await
            .unwrap();
        child
            .set(
                urls::PARENT.into(),
                Value::AtomicUrl("internal:/".into()),
                &store,
            )
            .await
            .unwrap();
        child.save(&store).await.unwrap();

        let members_for = |value: &str| {
            let value = value.to_string();
            async {
                Collection::collect_members(
                    &store,
                    CollectionBuilder {
                        subject: "test_subject".into(),
                        property: Some(urls::PARENT.into()),
                        value: Some(value),
                        filters: Vec::new(),
                        sort_by: None,
                        sort_desc: false,
                        page_size: DEFAULT_PAGE_SIZE,
                        current_page: 0,
                        name: None,
                        include_nested: false,
                        include_external: false,
                        drive: None,
                        aggregation: None,
                        expression_filters: Vec::new(),
                    },
                    &ForAgent::Sudo,
                )
                .await
                .unwrap()
                .members
            }
        };

        // `init_temp` configures the base domain as `https://localhost`, so
        // this is exactly what a browser is served for `internal:/`.
        let stored = members_for("internal:/").await;
        let localized = members_for("https://localhost/").await;

        assert!(
            stored.contains(&child.get_subject().to_string()),
            "the stored spelling should find the child: {stored:?}"
        );
        assert_eq!(
            stored, localized,
            "a client filtering with the localized subject it was served must \
             get the same members as the stored `internal:` spelling"
        );
    }

    /// The de-localization above is gated on the property's datatype. A
    /// text-valued property holds text, not a subject, and is never
    /// localized on the way out — rewriting a filter for text that merely
    /// looks like one of our URLs would break a query that works today.
    #[tokio::test]
    async fn text_valued_filters_are_left_alone() {
        let store = crate::db::Db::init_temp("delocalize_leaves_strings")
            .await
            .unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();

        let text = "https://localhost/not-a-subject";
        let mut tag = Resource::new_instance(urls::TAG, &store).await.unwrap();
        tag.set(urls::SHORTNAME.into(), Value::Slug("texty".into()), &store)
            .await
            .unwrap();
        tag.set(
            urls::DESCRIPTION.into(),
            Value::Markdown(text.to_string()),
            &store,
        )
        .await
        .unwrap();
        tag.save(&store).await.unwrap();

        let collection = Collection::collect_members(
            &store,
            CollectionBuilder {
                subject: "test_subject".into(),
                property: Some(urls::DESCRIPTION.into()),
                value: Some(text.to_string()),
                filters: Vec::new(),
                sort_by: None,
                sort_desc: false,
                page_size: DEFAULT_PAGE_SIZE,
                current_page: 0,
                name: None,
                include_nested: false,
                include_external: false,
                drive: None,
                aggregation: None,
                expression_filters: Vec::new(),
            },
            &ForAgent::Sudo,
        )
        .await
        .unwrap();

        assert!(
            collection.members.contains(&tag.get_subject().to_string()),
            "a String-valued property stores the text verbatim, so filtering \
             for it must still match: {:?}",
            collection.members
        );
    }

    #[tokio::test]
    async fn query_on_resource_arrays() {
        let store = crate::db::Db::init_temp("query_on_resource_arrays")
            .await
            .unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();

        store.populate().await.unwrap();
        let mut resource1 = Resource::new_instance(urls::TAG, &store).await.unwrap();
        resource1
            .set(urls::SHORTNAME.into(), Value::Slug("tag1".into()), &store)
            .await
            .unwrap();
        resource1
            .push(
                urls::ENDPOINT_RESULTS,
                SubResource::Subject("https://example.com/resource1".into()),
                false,
            )
            .unwrap();

        resource1.save(&store).await.unwrap();

        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::ENDPOINT_RESULTS.into()),
            value: Some("https://example.com/resource1".into()),
            filters: Vec::new(),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            include_nested: false,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        };
        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();

        assert!(collection
            .members
            .contains(&resource1.get_subject().to_string()));

        resource1
            .set(
                urls::ENDPOINT_RESULTS.into(),
                Value::ResourceArray(vec![SubResource::Subject(
                    "https://example.com/resource3".into(),
                )]),
                &store,
            )
            .await
            .unwrap();

        resource1.save(&store).await.unwrap();

        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::ENDPOINT_RESULTS.into()),
            value: Some("https://example.com/resource1".into()),
            filters: Vec::new(),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            include_nested: false,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        };

        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();

        assert!(!collection
            .members
            .contains(&resource1.get_subject().to_string()));

        resource1
            .push(
                urls::ENDPOINT_RESULTS,
                SubResource::Subject("https://example.com/resource2".into()),
                false,
            )
            .unwrap();

        resource1.save(&store).await.unwrap();

        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::ENDPOINT_RESULTS.into()),
            value: Some("https://example.com/resource2".into()),
            filters: Vec::new(),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            include_nested: false,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        };

        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();

        assert!(collection
            .members
            .contains(&resource1.get_subject().to_string()));
    }

    /// Tests that multiple consecutive push operations work correctly with collections.
    /// This specifically tests the scenario where array length changes with each push,
    /// ensuring the query index keys remain consistent.
    #[tokio::test]
    async fn query_on_resource_arrays_multiple_pushes() {
        let store = crate::db::Db::init_temp("query_on_resource_arrays_multiple_pushes")
            .await
            .unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();

        store.populate().await.unwrap();
        let mut resource1 = Resource::new_instance(urls::TAG, &store).await.unwrap();
        resource1
            .set(urls::SHORTNAME.into(), Value::Slug("tag1".into()), &store)
            .await
            .unwrap();

        // Push first item
        resource1
            .push(
                urls::ENDPOINT_RESULTS,
                SubResource::Subject("https://example.com/item1".into()),
                false,
            )
            .unwrap();
        resource1.save(&store).await.unwrap();

        // Should find resource when querying for item1
        let collection = Collection::collect_members(
            &store,
            CollectionBuilder {
                subject: "test_subject".into(),
                property: Some(urls::ENDPOINT_RESULTS.into()),
                value: Some("https://example.com/item1".into()),
                filters: Vec::new(),
                sort_by: None,
                sort_desc: false,
                page_size: DEFAULT_PAGE_SIZE,
                current_page: 0,
                name: None,
                include_nested: false,
                include_external: false,
                drive: None,
                aggregation: None,
                expression_filters: Vec::new(),
            },
            &ForAgent::Sudo,
        )
        .await
        .unwrap();
        assert!(
            collection
                .members
                .contains(&resource1.get_subject().to_string()),
            "Should find resource after first push"
        );

        // Push second item (array length changes from 1 to 2)
        resource1
            .push(
                urls::ENDPOINT_RESULTS,
                SubResource::Subject("https://example.com/item2".into()),
                false,
            )
            .unwrap();
        resource1.save(&store).await.unwrap();

        // Should still find resource when querying for item1
        let collection = Collection::collect_members(
            &store,
            CollectionBuilder {
                subject: "test_subject".into(),
                property: Some(urls::ENDPOINT_RESULTS.into()),
                value: Some("https://example.com/item1".into()),
                filters: Vec::new(),
                sort_by: None,
                sort_desc: false,
                page_size: DEFAULT_PAGE_SIZE,
                current_page: 0,
                name: None,
                include_nested: false,
                include_external: false,
                drive: None,
                aggregation: None,
                expression_filters: Vec::new(),
            },
            &ForAgent::Sudo,
        )
        .await
        .unwrap();
        assert!(
            collection
                .members
                .contains(&resource1.get_subject().to_string()),
            "Should still find resource for item1 after second push"
        );

        // Should also find resource when querying for item2
        let collection = Collection::collect_members(
            &store,
            CollectionBuilder {
                subject: "test_subject".into(),
                property: Some(urls::ENDPOINT_RESULTS.into()),
                value: Some("https://example.com/item2".into()),
                filters: Vec::new(),
                sort_by: None,
                sort_desc: false,
                page_size: DEFAULT_PAGE_SIZE,
                current_page: 0,
                name: None,
                include_nested: false,
                include_external: false,
                drive: None,
                aggregation: None,
                expression_filters: Vec::new(),
            },
            &ForAgent::Sudo,
        )
        .await
        .unwrap();
        assert!(
            collection
                .members
                .contains(&resource1.get_subject().to_string()),
            "Should find resource for item2 after second push"
        );

        // Push third item (array length changes from 2 to 3)
        resource1
            .push(
                urls::ENDPOINT_RESULTS,
                SubResource::Subject("https://example.com/item3".into()),
                false,
            )
            .unwrap();
        resource1.save(&store).await.unwrap();

        // Should find resource for all three items
        for item in ["item1", "item2", "item3"] {
            let collection = Collection::collect_members(
                &store,
                CollectionBuilder {
                    subject: "test_subject".into(),
                    property: Some(urls::ENDPOINT_RESULTS.into()),
                    value: Some(format!("https://example.com/{}", item)),
                    filters: Vec::new(),
                    sort_by: None,
                    sort_desc: false,
                    page_size: DEFAULT_PAGE_SIZE,
                    current_page: 0,
                    name: None,
                    include_nested: false,
                    include_external: false,
                    drive: None,
                    aggregation: None,
                    expression_filters: Vec::new(),
                },
                &ForAgent::Sudo,
            )
            .await
            .unwrap();
            assert!(
                collection
                    .members
                    .contains(&resource1.get_subject().to_string()),
                "Should find resource for {} after third push",
                item
            );
        }

        // Now set to replace with completely different items
        resource1
            .set(
                urls::ENDPOINT_RESULTS.into(),
                Value::ResourceArray(vec![SubResource::Subject(
                    "https://example.com/newitem".into(),
                )]),
                &store,
            )
            .await
            .unwrap();
        resource1.save(&store).await.unwrap();

        // Old items should no longer be found
        for item in ["item1", "item2", "item3"] {
            let collection = Collection::collect_members(
                &store,
                CollectionBuilder {
                    subject: "test_subject".into(),
                    property: Some(urls::ENDPOINT_RESULTS.into()),
                    value: Some(format!("https://example.com/{}", item)),
                    filters: Vec::new(),
                    sort_by: None,
                    sort_desc: false,
                    page_size: DEFAULT_PAGE_SIZE,
                    current_page: 0,
                    name: None,
                    include_nested: false,
                    include_external: false,
                    drive: None,
                    aggregation: None,
                    expression_filters: Vec::new(),
                },
                &ForAgent::Sudo,
            )
            .await
            .unwrap();
            assert!(
                !collection
                    .members
                    .contains(&resource1.get_subject().to_string()),
                "Should NOT find resource for {} after set replacement",
                item
            );
        }

        // New item should be found
        let collection = Collection::collect_members(
            &store,
            CollectionBuilder {
                subject: "test_subject".into(),
                property: Some(urls::ENDPOINT_RESULTS.into()),
                value: Some("https://example.com/newitem".into()),
                filters: Vec::new(),
                sort_by: None,
                sort_desc: false,
                page_size: DEFAULT_PAGE_SIZE,
                current_page: 0,
                name: None,
                include_nested: false,
                include_external: false,
                drive: None,
                aggregation: None,
                expression_filters: Vec::new(),
            },
            &ForAgent::Sudo,
        )
        .await
        .unwrap();
        assert!(
            collection
                .members
                .contains(&resource1.get_subject().to_string()),
            "Should find resource for newitem after set"
        );
    }

    #[tokio::test]
    async fn create_collection_nested_members_and_sorting() {
        let store = crate::Store::init().await.unwrap();
        store.populate().await.unwrap();
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            filters: Vec::new(),
            sort_by: Some(urls::SHORTNAME.into()),
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            // The important bit here
            include_nested: true,
            include_external: false,
            drive: None,
            aggregation: None,
            expression_filters: Vec::new(),
        };
        let collection = Collection::collect_members(&store, collection_builder, &ForAgent::Sudo)
            .await
            .unwrap();
        let first_resource = &collection.referenced_resources.clone().unwrap()[0];
        assert!(first_resource.get_subject().as_str().contains("Agent"));

        let resource_collection = &collection.to_resource(&store).await.unwrap().to_single();
        let val = resource_collection
            .get(urls::COLLECTION_INCLUDE_NESTED)
            .unwrap()
            .to_bool()
            .unwrap();
        assert!(val, "Include nested must be true");
    }

    #[tokio::test]
    #[cfg(feature = "db")]
    async fn get_collection() {
        let store = crate::db::test::get_shared_db()
            .await
            .lock()
            .unwrap()
            .clone();
        let collections_collection = store
            .get_resource_extended(&"internal:/collections".into(), false, &ForAgent::Public)
            .await
            .unwrap()
            .to_single();
        assert!(
            collections_collection
                .get(urls::COLLECTION_PROPERTY)
                .unwrap()
                .to_string()
                == urls::IS_A
        );
        let member_count = collections_collection
            .get(urls::COLLECTION_MEMBER_COUNT)
            .unwrap();
        println!("Member Count is {}", member_count);
        assert!(
            member_count.to_int().unwrap() > 10,
            "Member count is too small"
        );
    }

    #[tokio::test]
    #[ignore]
    // TODO: This currently only tests atomicdata.dev, should test local resources. These need to be rewritten
    async fn get_collection_params() {
        let store = crate::Store::init().await.unwrap();
        store.populate().await.unwrap();

        let collection_page_size = store
            .get_resource_extended(
                &"https://atomicdata.dev/classes?page_size=1".into(),
                false,
                &ForAgent::Public,
            )
            .await
            .unwrap()
            .to_single();
        assert!(
            collection_page_size
                .get(urls::COLLECTION_PAGE_SIZE)
                .unwrap()
                .to_string()
                == "1"
        );
        let collection_page_nr = store
            .get_resource_extended(
                &"https://atomicdata.dev/classes?current_page=2&page_size=1".into(),
                false,
                &ForAgent::Public,
            )
            .await
            .unwrap()
            .to_single();
        assert!(
            collection_page_nr
                .get(urls::COLLECTION_PAGE_SIZE)
                .unwrap()
                .to_string()
                == "1"
        );
        let members_vec = match collection_page_nr.get(urls::COLLECTION_MEMBERS).unwrap() {
            crate::Value::ResourceArray(vec) => vec,
            _ => panic!(),
        };
        assert!(members_vec.len() == 1);
        assert!(
            collection_page_nr
                .get(urls::COLLECTION_CURRENT_PAGE)
                .unwrap()
                .to_string()
                == "2"
        );
    }

    #[test]
    fn sorting_resources() {
        let prop = urls::DESCRIPTION.to_string();
        let mut a = Resource::new("first".into());
        a.set_unsafe(prop.clone(), Value::Markdown("1".into()))
            .unwrap();
        let mut b = Resource::new("second".into());
        b.set_unsafe(prop.clone(), Value::Markdown("2".into()))
            .unwrap();
        let c = Resource::new("third_missing_property".into());

        let asc = vec![a.clone(), b.clone(), c.clone()];
        let sorted = sort_resources(asc.clone(), &prop, false);
        assert_eq!(a.get_subject(), sorted[0].get_subject());
        assert_eq!(b.get_subject(), sorted[1].get_subject());
        assert_eq!(c.get_subject(), sorted[2].get_subject());

        let sorted_desc = sort_resources(asc, &prop, true);
        assert_eq!(b.get_subject(), sorted_desc[0].get_subject());
        assert_eq!(a.get_subject(), sorted_desc[1].get_subject());
        assert_eq!(
            c.get_subject(),
            sorted_desc[2].get_subject(),
            "c is missing the sorted property - it should _alway_ be last"
        );
    }

    /// Verifies that resources with DID subjects (`did:ad:...`) are correctly indexed and
    /// returned by sorted queries. This simulates the chatroom refresh scenario where messages
    /// have DID subjects but must appear when the chatroom queries by parent + sort by createdAt.
    #[tokio::test]
    async fn did_subject_resource_appears_in_sorted_query() {
        let store = crate::db::Db::init_temp("did_subject_resource_appears_in_sorted_query")
            .await
            .unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();
        store.populate().await.unwrap();

        // Create a chatroom-like resource (normal internal subject)
        let mut chatroom = Resource::new_instance(urls::CHATROOM, &store)
            .await
            .unwrap();
        chatroom
            .set(
                urls::NAME.into(),
                crate::Value::String("Test Chat".into()),
                &store,
            )
            .await
            .unwrap();
        store
            .add_resource_opts(&chatroom, false, true, true)
            .await
            .unwrap();
        let chatroom_subject = chatroom.get_subject().clone();

        // First query to register the query as watched (empty chatroom)
        let q = crate::storelike::Query {
            property: Some(urls::PARENT.into()),
            value: Some(crate::Value::AtomicUrl(chatroom_subject.clone())),
            filters: Vec::new(),
            sort_by: Some(urls::CREATED_AT.into()),
            sort_desc: true,
            limit: Some(10),
            include_nested: false,
            include_external: false,
            drive: Some(crate::Subject::from("internal:/")),
            ..Default::default()
        };
        let result = store.query(&q).await.unwrap();
        assert_eq!(result.subjects.len(), 0, "Chatroom should start empty");

        // Create a message with a DID subject (simulating genesis commit result)
        let did_subject = crate::Subject::from("did:ad:TestSignatureHere123");
        let mut message = Resource::new(did_subject.to_string());
        message
            .set_unsafe(
                urls::PARENT.into(),
                crate::Value::AtomicUrl(chatroom_subject.clone()),
            )
            .unwrap();
        message
            .set_unsafe(urls::CREATED_AT.into(), crate::Value::Timestamp(1000000))
            .unwrap();
        message
            .set_unsafe(
                urls::IS_A.into(),
                crate::Value::ResourceArray(vec![crate::values::SubResource::Subject(
                    urls::MESSAGE.into(),
                )]),
            )
            .unwrap();

        // Add the DID message to the store with index update (simulating apply_commit)
        store
            .add_resource_opts(&message, false, true, true)
            .await
            .unwrap();

        // Query again - should now find the DID message
        let result = store.query(&q).await.unwrap();
        assert_eq!(
            result.subjects.len(),
            1,
            "DID message should appear in chatroom query after being added"
        );
        assert_eq!(
            result.subjects[0].as_str(),
            "did:ad:TestSignatureHere123",
            "The DID subject should be returned"
        );
    }
}
