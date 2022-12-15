use crate::{agents::ForAgent, urls, Resource, Value};

/// Use this to construct a list of Resources
#[derive(Debug)]
pub struct Query {
    /// Filter by Property
    pub property: Option<String>,
    /// Filter by Value
    pub value: Option<Value>,
    /// Maximum of items to return
    pub limit: Option<usize>,
    /// Value at which to begin lexicographically sorting things.
    pub start_val: Option<Value>,
    /// Value at which to stop lexicographically sorting things.
    pub end_val: Option<Value>,
    /// How many items to skip from the first one
    pub offset: usize,
    /// The Property URL that is used to sort the results
    pub sort_by: Option<String>,
    /// Sort descending instead of ascending.
    pub sort_desc: bool,
    /// Whether to include non-server resources
    pub include_external: bool,
    /// Whether to include full Resources in the result, if not, will add empty vector here.
    pub include_nested: bool,
    /// For which Agent the query is executed. Pass `None` if you want to skip permission checks.
    pub for_agent: ForAgent,
}

impl Query {
    pub fn new() -> Self {
        Query {
            property: None,
            value: None,
            limit: None,
            start_val: None,
            end_val: None,
            offset: 0,
            sort_by: None,
            sort_desc: false,
            include_external: false,
            include_nested: true,
            for_agent: ForAgent::Sudo,
        }
    }

    /// Search for a property-value combination
    pub fn new_prop_val(prop: &str, val: &str) -> Self {
        let mut q = Self::new();
        q.property = Some(prop.to_string());
        q.value = Some(Value::String(val.to_string()));
        q
    }

    /// Search for instances of some Class
    pub fn new_class(class: &str) -> Self {
        let mut q = Self::new();
        q.property = Some(urls::IS_A.into());
        q.value = Some(Value::AtomicUrl(class.to_string()));
        q
    }
}

impl Default for Query {
    fn default() -> Self {
        Self::new()
    }
}

pub struct QueryResult {
    pub subjects: Vec<String>,
    pub resources: Vec<Resource>,
    /// The amount of hits that were found, including the ones that were out of bounds or not authorized.
    pub count: usize,
}
