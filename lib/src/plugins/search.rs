use crate::{endpoints::Endpoint, urls};

// Note that the actual logic of this endpoint resides in `atomic-server`, as it depends on the Actix runtime.
pub fn search_endpoint() -> Endpoint {
    Endpoint {
      path: "/search".to_string(),
      params: vec![
        urls::SEARCH_QUERY.into(),
        urls::SEARCH_LIMIT.into(),
        urls::SEARCH_PROPERTY.into(),
    ],
      description: "Full text-search endpoint. You can use the keyword `AND` and `OR`, or use `\"` for advanced searches. ".to_string(),
      shortname: "search".to_string(),
      handle: None,
      handle_post: None,
  }
}
