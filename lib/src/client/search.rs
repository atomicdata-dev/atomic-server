/*!
# Search Client

Use the `/search` endpoint from AtomicServer to perform full-text search.
*/

use std::collections::HashMap;
use url::Url;

// Define the SearchOpts struct with optional fields
#[derive(Debug, Default)]
pub struct SearchOpts {
    pub include: Option<bool>,
    pub limit: Option<u32>,
    pub parents: Option<Vec<String>>,
    pub filters: Option<HashMap<String, String>>,
}

// Function to build the base URL for search
fn base_url(server_url: &str) -> Url {
    let mut url = Url::parse(server_url).expect("Invalid server URL");
    url.set_path("search");
    url
}

// Special characters for Tantivy query escaping
const SPECIAL_CHARS_TANTIVY: &[char] = &[
    '+', '^', '`', ':', '{', '}', '"', '[', ']', '(', ')', '!', '\\', '*', ' ', '.',
];

// Escape function for Tantivy syntax
fn escape_tantivy_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if SPECIAL_CHARS_TANTIVY.contains(&c) {
                format!("\\{}", c)
            } else {
                c.to_string()
            }
        })
        .collect()
}

// Build the filter string for the URL
fn build_filter_string(filters: &HashMap<String, String>) -> String {
    filters
        .iter()
        .filter_map(|(key, value)| {
            if !value.is_empty() {
                Some(format!("{}:\"{}\"", escape_tantivy_key(key), value))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

// Build the complete search URL with query parameters
pub fn build_search_subject(server_url: &str, query: &str, opts: SearchOpts) -> String {
    let mut url = base_url(server_url);

    url.query_pairs_mut().append_pair("q", query);
    if let Some(include) = opts.include {
        url.query_pairs_mut()
            .append_pair("include", &include.to_string());
    }
    if let Some(limit) = opts.limit {
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
    }
    if let Some(filters) = opts.filters {
        if !filters.is_empty() {
            let filter_string = build_filter_string(&filters);
            url.query_pairs_mut().append_pair("filters", &filter_string);
        }
    }
    if let Some(parents) = opts.parents {
        let parents_string = parents.join(",");
        url.query_pairs_mut()
            .append_pair("parents", &parents_string);
    }

    url.to_string()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_url() {
        let server_url = "http://example.com";
        let expected_url = "http://example.com/search";
        assert_eq!(base_url(server_url).to_string(), expected_url);
    }

    #[test]
    fn test_escape_tantivy_key() {
        let key = "+^`:{}\"[]()!\\* .";
        let expected_escaped_key = "\\+\\^\\`\\:\\{\\}\\\"\\[\\]\\(\\)\\!\\\\\\*\\ \\.";
        assert_eq!(escape_tantivy_key(key), expected_escaped_key);
    }

    #[test]
    fn test_build_filter_string() {
        let mut filters = HashMap::new();
        filters.insert("name".to_string(), "John".to_string());
        filters.insert("age".to_string(), "30".to_string());
        let expected_filter_string = "name:\"John\" AND age:\"30\"";
        assert_eq!(build_filter_string(&filters), expected_filter_string);
    }

    #[test]
    fn test_build_search_subject() {
        // Mimics lib/search.test.ts
        let server_url = "https://test.com";
        let query = "q=test";
        let opts = SearchOpts {
            include: Some(true),
            limit: Some(30),
            filters: Some({
                let mut filters = HashMap::new();
                filters.insert("age".to_string(), "10".to_string());
                filters
            }),
            parents: Some(vec!["https://test.com/parent".to_string()]),
        };
        let expected_search_url = "https://test.com/search?q=test&include=true&limit=30&filters=age%3A%2210%22&parents=https%3A%2F%2Ftest.com%2Fparent";
        assert_eq!(
            build_search_subject(server_url, query, opts),
            expected_search_url
        );
    }
}
