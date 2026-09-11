//! Matching a concrete request path against OpenAPI path templates.

use std::borrow::Cow;

use indexmap::IndexMap;
use percent_encoding::percent_decode_str;

/// A template that matched, together with the path variables it bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    /// The OpenAPI path template that matched, e.g. `/pets/{petId}`.
    pub template: String,
    /// Path variables bound by the match, percent-decoded.
    pub params: IndexMap<String, String>,
}

fn decode(segment: &str) -> String {
    match percent_decode_str(segment).decode_utf8() {
        Ok(Cow::Borrowed(value)) => value.to_string(),
        Ok(Cow::Owned(value)) => value,
        Err(_) => segment.to_string(),
    }
}

fn match_template(template: &str, actual: &str) -> Option<IndexMap<String, String>> {
    let template_segments: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();
    let actual_segments: Vec<&str> = actual.split('/').filter(|s| !s.is_empty()).collect();
    if template_segments.len() != actual_segments.len() {
        return None;
    }

    let mut params = IndexMap::new();
    for (index, template_segment) in template_segments.iter().enumerate() {
        let actual_segment = actual_segments.get(index).copied().unwrap_or("");
        if let Some(name) = template_segment
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
        {
            params.insert(name.to_string(), decode(actual_segment));
        } else if *template_segment != actual_segment {
            return None;
        }
    }
    Some(params)
}

/// Returns the first template in `templates` that matches `actual`.
pub fn find_route<S: AsRef<str>>(templates: &[S], actual: &str) -> Option<RouteMatch> {
    for template in templates {
        let template = template.as_ref();
        if let Some(params) = match_template(template, actual) {
            return Some(RouteMatch {
                template: template.to_string(),
                params,
            });
        }
    }
    None
}
