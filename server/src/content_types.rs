//! Content-type / Accept header negotiation, MIME types

use actix_web::http::header::HeaderMap;

#[derive(Debug, PartialEq)]
pub enum ContentType {
    /// Plain JSON, using shortnames as keys instead of URLs
    /// https://docs.atomicdata.dev/interoperability/json.html#atomic-data-as-plain-json
    Json,
    /// JSON-AD, default Atomic Data serialization
    /// https://docs.atomicdata.dev/core/json-ad.html
    JsonAd,
    /// JSON-LD, RDF compatible JSON with @context mapping
    /// https://docs.atomicdata.dev/interoperability/json.html#from-json-to-json-ad
    JsonLd,
    Html,
    /// RDF Turtle format
    /// https://www.w3.org/TR/turtle/
    Turtle,
    /// RDF N-Triples format
    /// https://www.w3.org/TR/n-triples/
    NTriples,
}

const MIME_HTML: &str = "text/html";
const MIME_XML: &str = "application/xml";
const MIME_JSON: &str = "application/json";
const MIME_JSONLD: &str = "application/ld+json";
const MIME_JSONAD: &str = "application/ad+json";
const MIME_TURTLE: &str = "text/turtle";
const MIME_NT: &str = "application/n-triples";

impl ContentType {
    pub fn to_mime(&self) -> &str {
        match self {
            ContentType::Json => MIME_JSON,
            ContentType::JsonAd => MIME_JSONAD,
            ContentType::JsonLd => MIME_JSONLD,
            ContentType::Html => MIME_HTML,
            ContentType::Turtle => MIME_TURTLE,
            ContentType::NTriples => MIME_NT,
        }
    }
}

/// Returns the preffered content type.
/// Defaults to HTML if none is found.
pub fn get_accept(map: &HeaderMap) -> ContentType {
    let accept_header = match map.get("Accept") {
        Some(header) => header.to_str().unwrap_or(""),
        None => return ContentType::Html,
    };
    parse_accept_header(accept_header)
}

/// Parses an HTTP Accept header
/// Does not fully adhere to the RFC spec: https://tools.ietf.org/html/rfc7231
/// Does not take into consideration the q value, simply reads the first thing before the comma
/// Defaults to HTML
pub fn parse_accept_header(header: &str) -> ContentType {
    for mimepart in header.split(',') {
        if mimepart.contains(MIME_JSONAD) {
            return ContentType::JsonAd;
        }
        if mimepart.contains(MIME_HTML) {
            return ContentType::Html;
        }
        if mimepart.contains(MIME_XML) {
            return ContentType::Html;
        }
        if mimepart.contains(MIME_JSON) {
            return ContentType::Json;
        }
        if mimepart.contains(MIME_JSONLD) {
            return ContentType::JsonLd;
        }
        if mimepart.contains(MIME_TURTLE) {
            return ContentType::Turtle;
        }
        if mimepart.contains(MIME_NT) {
            return ContentType::NTriples;
        }
        if mimepart.contains(MIME_NT) {
            return ContentType::NT
        }
    }
    tracing::info!("Unknown Accept header, defaut to HTML: {}", header);
    ContentType::Html
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_types() {
        assert!(parse_accept_header("text/html,application/xml") == ContentType::Html);
        assert!(parse_accept_header("application/ad+json") == ContentType::JsonAd);
        assert!(parse_accept_header("application/ld+json") == ContentType::JsonLd);
    }

    #[test]
    fn parse_types_with_blank_chars() {
        assert!(parse_accept_header("application/ad+json ; ") == ContentType::JsonAd);
        assert!(parse_accept_header(" application/ad+json ; ") == ContentType::JsonAd);
    }
}
