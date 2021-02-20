//! Content-type / Accept header negotiation, MIME types

use actix_web::{http::HeaderMap};

#[derive(PartialEq)]
pub enum ContentType {
    JSON,
    JSONAD,
    JSONLD,
    HTML,
    TURTLE,
    NT,
    AD3,
}

const MIME_AD3: &str = "application/ad3-ndjson";
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
            ContentType::JSON => MIME_JSON,
            ContentType::JSONAD => MIME_JSONAD,
            ContentType::JSONLD => MIME_JSONLD,
            ContentType::HTML => MIME_HTML,
            ContentType::TURTLE => MIME_TURTLE,
            ContentType::AD3 => MIME_AD3,
            ContentType::NT => MIME_NT
        }
    }
}

/// Returns the preffered content type.
/// Defaults to HTML if none is found.
pub fn get_accept(map: &HeaderMap) -> ContentType {
    let accept_header = match map.get("Accept") {
        Some(header) => {
            header.to_str().unwrap_or("")
        }
        None => {
            return ContentType::HTML
        }
    };
    parse_accept_header(accept_header)
}

/// Parses an HTTP Accept header
/// Does not fully adhere to the RFC spec: https://tools.ietf.org/html/rfc7231
/// Does not take into consideration the q value, simply reads the first thing before the comma
/// Defaults to HTML
pub fn parse_accept_header(header: &str) -> ContentType {
    for mimepart in header.split(',') {
        if mimepart.contains(MIME_AD3) {
            return ContentType::AD3
        }
        if mimepart.contains(MIME_HTML) {
            return ContentType::HTML
        }
        if mimepart.contains(MIME_XML) {
            return ContentType::HTML
        }
        if mimepart.contains(MIME_JSON) {
            return ContentType::JSON
        }
        if mimepart.contains(MIME_JSONLD) {
            return ContentType::JSONLD
        }
        if mimepart.contains(MIME_JSONAD) {
            return ContentType::JSONAD
        }
        if mimepart.contains(MIME_TURTLE) {
            return ContentType::TURTLE
        }
    }
    log::info!("Unknown Accept header, defaut to HTML: {}", header);
    ContentType::HTML
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_types() {
        assert!(parse_accept_header("text/html,application/xml") == ContentType::HTML);
        assert!(parse_accept_header("application/ad3-ndjson") == ContentType::AD3);
        assert!(parse_accept_header("application/ad+json") == ContentType::JSONAD);
        assert!(parse_accept_header("application/ld+json") == ContentType::JSONLD);
    }

    #[test]
    fn parse_types_with_blank_chars() {
        assert!(parse_accept_header("application/ad3-ndjson ; ") == ContentType::AD3);
        assert!(parse_accept_header(" application/ad3-ndjson ; ") == ContentType::AD3);
    }
}
