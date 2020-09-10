#[derive(PartialEq)]
pub enum ContentType {
    JSON,
    JSONLD,
    HTML,
    AD3,
}

/// Returns the preffered content type.
pub fn get_accept(req: actix_web::HttpRequest) -> ContentType {
    let accept_header = req.headers().get("Accept").unwrap().to_str().unwrap();
    parse_accept_header(accept_header)
}

/// Parses an HTTP Accept header
/// Does not fully adhere to the RFC spec: https://tools.ietf.org/html/rfc7231
/// Does not take into consideration the q value, simply reads the first thing before the comma
/// Defaults to HTML
fn parse_accept_header(header: &str) -> ContentType {
    for mimepart in header.split(',') {
        if mimepart.contains("application/ad3-ndjson") {
            return ContentType::AD3
        }
        if mimepart.contains("text/html") {
            return ContentType::HTML
        }
        if mimepart.contains("application/xml") {
            return ContentType::HTML
        }
        if mimepart.contains("application/json") {
            return ContentType::JSON
        }
        if mimepart.contains("application/ld+json") {
            return ContentType::JSONLD
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
    }

    #[test]
    fn parse_types_with_blank_chars() {
        assert!(parse_accept_header("application/ad3-ndjson ; ") == ContentType::AD3);
        assert!(parse_accept_header(" application/ad3-ndjson ; ") == ContentType::AD3);
    }
}
