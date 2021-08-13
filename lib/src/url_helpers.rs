//! Helper functions for dealing with URLs

use crate::errors::AtomicResult;
use url::Url;

pub fn base_url(url: &str) -> AtomicResult<String> {
    let mut parsed: Url = Url::parse(url)?;

    match parsed.path_segments_mut() {
        Ok(mut path) => {
            path.clear();
        }
        Err(_) => return Err(format!("Url {} is not valid.", url).into()),
    }

    parsed.set_query(None);

    Ok(parsed.to_string())
}

/// Throws an error if the URL is not a valid URL
pub fn check_valid_url(url: &str) -> AtomicResult<()> {
    if !url.starts_with("http") {
        return Err(format!("Url does not start with http: {}", url).into());
    }
    Ok(())
}
