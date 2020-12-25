//! Helper functions for dealing with URLs

use url::Url;
use crate::errors::AtomicResult;

pub fn base_url(url: &str) -> AtomicResult<String> {
    let mut parsed: Url = Url::parse(url)?;

    match parsed.path_segments_mut() {
        Ok(mut path) => {
            path.clear();
        }
        Err(_) => {
            return Err(format!("Url {} is not valid.", url).into())
        }
    }

    parsed.set_query(None);

    Ok(parsed.to_string())
}
