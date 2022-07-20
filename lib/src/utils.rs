//! Helper functions for dealing with URLs

use crate::errors::AtomicResult;
use url::Url;

/// Removes the path and query from a String, returns the base server URL
pub fn server_url(url: &str) -> AtomicResult<String> {
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
    if !url.starts_with("http") && !url.starts_with("local:") {
        return Err(format!("Url does not start with http: {}", url).into());
    }
    Ok(())
}

/// Returns the current timestamp in milliseconds since UNIX epoch
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("You're a time traveler")
        .as_millis() as i64
}

/// Generates a relatively short random string of n length
pub fn random_string(n: usize) -> String {
    use rand::Rng;
    let random_string: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(n)
        .map(char::from)
        .collect();
    random_string.to_lowercase()
}
