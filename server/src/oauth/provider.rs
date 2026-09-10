//! Trusted provider metadata for authorization transports.
//!
//! This is deliberately loaded from a vendored data document.  Request data
//! and environment variables cannot choose an OAuth endpoint: doing so could
//! disclose client credentials or authorization codes.
use crate::errors::AtomicServerResult as Result;
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
struct Record {
    id: String,
    origin: String,
    token_path: String,
    authorize_path: String,
}

pub(crate) struct Provider {
    pub id: String,
    pub origin: Url,
    pub token: Url,
    pub authorize: Url,
}

pub(crate) fn load(id: &str) -> Result<Provider> {
    let records: Vec<Record> = serde_json::from_str(include_str!("providers.json"))
        .map_err(|_| "Invalid vendored OAuth provider metadata")?;
    let record = records
        .into_iter()
        .find(|r| r.id == id)
        .ok_or("OAuth provider is not registered")?;
    let origin = Url::parse(&record.origin).map_err(|_| "Invalid OAuth provider origin")?;
    if origin.scheme() != "https"
        || origin.username() != ""
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err("OAuth provider origin must be a credential-free HTTPS origin".into());
    }
    Ok(Provider {
        id: record.id,
        token: same_origin_path(&origin, &record.token_path)?,
        authorize: same_origin_path(&origin, &record.authorize_path)?,
        origin,
    })
}

fn same_origin_path(origin: &Url, path: &str) -> Result<Url> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains('?') || path.contains('#')
    {
        return Err("Invalid OAuth provider path".into());
    }
    let endpoint = origin
        .join(path)
        .map_err(|_| "Invalid OAuth provider path")?;
    if endpoint.origin() != origin.origin() {
        return Err("OAuth provider endpoint must remain same-origin".into());
    }
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_rejects_hostile_endpoint_paths() {
        for path in [
            "https://evil.example/token",
            "//evil.example/token",
            "token?x=1",
            "/token#fragment",
        ] {
            let origin = Url::parse("https://provider.example").unwrap();
            assert!(same_origin_path(&origin, path).is_err(), "path: {path}");
        }
    }

    #[test]
    fn metadata_accepts_pure_origin_paths_without_query() {
        let origin = Url::parse("https://provider.example").unwrap();
        let endpoint = same_origin_path(&origin, "/v1/oauth/token").unwrap();
        assert_eq!(endpoint.origin(), origin.origin());
        assert!(endpoint.query().is_none());
        assert!(endpoint.fragment().is_none());
    }
}
