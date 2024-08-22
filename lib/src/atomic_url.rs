use serde::{Deserialize, Serialize, Serializer};
use url::Url;

use crate::{errors::AtomicResult, utils::random_string};

pub enum Routes {
    Agents,
    AllVersions,
    Collections,
    Commits,
    CommitsUnsigned,
    Endpoints,
    Import,
    Tpf,
    Version,
    Setup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Wrapper for URLs / subjects.
/// Has a bunch of methods for finding or creating commonly used paths.
pub struct AtomicUrl {
    url: Url,
}

impl AtomicUrl {
    pub fn new(url: Url) -> Self {
        Self { url }
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Returns the route to some common Endpoint
    pub fn set_route(&self, route: Routes) -> Self {
        let path = match route {
            Routes::AllVersions => "/all-versions".to_string(),
            Routes::Agents => "/collections/agents".to_string(),
            Routes::Collections => "/collections".to_string(),
            Routes::Commits => "/collections/commits".to_string(),
            Routes::CommitsUnsigned => "/commits-unsigned".to_string(),
            Routes::Endpoints => "/endpoints".to_string(),
            Routes::Import => "/import".to_string(),
            Routes::Tpf => "/tpf".to_string(),
            Routes::Version => "/version".to_string(),
            Routes::Setup => "/setup".to_string(),
        };
        let mut new = self.url.clone();
        new.set_path(&path);
        Self::new(new)
    }

    /// Returns a new URL generated from the provided path_shortname and a random string.
    /// ```
    /// let url = atomic_lib::AtomicUrl::try_from("https://example.com").unwrap();
    /// let generated = url.generate_random("my-type");
    /// assert!(generated.to_string().starts_with("https://example.com/my-type/"));
    /// ```
    pub fn generate_random(&self, path_shortname: &str) -> Self {
        let mut url = self.url.clone();
        let path = format!("{path_shortname}/{}", random_string(10));
        url.set_path(&path);
        Self { url }
    }

    /// Adds a sub-path to a URL.
    /// Adds a slash to the existing URL, followed by the passed path.
    ///
    /// ```
    /// use atomic_lib::AtomicUrl;
    /// let start = "http://localhost";
    /// let mut url = AtomicUrl::try_from(start).unwrap();
    /// assert_eq!(url.to_string(), "http://localhost/");
    /// url.append("/");
    /// assert_eq!(url.to_string(), "http://localhost/");
    /// url.append("someUrl/123");
    /// assert_eq!(url.to_string(), "http://localhost/someUrl/123");
    /// url.append("/345");
    /// assert_eq!(url.to_string(), "http://localhost/someUrl/123/345");
    /// ```
    pub fn append(&mut self, path: &str) -> &Self {
        let mut new_path = self.url.path().to_string();
        match (new_path.ends_with('/'), path.starts_with('/')) {
            (true, true) => {
                new_path.pop();
            }
            (false, false) => new_path.push('/'),
            _other => {}
        };

        // Remove first slash if it exists
        if new_path.starts_with('/') {
            new_path.remove(0);
        }

        new_path.push_str(path);

        self.url.set_path(&new_path);
        self
    }

    /// Sets the subdomain of the URL.
    /// Removes an existing subdomain if the subdomain is None
    pub fn set_subdomain(&mut self, subdomain: Option<&str>) -> AtomicResult<&Self> {
        let mut host = self.url.host_str().unwrap().to_string();
        if let Some(subdomain) = subdomain {
            host = format!("{}.{}", subdomain, host);
        }
        self.url.set_host(Some(host.as_str()))?;
        Ok(self)
    }

    /// Removes existing path, sets the new one. Escapes special characters
    pub fn set_path(mut self, path: &str) -> Self {
        self.url.set_path(path);
        self
    }

    pub fn subdomain(&self) -> Option<String> {
        let url = self.url.clone();
        let host = url.host_str().unwrap();
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() > 2 {
            Some(parts[0].to_string())
        } else {
            None
        }
    }

    /// Returns the inner {url::Url} struct that has a bunch of regular URL methods
    /// Useful if you need the host or something.
    pub fn url(&self) -> Url {
        self.url.clone()
    }
}

impl TryFrom<&str> for AtomicUrl {
    type Error = url::ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = Url::parse(value)?;
        Ok(Self { url })
    }
}

impl Serialize for AtomicUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.url.as_str())
    }
}

impl<'de> Deserialize<'de> for AtomicUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let url = Url::parse(&s).map_err(serde::de::Error::custom)?;
        Ok(Self { url })
    }
}

impl std::fmt::Display for AtomicUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_url() {
        let _should_fail = AtomicUrl::try_from("nonsense").unwrap_err();
        let _should_succeed = AtomicUrl::try_from("http://localhost/someUrl").unwrap();
    }

    #[test]
    fn subdomain() {
        let sub = "http://test.example.com";
        assert_eq!(
            AtomicUrl::try_from(sub).unwrap().subdomain(),
            Some("test".to_string())
        );
        let mut no_sub = AtomicUrl::try_from("http://example.com").unwrap();
        assert_eq!(no_sub.subdomain(), None);

        let to_sub = no_sub.set_subdomain(Some("mysub")).unwrap();
        assert_eq!(to_sub.subdomain(), Some("mysub".to_string()));
    }
}
