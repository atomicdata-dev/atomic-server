//! The declaration is evaluated with no host capabilities before execution.
//! Version one makes public reads independent of credential storage.
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    #[serde(default)]
    pub secrets: Vec<Secret>,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<super::actions::Action>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    pub name: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub method: String,
    /// Exact endpoint; query parameters may vary. No wildcard hosts or paths.
    pub url: String,
    pub effect: String,
}

impl Manifest {
    pub fn parse(raw: serde_json::Value) -> Result<Option<Self>, String> {
        // Legacy drafts have no version and receive only legacy GET/HEAD access.
        if raw.get("schemaVersion").is_none() {
            return Ok(None);
        }
        if raw
            .get("secrets")
            .and_then(|v| v.as_array())
            .is_some_and(|secrets| {
                secrets.iter().any(|secret| {
                    secret
                        .get("description")
                        .is_some_and(|description| !description.is_string())
                })
            })
        {
            return Err("secret description must be text".into());
        }
        let manifest: Self = serde_json::from_value(raw).map_err(|e| e.to_string())?;
        if manifest.schema_version != 1 {
            return Err("unsupported manifest schemaVersion".into());
        }
        let mut names = std::collections::HashSet::new();
        for secret in &manifest.secrets {
            if secret.name.is_empty() || !names.insert(&secret.name) {
                return Err("secret names must be nonempty and unique".into());
            }
            let parsed = endpoint(&secret.origin)?;
            if parsed.origin().ascii_serialization() != secret.origin {
                return Err("secret origin must be an exact HTTP origin".into());
            }
        }
        names.clear();
        for operation in &manifest.operations {
            if operation.id.is_empty() || !names.insert(&operation.id) {
                return Err("operation IDs must be nonempty and unique".into());
            }
            endpoint(&operation.url)?;
            if !matches!(
                operation.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
            ) {
                return Err("operation has an unsupported HTTP method".into());
            }
            if !matches!(operation.effect.as_str(), "read" | "write") {
                return Err("operation effect must be read or write".into());
            }
        }
        super::actions::validate_actions(&manifest)?;
        Ok(Some(manifest))
    }

    pub fn allows_read(&self, id: Option<&str>, method: &str, url: &url::Url) -> bool {
        self.allows_effect(id, method, url, "read")
    }

    pub fn allows_effect(
        &self,
        id: Option<&str>,
        method: &str,
        url: &url::Url,
        effect: &str,
    ) -> bool {
        self.operations.iter().any(|operation| {
            let Ok(endpoint) = endpoint(&operation.url) else {
                return false;
            };
            id == Some(operation.id.as_str())
                && operation.method == method
                && operation.effect == effect
                && endpoint.origin() == url.origin()
                && matches_path(endpoint.path(), url.path())
        })
    }
}

/// Typed parameters admit only positive decimal IDs or hyphenated UUIDs.
/// No globbing, repository substitution, encoded slashes or traversal.
fn matches_path(pattern: &str, actual: &str) -> bool {
    let p: Vec<_> = pattern.split('/').collect();
    let a: Vec<_> = actual.split('/').collect();
    p.len() == a.len()
        && p.iter().zip(a).all(|(p, a)| {
            if *p == "%7Bnumber%7D" || *p == "{number}" {
                !a.is_empty() && !a.starts_with('0') && a.bytes().all(|c| c.is_ascii_digit())
            } else if *p == "%7Buuid%7D" || *p == "{uuid}" {
                a.len() == 36
                    && a.bytes().enumerate().all(|(i, c)| {
                        if matches!(i, 8 | 13 | 18 | 23) {
                            c == b'-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    })
            } else {
                *p == a
            }
        })
}

fn endpoint(value: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(value).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(
            "operation URLs must be HTTP endpoints without credentials, query or fragment".into(),
        );
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_manifest_conformance() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/plugin-manifests.json")).unwrap();
        for case in cases.as_array().unwrap() {
            assert_eq!(
                Manifest::parse(case["manifest"].clone()).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
    #[test]
    fn public_read_is_declared_without_a_secret_and_write_cannot_run_in_preview() {
        let manifest = Manifest::parse(serde_json::json!({"schemaVersion":1,"operations":[
            {"id":"list","method":"POST","url":"https://api.test/query","effect":"read"},
            {"id":"delete","method":"DELETE","url":"https://api.test/records","effect":"write"}
        ]}))
        .unwrap()
        .unwrap();
        assert!(manifest.allows_read(
            Some("list"),
            "POST",
            &url::Url::parse("https://api.test/query?page=2").unwrap()
        ));
        assert!(!manifest.allows_read(
            Some("list"),
            "POST",
            &url::Url::parse("https://api.test/admin").unwrap()
        ));
        assert!(!manifest.allows_read(
            Some("delete"),
            "DELETE",
            &url::Url::parse("https://api.test/records").unwrap()
        ));
    }
}

#[cfg(test)]
mod path_tests {
    use super::matches_path;
    #[test]
    fn uuid_paths_are_single_canonical_segments() {
        let pattern = "/v1/pages/%7Buuid%7D";
        assert!(matches_path(
            pattern,
            "/v1/pages/3d3236d2-7bda-80a2-a77a-000b0adec99f"
        ));
        for path in [
            "/v1/pages/3d3236d27bda80a2a77a000b0adec99f",
            "/v1/pages/3d3236d2-7bda-80a2-a77a-000b0adec99g",
            "/v1/pages/3d3236d2-7bda-80a2-a77a-000b0adec99f/comments",
            "/v1/pages/%2e%2e",
            "/v1/pages/..",
            "/v1/users/3d3236d2-7bda-80a2-a77a-000b0adec99f",
        ] {
            assert!(!matches_path(pattern, path), "{path}");
        }
    }
    #[test]
    fn numeric_paths_cannot_escape_the_declared_repository() {
        let pattern = "/repos/owner/repo/issues/%7Bnumber%7D";
        assert!(matches_path(pattern, "/repos/owner/repo/issues/123"));
        for path in [
            "/repos/owner/other/issues/123",
            "/repos/owner/repo/issues/0",
            "/repos/owner/repo/issues/-1",
            "/repos/owner/repo/issues/1/comments",
            "/repos/owner/repo/issues/%31",
            "/repos/owner/repo/issues/..",
        ] {
            assert!(!matches_path(pattern, path));
        }
    }
}
