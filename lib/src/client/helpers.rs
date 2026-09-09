//! Functions for interacting with an Atomic Server
use crate::{
    agents::Agent,
    commit::sign_message,
    errors::AtomicResult,
    parse::{parse_json_ad_string, ParseOpts},
    storelike::ResourceResponse,
    Resource, Storelike, Subject,
};

// ---------------------------------------------------------------------------
// SSRF guard for outbound fetches of caller-supplied URLs.
//
// Only `fetch_body_untrusted` (used by the `/bookmark` and `/import` endpoints,
// which pass a `url` parameter straight through from an unauthenticated
// caller) goes through this guard. Plain `fetch_body`/`fetch_resource`/
// `post_commit` fetch or post to URLs the system itself determined (a
// resource's own subject, a peer/federation target, its own configured server)
// — including, legitimately, `localhost` for same-host client/server round
// trips, which this architecture relies on. Guarding those too breaks that.
//
// Reject loopback, RFC1918/CGNAT, and link-local (incl. the 169.254.169.254
// cloud-metadata endpoint) targets, on the initial request AND on every
// redirect hop, for both domain names and IP literals.
//
// Native reqwest/hyper-util bypasses the DNS resolver entirely for IP-literal
// hosts (connects directly), so a resolver hook alone isn't enough — an
// explicit pre-flight check on every URL (initial + each redirect target)
// catches that case, while `PublicOnlyResolver` additionally filters resolved
// addresses for domain names (closing DNS-rebinding). WASM builds run under
// the browser's own fetch sandboxing and get neither hook.
//
// Escape hatch: `ATOMIC_ALLOW_PRIVATE_FETCH=1` disables the guard for
// deployments that intentionally want `/bookmark`/`/import` to reach internal
// hosts. Secure by default.
#[cfg(not(target_arch = "wasm32"))]
mod ssrf_guard {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

    pub fn allow_private_fetch() -> bool {
        static ALLOW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ALLOW.get_or_init(|| {
            matches!(
                std::env::var("ATOMIC_ALLOW_PRIVATE_FETCH").as_deref(),
                Ok("1") | Ok("true") | Ok("TRUE")
            )
        })
    }

    fn ipv4_is_blocked(v4: Ipv4Addr) -> bool {
        let o = v4.octets();
        v4.is_loopback()        // 127.0.0.0/8
            || v4.is_private()    // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local() // 169.254.0.0/16 — cloud metadata
            || v4.is_broadcast()  // 255.255.255.255
            || v4.is_unspecified()// 0.0.0.0
            || v4.is_documentation()
            || (o[0] == 100 && (64..128).contains(&o[1])) // 100.64.0.0/10 CGNAT
    }

    fn ipv6_is_blocked(v6: Ipv6Addr) -> bool {
        v6.is_loopback()
            || v6.is_unspecified()
            || v6.is_unique_local() // fc00::/7
            || v6.is_unicast_link_local() // fe80::/10
            || v6
                .to_ipv4_mapped()
                .map(ipv4_is_blocked)
                .unwrap_or(false)
    }

    pub fn ip_is_blocked(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => ipv4_is_blocked(v4),
            IpAddr::V6(v6) => ipv6_is_blocked(v6),
        }
    }

    /// Validates scheme + (if the host is an IP literal) that it's public.
    /// Domain-name hosts are validated later, at actual connect time, by
    /// `PublicOnlyResolver` — this only needs to catch what the resolver
    /// never sees. Pure / parameterized on `allow_private` so it's testable
    /// without touching process-global env state.
    pub fn preflight(url: &url::Url, allow_private: bool) -> Result<(), String> {
        match url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(format!(
                "Refusing to fetch '{url}': unsupported scheme '{other}' (only http/https allowed)"
            ))
            }
        }

        if allow_private {
            return Ok(());
        }

        // Use the parsed `Host` enum, not `host_str()` — for an IPv6 literal
        // `host_str()` returns the bracketed form (`[::1]`), which
        // `IpAddr::from_str` rejects, silently letting it through a naive
        // string-parse check.
        let blocked_ip = match url.host() {
            Some(url::Host::Ipv4(v4)) => ip_is_blocked(IpAddr::V4(v4)).then_some(IpAddr::V4(v4)),
            Some(url::Host::Ipv6(v6)) => ip_is_blocked(IpAddr::V6(v6)).then_some(IpAddr::V6(v6)),
            _ => None,
        };
        if let Some(ip) = blocked_ip {
            return Err(format!(
                "Refusing to fetch '{url}': target address {ip} is not a public address"
            ));
        }

        Ok(())
    }

    pub fn check_url(url: &url::Url) -> Result<(), String> {
        preflight(url, allow_private_fetch())
    }

    type BoxErr = Box<dyn std::error::Error + Send + Sync>;

    /// Resolves a domain name and filters out any non-public addresses, so a
    /// name that resolves (now, or on a later request — DNS rebinding) to an
    /// internal address can't be connected to. Uses `ToSocketAddrs` (the OS
    /// resolver) since it's the same resolution DNS-rebinding attacks target.
    pub fn resolve_public(host: &str, allow_private: bool) -> std::io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = (host, 0).to_socket_addrs()?.collect();

        let public: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|addr| allow_private || !ip_is_blocked(addr.ip()))
            .collect();

        if public.is_empty() {
            return Err(std::io::Error::other(format!(
                "'{host}' resolved only to non-public addresses; refusing to connect"
            )));
        }

        Ok(public)
    }

    #[derive(Clone, Copy, Default)]
    pub struct PublicOnlyResolver;

    impl reqwest::dns::Resolve for PublicOnlyResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let host = name.as_str().to_string();
            Box::pin(async move {
                let allow_private = allow_private_fetch();
                let addrs =
                    tokio::task::spawn_blocking(move || resolve_public(&host, allow_private))
                        .await
                        .map_err(|e| std::io::Error::other(e.to_string()))?
                        .map_err(|e| Box::new(e) as BoxErr)?;

                Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
            })
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(10))
}

#[cfg(target_arch = "wasm32")]
fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

/// Same as `http_client_builder`, but with the SSRF guard wired in — for
/// fetching URLs that came from an unauthenticated, external caller (see
/// `fetch_body_untrusted`).
#[cfg(not(target_arch = "wasm32"))]
fn untrusted_http_client_builder() -> reqwest::ClientBuilder {
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        match ssrf_guard::check_url(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    });

    http_client_builder()
        .redirect(redirect_policy)
        .dns_resolver(std::sync::Arc::new(ssrf_guard::PublicOnlyResolver))
}

/// Fetches a resource, makes sure its subject matches.
/// Checks the datatypes for the Values.
/// Ignores all atoms where the subject is different.
/// WARNING: Calls store methods, and is called by store methods, might get stuck in a loop!
#[tracing::instrument(skip_all)]
pub async fn fetch_resource(
    subject: &str,
    store: &impl Storelike,
    client_agent: Option<&Agent>,
) -> AtomicResult<ResourceResponse> {
    let subject_obj = Subject::from_raw(subject, store.get_base_domain().as_deref());
    let url = if subject_obj.is_did() {
        // Route DID requests through the server's normal resource endpoint.
        // The server's catch-all GET handler parses the DID from the path
        // and resolves it locally or via DHT.
        let server = store.get_server_url();
        format!("{}/{}", server.trim_end_matches('/'), subject)
    } else {
        subject.to_string()
    };

    // DID agents are not understood by old/external servers (they can't resolve
    // `did:ad:agent:` to fetch the public key). Only sign requests to our own server.
    let effective_agent = match client_agent {
        Some(agent) if agent.subject.is_did() => {
            let server = store.get_server_url();
            if url.starts_with(server.trim_end_matches('/')) {
                client_agent
            } else {
                None
            }
        }
        _ => client_agent,
    };

    let body = fetch_body(&url, crate::parse::JSON_AD_MIME, effective_agent).await?;
    let resources = Box::pin(parse_json_ad_string(&body, store, &ParseOpts::default()))
        .await
        .map_err(|e| format!("Error parsing body of {}. {}", subject, e))?;

    if resources.len() == 1 {
        Ok(ResourceResponse::Resource(resources[0].clone()))
    } else {
        let mut main_resource: Option<Resource> = None;
        let mut referenced: Vec<Resource> = Vec::new();

        let pure_subject = if subject_obj.is_did() {
            subject_obj.pure_id()
        } else {
            subject.to_string()
        };

        for r in resources {
            if r.get_subject_enum().pure_id() == pure_subject {
                main_resource = Some(r);
            } else {
                referenced.push(r);
            }
        }

        let Some(main_resource) = main_resource else {
            return Err(format!(
                "Requested subject not found in returned resources: {}",
                subject
            )
            .into());
        };

        Ok(ResourceResponse::ResourceWithReferenced(
            main_resource,
            referenced,
        ))
    }
}

/// Returns the various x-atomic authentication headers, includign agent signature
pub fn get_authentication_headers(url: &str, agent: &Agent) -> AtomicResult<Vec<(String, String)>> {
    let mut headers = Vec::new();
    let now = crate::utils::now().to_string();
    let message = format!("{} {}", url, now);
    let signature = sign_message(
        &message,
        agent
            .private_key
            .as_ref()
            .ok_or("No private key in agent")?,
        &agent.public_key,
    )?;
    headers.push(("x-atomic-public-key".into(), agent.public_key.to_string()));
    headers.push(("x-atomic-signature".into(), signature));
    headers.push(("x-atomic-timestamp".into(), now));
    headers.push(("x-atomic-agent".into(), agent.subject.to_string()));
    Ok(headers)
}

/// Fetches a URL, returns its body.
/// Uses the store's Agent agent (if set) to sign the request.
/// For a URL the system itself determined (a resource's own subject, a
/// federation peer, its own server) — NOT for a caller-supplied URL. See
/// `fetch_body_untrusted` for that.
#[tracing::instrument(skip_all)]
pub async fn fetch_body(
    url: &str,
    content_type: &str,
    client_agent: Option<&Agent>,
) -> AtomicResult<String> {
    if !url.starts_with("http") {
        return Err(format!("Could not fetch url '{}', must start with http.", url).into());
    }

    let client = http_client_builder()
        .build()
        .map_err(|e| format!("Could not build HTTP client: {}", e))?;

    fetch_body_with_client(&client, url, content_type, client_agent, None).await
}

/// Largest body `fetch_body_untrusted` will read: a caller-supplied URL
/// must not be able to make the server buffer an arbitrarily large response.
pub const UNTRUSTED_BODY_MAX_BYTES: usize = 10 * 1024 * 1024;

/// Fetches a URL that was supplied by an unauthenticated, external caller
/// (currently: the `/bookmark` and `/import` endpoints' `url` parameter).
/// Guards against SSRF — see the `ssrf_guard` module docs above — and refuses
/// bodies over [`UNTRUSTED_BODY_MAX_BYTES`].
#[tracing::instrument(skip_all)]
pub async fn fetch_body_untrusted(url: &str, content_type: &str) -> AtomicResult<String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let client = untrusted_client_for(url)?;
        fetch_body_with_client(
            &client,
            url,
            content_type,
            None,
            Some(UNTRUSTED_BODY_MAX_BYTES),
        )
        .await
    }

    #[cfg(target_arch = "wasm32")]
    {
        // Runs under the browser's own fetch sandboxing; no separate guard available.
        fetch_body(url, content_type, None).await
    }
}

/// Downloads raw bytes from a URL that was supplied by a caller (a plugin's
/// `downloadURL`, say). Same SSRF guard as `fetch_body_untrusted`; the body is
/// read as a stream and the fetch fails as soon as it passes `max_bytes`, so a
/// hostile or mis-set `Content-Length` cannot get around the cap either.
#[tracing::instrument(skip_all)]
pub async fn fetch_bytes_untrusted(url: &str, max_bytes: usize) -> AtomicResult<Vec<u8>> {
    #[cfg(not(target_arch = "wasm32"))]
    let client = untrusted_client_for(url)?;
    #[cfg(target_arch = "wasm32")]
    let client = http_client_builder()
        .build()
        .map_err(|e| format!("Could not build HTTP client: {}", e))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Error when fetching {}: {}", url, e))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("Could not fetch url '{}'. Status: {}", url, status).into());
    }
    let body = read_body_bounded(resp, url, max_bytes).await?;
    crate::metrics::external_fetch();
    Ok(body)
}

/// Runs the pre-flight part of the SSRF guard on `url` and returns a client
/// whose resolver and redirect policy enforce the rest.
#[cfg(not(target_arch = "wasm32"))]
fn untrusted_client_for(url: &str) -> AtomicResult<reqwest::Client> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL '{url}': {e}"))?;
    if let Err(e) = ssrf_guard::check_url(&parsed) {
        return Err(e.into());
    }

    untrusted_http_client_builder()
        .build()
        .map_err(|e| format!("Could not build HTTP client: {}", e).into())
}

/// Reads a response body into memory, refusing anything over `max_bytes`:
/// first by the declared `Content-Length`, then — since that header can be
/// absent or wrong — by counting the bytes as they stream in.
async fn read_body_bounded(
    resp: reqwest::Response,
    url: &str,
    max_bytes: usize,
) -> AtomicResult<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "Response from '{}' is too large: {} bytes declared, limit is {} bytes",
                url, len, max_bytes
            )
            .into());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut resp = resp;
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("Error reading response body of {}: {}", url, e))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(format!(
                    "Response from '{}' is too large: exceeds the limit of {} bytes",
                    url, max_bytes
                )
                .into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    #[cfg(target_arch = "wasm32")]
    {
        // The browser's fetch buffers for us; there is no `chunk()` here.
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("Error reading response body of {}: {}", url, e))?;
        if body.len() > max_bytes {
            return Err(format!(
                "Response from '{}' is too large: exceeds the limit of {} bytes",
                url, max_bytes
            )
            .into());
        }
        Ok(body.to_vec())
    }
}

/// `max_bytes`: cap on the body size, for URLs that came from a caller.
/// `None` reads the whole body, for URLs the system itself determined.
async fn fetch_body_with_client(
    client: &reqwest::Client,
    url: &str,
    content_type: &str,
    client_agent: Option<&Agent>,
    max_bytes: Option<usize>,
) -> AtomicResult<String> {
    let mut req = client.get(url).header("Accept", content_type);
    if let Some(agent) = client_agent {
        if should_sign_request(url, agent) {
            let headers = get_authentication_headers(url, agent)?;
            for (key, value) in headers {
                req = req.header(key, value);
            }
        } else {
            tracing::warn!(
                "Skipping signed auth headers for cross-origin fetch. url={}, agent={}",
                url,
                agent.subject
            );
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Error when fetching {}: {}", url, e))?;
    let status = resp.status().as_u16();
    // Without reqwest's `charset` feature `text()` is exactly this lossy
    // UTF-8 decode, so the bounded path decodes the same way.
    let body = match max_bytes {
        Some(max) => {
            String::from_utf8_lossy(&read_body_bounded(resp, url, max).await?).into_owned()
        }
        None => resp
            .text()
            .await
            .map_err(|e| format!("Could not parse HTTP response for {}: {}", url, e))?,
    };
    if status != 200 {
        return Err(format!(
            "Could not fetch url '{}'. Status: {}. Body: {}",
            url, status, body
        )
        .into());
    };
    crate::metrics::external_fetch();
    Ok(body)
}

fn should_sign_request(url: &str, agent: &Agent) -> bool {
    // DID agents can be verified without fetching an HTTP subject.
    if agent.subject.is_did() {
        return true;
    }

    let Ok(target) = url::Url::parse(url) else {
        return false;
    };

    let Ok(agent_url) = url::Url::parse(agent.subject.as_str()) else {
        return false;
    };

    target.scheme() == agent_url.scheme()
        && target.host_str() == agent_url.host_str()
        && target.port_or_known_default() == agent_url.port_or_known_default()
}

/// JSON-AD body for posting a commit (HTTP or WS). Includes signature; omits `@id`.
pub async fn commit_to_wire_json(
    commit: &crate::Commit,
    store: &impl Storelike,
) -> AtomicResult<String> {
    let mut json_val: serde_json::Value =
        serde_json::from_str(&commit.into_resource(store).await?.to_json_ad(None)?)?;
    if let Some(obj) = json_val.as_object_mut() {
        obj.remove("@id");
    }
    Ok(serde_json::to_string(&json_val)?)
}

/// Posts a Commit to the endpoint of the Subject from the Commit
pub async fn post_commit(commit: &crate::Commit, store: &impl Storelike) -> AtomicResult<()> {
    let subject_str = commit.get_subject();
    let subject = Subject::from_raw(subject_str.as_str(), store.get_base_domain().as_deref());
    let server_url = if subject.is_did() {
        let mut url = store.get_server_url().to_string();
        if !url.ends_with('/') {
            url.push('/');
        }
        url
    } else {
        crate::utils::server_url(subject_str.as_str())?
    };
    // Default Commit endpoint is `https://example.com/commit`
    let endpoint = format!("{}commit", server_url);
    post_commit_custom_endpoint(&endpoint, commit, store).await
}

/// Posts a Commit to an endpoint
/// Default commit endpoint is `https://example.com/commit`
async fn post_commit_custom_endpoint(
    endpoint: &str,
    commit: &crate::Commit,
    store: &impl Storelike,
) -> AtomicResult<()> {
    let json = commit_to_wire_json(commit, store).await?;

    let client = http_client_builder()
        .build()
        .map_err(|e| format!("Could not build HTTP client: {}", e))?;

    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(json)
        .send()
        .await
        .map_err(|e| format!("Error when posting commit to {}: {}", endpoint, e))?;

    let status = resp.status().as_u16();
    if status != 200 {
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "Failed applying commit to {}. Status: {} Body: {}",
            endpoint, status, body
        )
        .into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn fetch_resource_basic() {
        let store = crate::Store::init().await.unwrap();
        let resource = fetch_resource(crate::urls::SHORTNAME, &store, None)
            .await
            .unwrap()
            .to_single();

        let shortname = resource.get(crate::urls::SHORTNAME).unwrap();
        assert!(shortname.to_string() == "shortname");
    }

    #[tokio::test]
    #[ignore]
    async fn post_commit_basic() {
        // let store = Store::init().unwrap();
        // // TODO actually make this work
        // let commit = crate::commit::CommitBuilder::new("subject".into())
        //     .sign(&agent)
        //     .unwrap();
        // post_commit(&commit).unwrap();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod ssrf_guard_tests {
    use super::ssrf_guard::{ip_is_blocked, preflight, resolve_public};
    use std::net::IpAddr;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn blocks_internal_ips() {
        for s in [
            "127.0.0.1",
            "169.254.169.254", // cloud metadata
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "100.64.0.1", // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",          // ULA
            "fe80::1",          // link-local
            "::ffff:127.0.0.1", // v4-mapped loopback
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_is_blocked(ip), "{s} must be blocked");
        }
    }

    #[test]
    fn allows_public_ips() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!ip_is_blocked(ip), "{s} must be allowed");
        }
    }

    #[test]
    fn preflight_rejects_bad_scheme_and_literal_internal() {
        assert!(preflight(&url("http://127.0.0.1/"), false).is_err());
        assert!(preflight(&url("http://169.254.169.254/latest/meta-data/"), false).is_err());
        assert!(preflight(&url("http://[::1]/"), false).is_err());
        assert!(preflight(&url("http://192.168.0.1/admin"), false).is_err());
        assert!(preflight(&url("ftp://example.com/"), false).is_err());
        assert!(url::Url::parse("not a url").is_err());
    }

    #[test]
    fn preflight_allows_public_literal_and_domains() {
        // Domains pass preflight and are screened at connect time by the resolver.
        assert!(preflight(&url("http://example.com/page"), false).is_ok());
        assert!(preflight(&url("https://1.1.1.1/"), false).is_ok());
    }

    #[test]
    fn preflight_escape_hatch_allows_internal_but_still_rejects_bad_scheme() {
        // With the escape hatch, internal literals are allowed...
        assert!(preflight(&url("http://127.0.0.1/"), true).is_ok());
        // ...but non-http(s) schemes are still refused.
        assert!(preflight(&url("ftp://example.com/"), true).is_err());
    }

    #[test]
    fn resolver_rejects_loopback_domain() {
        // `localhost` resolves only to loopback → the resolver refuses it,
        // before any socket is opened.
        assert!(resolve_public("localhost", false).is_err());
    }

    #[test]
    fn resolver_filters_but_keeps_public() {
        // A literal public IP passes the resolver unchanged.
        let addrs = resolve_public("1.1.1.1", false).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|sa| !ip_is_blocked(sa.ip())));
    }

    #[test]
    fn resolver_escape_hatch_allows_loopback() {
        assert!(resolve_public("localhost", true).is_ok());
    }

    /// End-to-end wiring: fetching a loopback-resolving domain must be refused
    /// via the untrusted (bookmark/import) path.
    #[tokio::test]
    async fn fetch_body_untrusted_blocks_localhost_domain() {
        let result = super::fetch_body_untrusted("http://localhost:1/", "text/html").await;
        assert!(
            result.is_err(),
            "untrusted fetch of loopback-resolving domain must fail"
        );
    }

    /// Non-http(s) schemes are rejected before any network activity.
    #[tokio::test]
    async fn fetch_body_untrusted_blocks_bad_scheme() {
        let result = super::fetch_body_untrusted("file:///etc/passwd", "text/html").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fetch_bytes_untrusted_blocks_localhost_and_bad_scheme() {
        assert!(super::fetch_bytes_untrusted("http://127.0.0.1:1/", 1024)
            .await
            .is_err());
        assert!(super::fetch_bytes_untrusted("file:///etc/passwd", 1024)
            .await
            .is_err());
    }
}

/// The body cap. These talk to a one-shot loopback server through the plain
/// (guard-less) client, since the guard refuses loopback and its escape hatch
/// is process-global; `read_body_bounded` is the same function either way.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod bounded_body_tests {
    use std::io::{Read, Write};

    /// Serves one raw HTTP response on a loopback port, returns its URL.
    fn one_shot_server(response: Vec<u8>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read the request head; we do not care what it says.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        });
        format!("http://127.0.0.1:{port}/")
    }

    async fn fetch(url: &str, max_bytes: usize) -> crate::errors::AtomicResult<Vec<u8>> {
        let client = super::http_client_builder().build().unwrap();
        let resp = client.get(url).send().await.unwrap();
        super::read_body_bounded(resp, url, max_bytes).await
    }

    #[tokio::test]
    async fn declared_content_length_over_cap_is_refused() {
        let url = one_shot_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n".to_vec(),
        );
        let err = fetch(&url, 1024).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn streamed_body_over_cap_is_refused() {
        // Chunked, so there is no Content-Length to check up front and the
        // stream counter has to catch it.
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..4 {
            response.extend_from_slice(b"400\r\n");
            response.extend_from_slice(&[b'x'; 0x400]);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        let url = one_shot_server(response);
        let err = fetch(&url, 1024).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn body_within_cap_is_read_in_full() {
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&[b'y'; 1024]);
        let url = one_shot_server(response);
        let body = fetch(&url, 1024).await.unwrap();
        assert_eq!(body.len(), 1024);
    }
}
