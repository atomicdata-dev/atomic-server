//! Who sent a plugin route request, verified by the host before the sandbox
//! starts (#1718; design `server-plugin-routes.md` in atomic-plugins, 2.5
//! and 2.7), and the crypto host calls a route handler gets (D8).
//!
//! | `auth` | Verified here | `request.caller` |
//! | --- | --- | --- |
//! | `http-signature` | draft-cavage-12 or RFC 9421, the body digest, ±5 min | `{ keyId, owner, scheme, alg, actor? }` |
//! | `bearer` | a token of this installation's `tokens` store | `{ token: { id, name, scopes, client } }` |
//!
//! A failure is a `401` from the host, and the sandbox never runs. `atomic`
//! and `dpop` are not verified here (see `route_exec`).
//!
//! **Keys of remote callers.** A `keyId` is fetched (without its fragment)
//! through the egress guard: public addresses only, the checked address
//! pinned, no redirects, 5 s, 64 KiB. The document may be the key itself or
//! an actor with `publicKey`; the key's `id` must be the `keyId`, and its
//! `owner` must be on the same origin. Keys are cached per installation for
//! an hour, failures for a minute. When a cached key fails to verify, it is
//! fetched again (at most once a minute), since the sender may have rotated
//! it. When the key came inside its owner's actor document, `caller.actor`
//! carries that actor's `inbox` and `endpoints.sharedInbox` (same origin
//! only; see [`actor_endpoints`]), so a plugin can answer the signer without
//! fetching anything itself. A `keyId` an installation on this node bound
//! ([`super::route_keys::bind_key_id`]) is not fetched.
//!
//! **Open Cloud Mesh.** A request whose RFC 9421 signature carries
//! `tag="ocm"` is verified the way OCM 1.5 ("HTTP Message Signatures")
//! prescribes, instead of by fetching its `keyid`: exactly one signature with
//! that tag, covering `@method`, `@target-uri` and, with a body,
//! `content-digest` and `content-length`; the signer's domain is the JSON
//! body's `senderDomain`, or the part after the last `@` of its `sender`;
//! the key is the JWK whose `kid` is the `keyid`, in the JWK Set at the
//! `jwksUri` of `https://<domain>/.well-known/ocm`; its `alg` decides the
//! algorithm. `request.caller` is then `{ keyId, owner, domain, scheme,
//! alg, tag, endPoint }`, where `owner` is the discovery origin and
//! `endPoint` the OCM API URL that discovery advertised. Both fetches go
//! through the same egress guard (and test seams) as any key fetch, over
//! `https` only.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use actix_web::HttpRequest;
use atomic_lib::{Db, Subject};
use serde_json::{json, Value as Json};

use super::{
    egress, host_core,
    http_signatures::{self, Algorithm, Message, PublicKey, Refused},
    manifest::Manifest,
    route_keys,
    route_registry::RouteRegistry,
    route_tokens::{self, Consents, Issue, Pending},
};

/// Key documents: how long to wait, and how much to read.
pub const KEY_FETCH_TIMEOUT_SECS: u64 = 5;
pub const KEY_FETCH_MAX_BYTES: usize = 64 * 1024;
/// How long a fetched key, and a failed fetch, is remembered.
pub const KEY_TTL_MS: i64 = 60 * 60 * 1000;
pub const NEGATIVE_TTL_MS: i64 = 60 * 1000;
/// A cached key that fails to verify is fetched again at most this often.
pub const REFETCH_AFTER_MS: i64 = 60 * 1000;
/// Cached keys per installation.
pub const MAX_CACHED_KEYS: usize = 1024;
/// Signatures per request that are tried.
const MAX_SIGNATURES: usize = 4;

fn pure(subject: &str) -> String {
    Subject::from(subject).pure_id()
}

// -- key fetching ---------------------------------------------------------------

/// Fetches a key document. The real one goes through the egress guard.
#[async_trait::async_trait]
pub trait KeyFetch: Send + Sync {
    async fn fetch(&self, url: &url::Url) -> Result<Vec<u8>, String>;
}

/// The egress-guarded fetch: every resolved address public, the checked
/// address pinned, no proxy, no redirects, a 5 s deadline and a 64 KiB cap.
/// `loopback` and `peer_ca` are the test seams of
/// [`crate::config::Config::plugin_delivery_loopback`] and
/// [`crate::config::Config::plugin_e2e_peer_ca`].
#[derive(Default)]
pub struct EgressFetch {
    pub loopback: bool,
    pub peer_ca: Option<std::path::PathBuf>,
}

#[async_trait::async_trait]
impl KeyFetch for EgressFetch {
    async fn fetch(&self, url: &url::Url) -> Result<Vec<u8>, String> {
        let addresses = super::route_delivery::guarded_addresses(url, self.loopback).await?;
        let host = url.host_str().ok_or("URL has no host")?;
        let builder = reqwest::Client::builder()
            .no_proxy()
            .resolve_to_addrs(host, &addresses)
            .timeout(std::time::Duration::from_secs(KEY_FETCH_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none());
        let client =
            super::route_delivery::with_seam_roots(builder, self.peer_ca.as_deref(), &addresses)?
                .build()
                .map_err(|e| format!("could not build an HTTP client: {e}"))?;
        let response = client
            .get(url.clone())
            .header(
                "accept",
                "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\", application/json",
            )
            .send()
            .await
            .map_err(|e| format!("could not fetch the key: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("the key document answered {}", response.status()));
        }
        let origin = egress::origin_of(url)?;
        host_core::read_capped(response.bytes_stream(), KEY_FETCH_MAX_BYTES, &origin).await
    }
}

/// Finds the key `key_id` names in a fetched document, and its owner.
pub fn key_from_document(
    document: &[u8],
    key_id: &url::Url,
) -> Result<(PublicKey, String), String> {
    let doc: Json = serde_json::from_slice(document).map_err(|_| "the key document is not JSON")?;
    let mut candidates: Vec<&Json> = Vec::new();
    if doc.get("publicKeyPem").is_some() {
        candidates.push(&doc);
    }
    match doc.get("publicKey") {
        Some(Json::Array(keys)) => candidates.extend(keys.iter()),
        Some(key @ Json::Object(_)) => candidates.push(key),
        _ => {}
    }
    let wanted = key_id.as_str();
    let key = candidates
        .into_iter()
        .find(|k| k["id"].as_str() == Some(wanted))
        .ok_or("the key document has no key with this keyId")?;
    let owner = key["owner"]
        .as_str()
        .or_else(|| key["controller"].as_str())
        .or_else(|| doc["id"].as_str())
        .ok_or("the key has no owner")?;
    let owner_url = url::Url::parse(owner).map_err(|_| "the key's owner is not a URL")?;
    if owner_url.origin() != key_id.origin() {
        return Err("the key's owner is on another origin than the key".into());
    }
    let pem = key["publicKeyPem"]
        .as_str()
        .ok_or("the key has no publicKeyPem")?;
    let public = PublicKey::from_pem(pem)?;
    public.check_strength()?;
    Ok((public, owner.to_string()))
}

/// The signer's inbox, from the actor document the key was found in: its
/// `id`, `inbox` and `endpoints.sharedInbox`. Only when the fetched document
/// is the key owner's own actor (its `id` is the owner), and only URLs on
/// the owner's origin, so a key document cannot point deliveries at another
/// server. Mastodon, Pleroma and Misskey serve the key inside the actor, so
/// they qualify; a separate key document (GoToSocial's `/main-key`) doesn't.
pub fn actor_endpoints(document: &[u8], owner: &str) -> Option<Json> {
    let doc: Json = serde_json::from_slice(document).ok()?;
    if doc["id"].as_str() != Some(owner) {
        return None;
    }
    let origin = url::Url::parse(owner).ok()?.origin();
    let same_origin = |value: &Json| {
        let value = value.as_str()?;
        let parsed = url::Url::parse(value).ok()?;
        (matches!(parsed.scheme(), "http" | "https")
            && parsed.origin() == origin
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && value.len() <= 2048)
            .then(|| value.to_string())
    };
    let inbox = same_origin(&doc["inbox"]);
    let shared = same_origin(&doc["endpoints"]["sharedInbox"]);
    if inbox.is_none() && shared.is_none() {
        return None;
    }
    Some(json!({ "id": owner, "inbox": inbox, "sharedInbox": shared }))
}

#[derive(Clone)]
enum Cached {
    Found {
        /// Boxed, so a cached failure stays small.
        key: Box<PublicKey>,
        owner: String,
        actor: Option<Json>,
        /// The algorithm a JWK's `alg` fixes (OCM keys); `None` for a PEM.
        alg: Option<Algorithm>,
        /// The OCM `endPoint` the signer's discovery advertised.
        endpoint: Option<String>,
        at: i64,
    },
    Missing {
        reason: String,
        at: i64,
    },
}

/// Remote keys, per installation, with a short negative cache.
pub struct KeyResolver {
    fetch: Arc<dyn KeyFetch>,
    cache: Mutex<HashMap<String, HashMap<String, Cached>>>,
}

impl Default for KeyResolver {
    fn default() -> Self {
        Self::new(Arc::new(EgressFetch::default()))
    }
}

/// A resolved key and where it came from.
pub struct Resolved {
    pub key: PublicKey,
    pub owner: String,
    /// [`actor_endpoints`] of the fetched document, if it had them.
    pub actor: Option<Json>,
    /// The algorithm the key's JWK fixes, if it came from one (OCM).
    pub alg: Option<Algorithm>,
    /// The OCM `endPoint` of the signer's discovery, for an OCM key.
    pub endpoint: Option<String>,
    /// Answered from the cache, not fetched now.
    pub cached: bool,
}

/// How long an OCM discovery or JWK Set document may be.
pub const OCM_DOCUMENT_MAX_BYTES: usize = KEY_FETCH_MAX_BYTES;

impl KeyResolver {
    pub fn new(fetch: Arc<dyn KeyFetch>) -> Self {
        Self {
            fetch,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, installation: &str, key_id: &str, now: i64) -> Option<Cached> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let entry = cache.get(&pure(installation))?.get(key_id)?.clone();
        let fresh = match &entry {
            Cached::Found { at, .. } => now - at < KEY_TTL_MS,
            Cached::Missing { at, .. } => now - at < NEGATIVE_TTL_MS,
        };
        fresh.then_some(entry)
    }

    fn store(&self, installation: &str, key_id: &str, entry: Cached) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let keys = cache.entry(pure(installation)).or_default();
        if keys.len() >= MAX_CACHED_KEYS && !keys.contains_key(key_id) {
            // Oldest out.
            if let Some(oldest) = keys
                .iter()
                .min_by_key(|(_, c)| match c {
                    Cached::Found { at, .. } | Cached::Missing { at, .. } => *at,
                })
                .map(|(k, _)| k.clone())
            {
                keys.remove(&oldest);
            }
        }
        keys.insert(key_id.to_string(), entry);
    }

    /// The key for `key_id`: a key this node's installations bound, a cached
    /// one, or one fetched now.
    pub async fn resolve(
        &self,
        db: &Db,
        installation: &str,
        key_id: &str,
        now: i64,
    ) -> Result<Resolved, Refused> {
        if let Some((_, key)) = route_keys::local_key(db, key_id) {
            let owner = key_id.split('#').next().unwrap_or(key_id).to_string();
            return Ok(Resolved {
                key,
                owner,
                actor: None,
                alg: None,
                endpoint: None,
                cached: false,
            });
        }
        match self.cached(installation, key_id, now) {
            Some(Cached::Found {
                key,
                owner,
                actor,
                alg,
                endpoint,
                ..
            }) => {
                return Ok(Resolved {
                    key: *key,
                    owner,
                    actor,
                    alg,
                    endpoint,
                    cached: true,
                })
            }
            Some(Cached::Missing { reason, .. }) => return Err(Refused(reason)),
            None => {}
        }
        self.fetch_now(installation, key_id, now).await
    }

    /// The OCM key `kid` of `domain`: from the JWK Set its discovery's
    /// `jwksUri` names. Cached like any key, under `ocm:<domain>#<kid>`.
    pub async fn resolve_ocm(
        &self,
        installation: &str,
        domain: &str,
        kid: &str,
        now: i64,
    ) -> Result<Resolved, Refused> {
        let cache_key = format!("ocm:{domain}#{kid}");
        match self.cached(installation, &cache_key, now) {
            Some(Cached::Found {
                key,
                owner,
                alg,
                endpoint,
                ..
            }) => {
                return Ok(Resolved {
                    key: *key,
                    owner,
                    actor: None,
                    alg,
                    endpoint,
                    cached: true,
                })
            }
            Some(Cached::Missing { reason, .. }) => return Err(Refused(reason)),
            None => {}
        }
        self.fetch_ocm_now(installation, domain, kid, now).await
    }

    /// Whether the OCM key of `domain` was cached long enough ago to fetch
    /// it again after it failed to verify.
    fn ocm_stale(&self, installation: &str, domain: &str, kid: &str, now: i64) -> bool {
        matches!(
            self.cached(installation, &format!("ocm:{domain}#{kid}"), now),
            Some(Cached::Found { at, .. }) if now - at >= REFETCH_AFTER_MS
        )
    }

    async fn fetch_ocm_now(
        &self,
        installation: &str,
        domain: &str,
        kid: &str,
        now: i64,
    ) -> Result<Resolved, Refused> {
        let cache_key = format!("ocm:{domain}#{kid}");
        let result = async {
            let origin = url::Url::parse(&format!("https://{domain}/"))
                .map_err(|_| format!("`{domain}` is not a domain"))?;
            let discovery = origin.join("/.well-known/ocm").map_err(|e| e.to_string())?;
            let bytes = self.fetch.fetch(&discovery).await?;
            let doc: Json = serde_json::from_slice(&bytes)
                .map_err(|_| "the OCM discovery document is not JSON".to_string())?;
            let jwks = doc["jwksUri"]
                .as_str()
                .ok_or("the OCM discovery document has no jwksUri")?;
            let jwks = url::Url::parse(jwks).map_err(|_| "jwksUri is not a URL".to_string())?;
            if jwks.scheme() != "https"
                || jwks.fragment().is_some()
                || !jwks.username().is_empty()
                || jwks.password().is_some()
            {
                return Err("jwksUri must be an https URL without credentials".to_string());
            }
            let bytes = self.fetch.fetch(&jwks).await?;
            let set: Json = serde_json::from_slice(&bytes)
                .map_err(|_| "the JWK Set is not JSON".to_string())?;
            let mut keys = set["keys"]
                .as_array()
                .ok_or("the JWK Set has no keys")?
                .iter()
                .filter(|k| k["kid"].as_str() == Some(kid));
            let jwk = keys
                .next()
                .ok_or("the JWK Set has no key with this keyid")?;
            if keys.next().is_some() {
                return Err("the JWK Set has more than one key with this keyid".to_string());
            }
            let (key, alg) = PublicKey::from_jwk(jwk)?;
            let endpoint = doc["endPoint"]
                .as_str()
                // Where to notify the signer. Its scheme is checked where it
                // is used: a delivery must match a declared operation.
                .filter(|e| {
                    url::Url::parse(e).is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
                })
                .map(|e| e.trim_end_matches('/').to_string());
            Ok((key, alg, origin.origin().ascii_serialization(), endpoint))
        }
        .await;
        match result {
            Ok((key, alg, owner, endpoint)) => {
                self.store(
                    installation,
                    &cache_key,
                    Cached::Found {
                        key: Box::new(key.clone()),
                        owner: owner.clone(),
                        actor: None,
                        alg: Some(alg),
                        endpoint: endpoint.clone(),
                        at: now,
                    },
                );
                Ok(Resolved {
                    key,
                    owner,
                    actor: None,
                    alg: Some(alg),
                    endpoint,
                    cached: false,
                })
            }
            Err(e) => {
                let reason = format!("the OCM signing key could not be used: {e}");
                self.store(
                    installation,
                    &cache_key,
                    Cached::Missing {
                        reason: reason.clone(),
                        at: now,
                    },
                );
                Err(Refused(reason))
            }
        }
    }

    async fn fetch_now(
        &self,
        installation: &str,
        key_id: &str,
        now: i64,
    ) -> Result<Resolved, Refused> {
        let result = async {
            let parsed =
                url::Url::parse(key_id).map_err(|_| "the keyId is not a URL".to_string())?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err("the keyId is not an HTTP URL".to_string());
            }
            let mut document = parsed.clone();
            document.set_fragment(None);
            let bytes = self.fetch.fetch(&document).await?;
            let (key, owner) = key_from_document(&bytes, &parsed)?;
            let actor = actor_endpoints(&bytes, &owner);
            Ok((key, owner, actor))
        }
        .await;
        match result {
            Ok((key, owner, actor)) => {
                self.store(
                    installation,
                    key_id,
                    Cached::Found {
                        key: Box::new(key.clone()),
                        owner: owner.clone(),
                        actor: actor.clone(),
                        alg: None,
                        endpoint: None,
                        at: now,
                    },
                );
                Ok(Resolved {
                    key,
                    owner,
                    actor,
                    alg: None,
                    endpoint: None,
                    cached: false,
                })
            }
            Err(e) => {
                let reason = format!("the signing key could not be used: {e}");
                self.store(
                    installation,
                    key_id,
                    Cached::Missing {
                        reason: reason.clone(),
                        at: now,
                    },
                );
                Err(Refused(reason))
            }
        }
    }

    /// After a cached key failed to verify: fetch it again, unless it was
    /// fetched within [`REFETCH_AFTER_MS`].
    async fn refetch(&self, installation: &str, key_id: &str, now: i64) -> Option<Resolved> {
        let stale = matches!(
            self.cached(installation, key_id, now),
            Some(Cached::Found { at, .. }) if now - at >= REFETCH_AFTER_MS
        );
        if !stale {
            return None;
        }
        self.fetch_now(installation, key_id, now).await.ok()
    }
}

// -- authenticating a request --------------------------------------------------------

/// The request, as the signature verifier needs it.
pub struct RequestParts {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl RequestParts {
    pub fn of(req: &HttpRequest) -> Self {
        let info = req.connection_info();
        Self {
            method: req.method().to_string(),
            scheme: info.scheme().to_string(),
            authority: info.host().to_string(),
            path: req.uri().path().to_string(),
            query: req.uri().query().map(str::to_string),
            headers: req
                .headers()
                .iter()
                .filter_map(|(n, v)| Some((n.as_str().to_string(), v.to_str().ok()?.to_string())))
                .collect(),
        }
    }

    pub fn message(&self) -> Message<'_> {
        Message {
            method: &self.method,
            scheme: &self.scheme,
            authority: &self.authority,
            path: &self.path,
            query: self.query.as_deref(),
            headers: &self.headers,
        }
    }
}

/// The domain an OCM request names as its signer: `senderDomain`, or the
/// part after the last `@` of `sender` (an OCM address). When both are
/// given they must agree. When the body names neither (Nextcloud 35's
/// notifications carry no `senderDomain`, though OCM 1.5 requires it), the
/// domain of the signature's `keyid`: an `http(s)` URL's host and port
/// (Nextcloud's `https://host/ocm#ecdsa-p256-sha256-1`), or the part before
/// `#` (`sender.example.org#key1`). That is no weaker: the key is still
/// looked up in that domain's own discovery and JWK Set. Lowercased; a host
/// with an optional port.
pub fn ocm_signer_domain(body: &[u8], key_id: &str) -> Result<String, Refused> {
    let doc: Json = serde_json::from_slice(body).map_err(|_| {
        Refused("an OCM-signed request needs a JSON body that names its sender".into())
    })?;
    let from_domain = doc["senderDomain"].as_str();
    let from_sender = doc["sender"]
        .as_str()
        .and_then(|s| s.rsplit_once('@'))
        .map(|(_, d)| d);
    let from_key: String;
    let raw = match (from_domain, from_sender) {
        (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => {
            return Err(Refused(
                "`senderDomain` and the domain of `sender` differ".into(),
            ))
        }
        (Some(d), _) | (None, Some(d)) => d,
        (None, None) => {
            from_key = match url::Url::parse(key_id) {
                Ok(u) if matches!(u.scheme(), "http" | "https") => match (u.host_str(), u.port()) {
                    (Some(h), Some(p)) => format!("{h}:{p}"),
                    (Some(h), None) => h.to_string(),
                    _ => String::new(),
                },
                _ => key_id.split('#').next().unwrap_or_default().to_string(),
            };
            if from_key.is_empty() {
                return Err(Refused(
                    "an OCM-signed request must name `senderDomain` or a `sender` address".into(),
                ));
            }
            &from_key
        }
    };
    let domain = raw.to_ascii_lowercase();
    let parsed = url::Url::parse(&format!("https://{domain}/")).ok();
    let exact = parsed.as_ref().is_some_and(|u| {
        u.path() == "/"
            && u.username().is_empty()
            && u.query().is_none()
            && u.host_str().is_some()
            && match u.port() {
                Some(port) => format!("{}:{port}", u.host_str().unwrap_or_default()) == domain,
                None => u.host_str() == Some(domain.as_str()),
            }
    });
    if !exact || domain.len() > 255 {
        return Err(Refused(format!("`{raw}` is not a server domain")));
    }
    Ok(domain)
}

/// Verifies an OCM request (see the module docs): the one `tag="ocm"`
/// signature, with the key from the signer's discovery.
pub async fn verify_ocm_signature(
    resolver: &KeyResolver,
    installation: &str,
    message: &Message<'_>,
    signatures: &[http_signatures::Parsed],
    body: &[u8],
    now_ms: i64,
) -> Result<Json, Refused> {
    let parsed = http_signatures::tagged(signatures, http_signatures::OCM_TAG)?;
    http_signatures::check_policy(parsed, message, body, now_ms.div_euclid(1000))?;
    http_signatures::check_ocm_policy(parsed, body)?;
    let domain = ocm_signer_domain(body, &parsed.key_id)?;
    let check = |resolved: &Resolved| {
        let mut pinned = parsed.clone();
        if let Some(alg) = resolved.alg {
            if parsed.algorithm.is_some_and(|stated| stated != alg) {
                return Err(Refused(
                    "the signature's `alg` is not the algorithm of the key's JWK".into(),
                ));
            }
            pinned.algorithm = Some(alg);
        }
        http_signatures::verify(&pinned, &resolved.key)
    };
    let resolved = resolver
        .resolve_ocm(installation, &domain, &parsed.key_id, now_ms)
        .await?;
    let (alg, owner, endpoint) = match check(&resolved) {
        Ok(alg) => (alg, resolved.owner, resolved.endpoint),
        Err(e) => {
            // The sender may have rotated its key: fetch its set again, at
            // most once a minute.
            if !(resolved.cached
                && resolver.ocm_stale(installation, &domain, &parsed.key_id, now_ms))
            {
                return Err(e);
            }
            let again = resolver
                .fetch_ocm_now(installation, &domain, &parsed.key_id, now_ms)
                .await?;
            (check(&again)?, again.owner, again.endpoint)
        }
    };
    Ok(json!({
        "keyId": parsed.key_id,
        "owner": owner,
        "domain": domain,
        "scheme": parsed.scheme.as_str(),
        "alg": alg.rfc9421_name(),
        "tag": http_signatures::OCM_TAG,
        "endPoint": endpoint,
    }))
}

/// Verifies an `http-signature` request. Policy (freshness, coverage,
/// digest) is checked before any key is fetched, so a stale or unbound
/// request costs no fetch. A request with an OCM-tagged signature is
/// verified as OCM ([`verify_ocm_signature`]).
pub async fn verify_signature(
    resolver: &KeyResolver,
    db: &Db,
    installation: &str,
    parts: &RequestParts,
    body: &[u8],
    now_ms: i64,
) -> Result<Json, Refused> {
    let message = parts.message();
    let now = now_ms.div_euclid(1000);
    let signatures = http_signatures::parse(&message)?;
    if signatures
        .iter()
        .any(|p| p.tag.as_deref() == Some(http_signatures::OCM_TAG))
    {
        return verify_ocm_signature(resolver, installation, &message, &signatures, body, now_ms)
            .await;
    }
    let mut last = Refused("the request is not signed".into());
    for parsed in signatures.iter().take(MAX_SIGNATURES) {
        if let Err(e) = http_signatures::check_policy(parsed, &message, body, now) {
            last = e;
            continue;
        }
        let resolved = match resolver
            .resolve(db, installation, &parsed.key_id, now_ms)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last = e;
                continue;
            }
        };
        let verified = match http_signatures::verify(parsed, &resolved.key) {
            Ok(alg) => Some((alg, resolved.owner, resolved.actor)),
            Err(e) if resolved.cached => {
                match resolver.refetch(installation, &parsed.key_id, now_ms).await {
                    Some(again) => http_signatures::verify(parsed, &again.key)
                        .ok()
                        .map(|alg| (alg, again.owner, again.actor)),
                    None => {
                        last = e;
                        None
                    }
                }
            }
            Err(e) => {
                last = e;
                None
            }
        };
        if let Some((alg, owner, actor)) = verified {
            let mut caller = json!({
                "keyId": parsed.key_id,
                "owner": owner,
                "scheme": parsed.scheme.as_str(),
                "alg": alg.rfc9421_name(),
            });
            // Where to answer the signer, from the document the key came
            // from; never from the request.
            if let Some(actor) = actor {
                caller["actor"] = actor;
            }
            return Ok(caller);
        }
    }
    Err(last)
}

/// Verifies a `bearer` request against the installation's tokens.
pub fn verify_bearer(
    db: &Db,
    installation: &str,
    req: &HttpRequest,
    now: i64,
) -> Result<Json, Refused> {
    let header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Refused("the request has no bearer token".into()))?;
    let (scheme, token) = header
        .split_once(' ')
        .ok_or_else(|| Refused("the request has no bearer token".into()))?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Refused("the request has no bearer token".into()));
    }
    let info = route_tokens::verify(db, installation, token.trim(), now)
        .ok_or_else(|| Refused("the bearer token is unknown, revoked or expired".into()))?;
    Ok(json!({ "token": {
        "id": info.id,
        "name": info.name,
        "scopes": info.scopes,
        "client": info.client,
    }}))
}

// -- host calls -----------------------------------------------------------------

/// What a route's crypto host calls need. Built per request.
pub struct CryptoHost {
    pub db: Arc<Db>,
    pub installation: String,
    pub manifest: Manifest,
    pub registry: Arc<RouteRegistry>,
    pub consents: Arc<Consents>,
    /// `scheme://host`, how this request reached the node, and the
    /// installation's base URL there (with `/_routes/<slug>` on
    /// `drive-prefix`).
    pub base: String,
    /// The API origin, where the consent page is.
    pub api_origin: String,
    /// Lines for the run log: every signature, with its operation id.
    pub log: Arc<Mutex<Vec<String>>>,
    /// The origins of the clients of tokens issued from a person's consent
    /// in this request: the response may redirect there
    /// ([`super::route_exec::ResponseRules::approved_clients`]).
    pub approved_clients: Arc<Mutex<Vec<String>>>,
    pub now: i64,
    /// The Installation's config, which `willow` key bindings read.
    pub config: Json,
    /// Whom the route reads as: a Willow entry's source must be readable by it.
    pub reader: atomic_lib::agents::ForAgent,
}

impl CryptoHost {
    fn tokens_declared(&self, name: &str) -> Result<(), String> {
        let declared = self
            .manifest
            .http
            .as_ref()
            .is_some_and(|h| h.tokens.iter().any(|t| t.name == name));
        if declared {
            Ok(())
        } else {
            Err(format!(
                "this plugin declares no token store named `{name}`"
            ))
        }
    }

    /// Binds `key_id` to the key if it lies in this installation's own
    /// route space, so this node verifies it without a fetch.
    fn maybe_bind(&self, name: &str, key_id: &str) -> Result<(), String> {
        let Ok(url) = url::Url::parse(key_id) else {
            return Ok(());
        };
        let Some(host) = url.host_str() else {
            return Ok(());
        };
        let host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        // `/_routes/<slug>/` is the installation's only on this node's API
        // hosts: the same path on another host is someone else's URL.
        let own = self
            .registry
            .target(&host, url.path())
            .is_some_and(|(subject, mount, _)| {
                pure(&subject) == pure(&self.installation)
                    && (mount != super::manifest_http::Mount::DrivePrefix
                        || self
                            .registry
                            .config()
                            .is_api_host(&super::route_registry::host_name(&host)))
            });
        if own {
            route_keys::bind_key_id(&self.db, &self.installation, name, key_id)?;
        }
        Ok(())
    }

    /// One `ctx.keys.*` or `ctx.tokens.*` call. Errors go back to the
    /// plugin, so none carries key material.
    pub async fn call(&self, name: &str, request: &str) -> Result<String, String> {
        let request: Json =
            serde_json::from_str(request).map_err(|e| format!("not a JSON request: {e}"))?;
        let out = match name {
            "keys.publicKey" => {
                let key = request["key"].as_str().ok_or("give the key's name")?;
                let info = route_keys::public(&self.db, &self.installation, &self.manifest, key)?;
                let key_id = request["keyId"].as_str();
                if let Some(key_id) = key_id {
                    self.maybe_bind(key, key_id)?;
                }
                let mut out = serde_json::to_value(info).map_err(|e| e.to_string())?;
                out["keyId"] = json!(key_id);
                out
            }
            "keys.sign" => {
                let sign: route_keys::SignRequest = serde_json::from_value(request)
                    .map_err(|e| format!("not a signing request: {e}"))?;
                let (out, line) = route_keys::sign(
                    &self.db,
                    &self.installation,
                    &self.manifest,
                    &sign,
                    std::time::SystemTime::now(),
                )?;
                self.maybe_bind(&sign.key, &sign.key_id)?;
                self.log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(line);
                out
            }
            "willow.subspace" | "willow.source" | "willow.authorise" | "willow.list" => {
                let willow = super::willow::WillowHost {
                    db: &self.db,
                    installation: &self.installation,
                    manifest: &self.manifest,
                    config: &self.config,
                    reader: &self.reader,
                    now_ms: self.now,
                    willow_now: super::willow::willow_now(),
                };
                let key = request["key"].as_str().ok_or("give the key's name")?;
                match name {
                    "willow.subspace" => willow.subspace(key)?,
                    "willow.list" => willow.list(key)?,
                    "willow.source" => {
                        let subject = request["subject"]
                            .as_str()
                            .ok_or("give the source's subject")?;
                        willow.source(key, subject).await?
                    }
                    _ => {
                        let authorise: super::willow::AuthoriseRequest =
                            serde_json::from_value(request.clone())
                                .map_err(|e| format!("not a Willow authorisation request: {e}"))?;
                        let (out, line) = willow.authorise(&authorise).await?;
                        if !line.is_empty() {
                            self.log
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(line);
                        }
                        out
                    }
                }
            }
            "tokens.issue" => {
                let issue = if let Some(code) = request["code"].as_str() {
                    let granted = self.consents.redeem(&self.installation, code, self.now)?;
                    Issue {
                        name: granted.name,
                        scopes: granted.scopes,
                        client: granted.client,
                        expires_at: expires_at(&request, self.now)?,
                        approved_by: Some(granted.approved_by),
                    }
                } else {
                    let name = request["name"]
                        .as_str()
                        .ok_or("give the token store's name")?;
                    self.tokens_declared(name)?;
                    Issue {
                        name: name.to_string(),
                        scopes: strings(&request["scopes"])?,
                        client: request["client"].as_str().map(str::to_string),
                        expires_at: expires_at(&request, self.now)?,
                        approved_by: None,
                    }
                };
                let (token, info) =
                    route_tokens::issue(&self.db, &self.installation, issue, self.now)?;
                // A person approved this client on the consent page: the
                // response may hand the token back to it.
                if info.approved_by.is_some() {
                    if let Some(origin) = info
                        .client
                        .as_deref()
                        .and_then(super::route_exec::origin_of)
                    {
                        self.approved_clients
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(origin);
                    }
                }
                let mut out = serde_json::to_value(info).map_err(|e| e.to_string())?;
                out["token"] = json!(token);
                out
            }
            "tokens.verify" => {
                let token = request["token"].as_str().ok_or("give the token")?;
                json!(route_tokens::verify(
                    &self.db,
                    &self.installation,
                    token,
                    self.now
                ))
            }
            "tokens.revoke" => {
                let id = request["id"].as_str().ok_or("give the token's id")?;
                json!(route_tokens::revoke(&self.db, &self.installation, id)?)
            }
            "tokens.requestConsent" => {
                let name = request["name"]
                    .as_str()
                    .ok_or("give the token store's name")?;
                self.tokens_declared(name)?;
                let redirect = request["redirect"]
                    .as_str()
                    .ok_or("give the route path the answer goes to")?;
                self.check_redirect(redirect)?;
                let id = self.consents.request(
                    Pending {
                        installation: self.installation.clone(),
                        name: name.to_string(),
                        scopes: strings(&request["scopes"])?,
                        client: request["client"].as_str().map(str::to_string),
                        redirect: format!("{}{redirect}", self.base),
                        state: request["state"].as_str().map(str::to_string),
                        expires_at: self.now + route_tokens::CONSENT_TTL_MS,
                    },
                    self.now,
                )?;
                json!({ "url": consent_url(&self.api_origin, &id) })
            }
            other => return Err(format!("there is no host call `{other}`")),
        };
        Ok(out.to_string())
    }

    /// The consent answer may only go to a `GET` route of this installation.
    fn check_redirect(&self, path: &str) -> Result<(), String> {
        let segments = super::route_registry::request_segments(path);
        let routed = path.starts_with('/')
            && !path.contains("//")
            && !path.contains(['?', '#', '\\'])
            && !segments.iter().any(|s| *s == ".." || *s == ".")
            && self.manifest.http.as_ref().is_some_and(|h| {
                h.routes.iter().any(|r| {
                    r.methods.iter().any(|m| m == "GET")
                        && super::manifest_http::pattern(&r.path)
                            .is_ok_and(|p| super::route_registry::matches(&p, &segments))
                })
            });
        if routed {
            Ok(())
        } else {
            Err(format!(
                "the consent answer can only go to a GET route of this plugin; `{path}` is not one"
            ))
        }
    }
}

/// The host's consent page for a request id.
pub fn consent_url(api_origin: &str, id: &str) -> String {
    format!(
        "{}/app/route-consent?request={id}",
        api_origin.trim_end_matches('/')
    )
}

fn strings(value: &Json) -> Result<Vec<String>, String> {
    match value {
        Json::Null => Ok(Vec::new()),
        Json::Array(items) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_string)
                    .ok_or("scopes are strings".to_string())
            })
            .collect(),
        _ => Err("scopes are an array of strings".into()),
    }
}

fn expires_at(request: &Json, now: i64) -> Result<Option<i64>, String> {
    match &request["expiresIn"] {
        Json::Null => Ok(None),
        value => value
            .as_u64()
            .filter(|s| *s > 0 && *s <= 10 * 365 * 24 * 3600)
            .map(|s| Some(now + (s as i64) * 1000))
            .ok_or_else(|| "expiresIn is a number of seconds, up to ten years".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn the_signers_inbox_comes_only_from_its_own_actor_document() {
        let owner = "https://m.example/users/bob";
        let doc = |v: Json| v.to_string().into_bytes();
        assert_eq!(
            actor_endpoints(
                &doc(json!({
                    "id": owner,
                    "inbox": "https://m.example/users/bob/inbox",
                    "endpoints": {"sharedInbox": "https://m.example/inbox"}
                })),
                owner
            ),
            Some(json!({
                "id": owner,
                "inbox": "https://m.example/users/bob/inbox",
                "sharedInbox": "https://m.example/inbox"
            }))
        );
        // A shared inbox on another server is not the signer's to name.
        assert_eq!(
            actor_endpoints(
                &doc(json!({
                    "id": owner,
                    "inbox": "https://m.example/i",
                    "endpoints": {"sharedInbox": "https://elsewhere.example/inbox"}
                })),
                owner
            ),
            Some(json!({"id": owner, "inbox": "https://m.example/i", "sharedInbox": null}))
        );
        for other in [
            // A separate key document, not the actor.
            json!({"id": format!("{owner}/main-key"), "inbox": "https://m.example/i"}),
            // Only inboxes elsewhere, or with credentials, or none.
            json!({"id": owner, "inbox": "https://elsewhere.example/i"}),
            json!({"id": owner, "inbox": "https://u:p@m.example/i"}),
            json!({"id": owner}),
        ] {
            assert_eq!(actor_endpoints(&doc(other.clone()), owner), None, "{other}");
        }
        assert_eq!(actor_endpoints(b"<html>", owner), None);
    }

    /// Serves one key document from memory and counts fetches.
    struct Fake {
        document: Mutex<Vec<u8>>,
        fetches: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl KeyFetch for Fake {
        async fn fetch(&self, url: &url::Url) -> Result<Vec<u8>, String> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            assert!(url.fragment().is_none(), "the fragment is not fetched");
            let doc = self.document.lock().unwrap().clone();
            if doc.is_empty() {
                Err("404".into())
            } else {
                Ok(doc)
            }
        }
    }

    fn actor(key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        json!({
            "id": "https://remote.example/users/bob",
            "type": "Person",
            "publicKey": {
                "id": "https://remote.example/users/bob#main-key",
                "owner": "https://remote.example/users/bob",
                "publicKeyPem": PublicKey::Ed25519(key.verifying_key()).to_pem(),
            }
        })
        .to_string()
        .into_bytes()
    }

    struct Ed(ed25519_dalek::SigningKey);
    impl http_signatures::Signer for Ed {
        fn algorithm(&self) -> http_signatures::Algorithm {
            http_signatures::Algorithm::Ed25519
        }
        fn sign(&self, data: &[u8]) -> Vec<u8> {
            use ed25519_dalek::Signer as _;
            self.0.sign(data).to_bytes().to_vec()
        }
    }

    fn signed_parts(
        key: &ed25519_dalek::SigningKey,
        body: &[u8],
        at: std::time::SystemTime,
    ) -> RequestParts {
        let url = url::Url::parse("https://node.example/_routes/s/inbox").unwrap();
        let mut headers = http_signatures::sign_cavage(
            &Ed(key.clone()),
            "https://remote.example/users/bob#main-key",
            &http_signatures::Outbound {
                method: "POST",
                url: &url,
                body: Some(body),
            },
            at,
        );
        headers.push(("content-type".into(), "application/activity+json".into()));
        RequestParts {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "node.example".into(),
            path: "/_routes/s/inbox".into(),
            query: None,
            headers,
        }
    }

    fn now_ms(at: std::time::SystemTime) -> i64 {
        at.duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[tokio::test]
    async fn a_signed_request_is_verified_through_a_cached_key_fetch() {
        let db = Db::init_temp("route_auth_cache").await.unwrap();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let fake = Arc::new(Fake {
            document: Mutex::new(actor(&key)),
            fetches: AtomicUsize::new(0),
        });
        let resolver = KeyResolver::new(fake.clone());
        let body = br#"{"type":"Follow"}"#;
        let at = std::time::SystemTime::now();
        let parts = signed_parts(&key, body, at);
        let caller = verify_signature(&resolver, &db, "did:ad:i", &parts, body, now_ms(at))
            .await
            .unwrap();
        assert_eq!(caller["keyId"], "https://remote.example/users/bob#main-key");
        assert_eq!(caller["owner"], "https://remote.example/users/bob");
        assert_eq!(caller["scheme"], "draft-cavage-12");
        assert_eq!(caller["alg"], "ed25519");
        // Cached per installation: a second request fetches nothing.
        verify_signature(&resolver, &db, "did:ad:i", &parts, body, now_ms(at))
            .await
            .unwrap();
        assert_eq!(fake.fetches.load(Ordering::SeqCst), 1);
        // Another installation has its own cache.
        verify_signature(&resolver, &db, "did:ad:j", &parts, body, now_ms(at))
            .await
            .unwrap();
        assert_eq!(fake.fetches.load(Ordering::SeqCst), 2);

        // A stale request never costs a fetch.
        let old = at - std::time::Duration::from_secs(600);
        let err = verify_signature(
            &resolver,
            &db,
            "did:ad:k",
            &signed_parts(&key, body, old),
            body,
            now_ms(at),
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("seconds"), "{err}");
        // Nor does a digest that does not match the body.
        let err = verify_signature(&resolver, &db, "did:ad:k", &parts, b"{}", now_ms(at))
            .await
            .unwrap_err();
        assert!(err.0.contains("Digest"), "{err}");
        assert_eq!(fake.fetches.load(Ordering::SeqCst), 2);

        // The sender rotates its key. The cached key fails; once it is a
        // minute old, it is fetched again and the new key verifies.
        let rotated = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        *fake.document.lock().unwrap() = actor(&rotated);
        let later = at + std::time::Duration::from_secs(30);
        let parts2 = signed_parts(&rotated, body, later);
        assert!(
            verify_signature(&resolver, &db, "did:ad:i", &parts2, body, now_ms(later))
                .await
                .is_err()
        );
        assert_eq!(
            fake.fetches.load(Ordering::SeqCst),
            2,
            "not refetched within a minute"
        );
        let later = at + std::time::Duration::from_secs(90);
        let parts2 = signed_parts(&rotated, body, later);
        verify_signature(&resolver, &db, "did:ad:i", &parts2, body, now_ms(later))
            .await
            .unwrap();
        assert_eq!(fake.fetches.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn missing_keys_are_cached_briefly() {
        let db = Db::init_temp("route_auth_negative").await.unwrap();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let fake = Arc::new(Fake {
            document: Mutex::new(Vec::new()),
            fetches: AtomicUsize::new(0),
        });
        let resolver = KeyResolver::new(fake.clone());
        let body = b"{}";
        let at = std::time::SystemTime::now();
        let parts = signed_parts(&key, body, at);
        for _ in 0..3 {
            let err = verify_signature(&resolver, &db, "did:ad:i", &parts, body, now_ms(at))
                .await
                .unwrap_err();
            assert!(err.0.contains("could not be used"), "{err}");
        }
        assert_eq!(fake.fetches.load(Ordering::SeqCst), 1, "negative cache");
        *fake.document.lock().unwrap() = actor(&key);
        let later = at + std::time::Duration::from_millis(NEGATIVE_TTL_MS as u64 + 1000);
        let parts = signed_parts(&key, body, later);
        verify_signature(&resolver, &db, "did:ad:i", &parts, body, now_ms(later))
            .await
            .unwrap();
        assert_eq!(fake.fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn key_documents_must_name_the_key_and_an_owner_on_its_origin() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pem = PublicKey::Ed25519(key.verifying_key()).to_pem();
        let id = url::Url::parse("https://remote.example/users/bob#main-key").unwrap();
        // The key document itself.
        let doc = json!({"id": id.as_str(), "owner": "https://remote.example/users/bob", "publicKeyPem": pem});
        assert_eq!(
            key_from_document(doc.to_string().as_bytes(), &id)
                .unwrap()
                .1,
            "https://remote.example/users/bob"
        );
        // Another key's id.
        let doc = json!({"publicKey": {"id": "https://remote.example/users/bob#other", "owner": "https://remote.example/users/bob", "publicKeyPem": pem}});
        assert!(key_from_document(doc.to_string().as_bytes(), &id).is_err());
        // An owner on another origin.
        let doc = json!({"publicKey": {"id": id.as_str(), "owner": "https://evil.example/users/bob", "publicKeyPem": pem}});
        assert!(key_from_document(doc.to_string().as_bytes(), &id)
            .unwrap_err()
            .contains("another origin"));
        assert!(key_from_document(b"<html>", &id).is_err());
    }

    #[tokio::test]
    async fn key_fetches_go_through_the_egress_guard() {
        // The real fetcher refuses what a keyId must never reach: loopback,
        // private ranges, metadata endpoints.
        for url in [
            "http://127.0.0.1:9883/users/bob",
            "http://10.0.0.1/users/bob",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/users/bob",
            "http://user:pass@example.com/users/bob",
        ] {
            let err = EgressFetch::default()
                .fetch(&url::Url::parse(url).unwrap())
                .await
                .unwrap_err();
            assert!(
                err.contains("refused") || err.contains("credentials"),
                "{url}: {err}"
            );
        }
        // And a refused keyId is remembered as missing, not fetched again.
        let db = Db::init_temp("route_auth_egress").await.unwrap();
        let resolver = KeyResolver::default();
        let err = resolver
            .resolve(&db, "did:ad:i", "http://127.0.0.1:1/k#main-key", 0)
            .await
            .err()
            .unwrap();
        assert!(err.0.contains("refused"), "{err}");
        assert!(matches!(
            resolver.cached("did:ad:i", "http://127.0.0.1:1/k#main-key", 1),
            Some(Cached::Missing { .. })
        ));
    }

    // -- Open Cloud Mesh ----------------------------------------------------------

    /// Serves an OCM peer's discovery and JWK Set from memory, by URL.
    struct Peer {
        documents: Mutex<HashMap<String, Vec<u8>>>,
        fetched: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl KeyFetch for Peer {
        async fn fetch(&self, url: &url::Url) -> Result<Vec<u8>, String> {
            self.fetched.lock().unwrap().push(url.to_string());
            self.documents
                .lock()
                .unwrap()
                .get(url.as_str())
                .cloned()
                .ok_or_else(|| "404".to_string())
        }
    }

    fn peer(origin: &str, keys: &[(&str, &ed25519_dalek::SigningKey)]) -> Arc<Peer> {
        let jwks = json!({
            "keys": keys.iter().map(|(kid, key)| {
                let mut jwk = PublicKey::Ed25519(key.verifying_key()).to_jwk();
                jwk["kid"] = json!(kid);
                jwk
            }).collect::<Vec<_>>()
        });
        let discovery = json!({
            "enabled": true,
            "apiVersion": "1.5.0",
            "endPoint": format!("{origin}/ocm"),
            "capabilities": ["http-sig"],
            "jwksUri": format!("{origin}/ocm/jwks"),
        });
        Arc::new(Peer {
            documents: Mutex::new(HashMap::from([
                (
                    format!("{origin}/.well-known/ocm"),
                    discovery.to_string().into_bytes(),
                ),
                (format!("{origin}/ocm/jwks"), jwks.to_string().into_bytes()),
            ])),
            fetched: Default::default(),
        })
    }

    /// A share the way an OCM sender signs it (OCM 1.5 appendix B).
    fn ocm_share(
        key: &ed25519_dalek::SigningKey,
        kid: &str,
        body: &[u8],
        at: std::time::SystemTime,
    ) -> RequestParts {
        let url = url::Url::parse("https://receiver.example/ocm/shares").unwrap();
        let mut headers = http_signatures::sign_rfc9421_tagged(
            &Ed(key.clone()),
            kid,
            &http_signatures::Outbound {
                method: "POST",
                url: &url,
                body: Some(body),
            },
            at,
            Some("ocm"),
        );
        headers.push(("content-type".into(), "application/json".into()));
        RequestParts {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "receiver.example".into(),
            path: "/ocm/shares".into(),
            query: None,
            headers,
        }
    }

    fn share_body(sender: &str) -> Vec<u8> {
        json!({
            "shareWith": "marie@receiver.example",
            "name": "spec.yaml",
            "providerId": "7c084226",
            "owner": sender,
            "sender": sender,
            "shareType": "user",
            "resourceType": "file",
            "protocol": {"name": "multi", "webdav": {"uri": "https://sender.example/dav/7c084226", "sharedSecret": "s", "permissions": ["read"]}}
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn an_ocm_signature_is_verified_with_the_senders_discovered_jwks() {
        let db = Db::init_temp("route_auth_ocm").await.unwrap();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let fake = peer("https://sender.example", &[("sender.example#key1", &key)]);
        let resolver = KeyResolver::new(fake.clone());
        let body = share_body("einstein@sender.example");
        let at = std::time::SystemTime::now();
        let parts = ocm_share(&key, "sender.example#key1", &body, at);
        let caller = verify_signature(&resolver, &db, "did:ad:i", &parts, &body, now_ms(at))
            .await
            .unwrap();
        assert_eq!(
            caller,
            json!({
                "keyId": "sender.example#key1",
                "owner": "https://sender.example",
                "domain": "sender.example",
                "scheme": "rfc9421",
                "alg": "ed25519",
                "tag": "ocm",
                "endPoint": "https://sender.example/ocm",
            })
        );
        // Discovery, then its jwksUri; cached afterwards.
        assert_eq!(
            *fake.fetched.lock().unwrap(),
            [
                "https://sender.example/.well-known/ocm",
                "https://sender.example/ocm/jwks"
            ]
        );
        verify_signature(&resolver, &db, "did:ad:i", &parts, &body, now_ms(at))
            .await
            .unwrap();
        assert_eq!(fake.fetched.lock().unwrap().len(), 2);

        // Another server's address in the body means that server's keys:
        // its discovery has none, so it fails.
        let forged = share_body("einstein@other.example");
        let err = verify_signature(
            &resolver,
            &db,
            "did:ad:i",
            &ocm_share(&key, "sender.example#key1", &forged, at),
            &forged,
            now_ms(at),
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("OCM signing key"), "{err}");

        // A kid the set does not have.
        let err = verify_signature(
            &resolver,
            &db,
            "did:ad:j",
            &ocm_share(&key, "sender.example#key2", &body, at),
            &body,
            now_ms(at),
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("no key with this keyid"), "{err}");

        // Signed by a key that is not the one published under that kid.
        let other = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let err = verify_signature(
            &resolver,
            &db,
            "did:ad:k",
            &ocm_share(&other, "sender.example#key1", &body, at),
            &body,
            now_ms(at),
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("does not verify"), "{err}");

        // A body changed after signing fails its digest before any fetch.
        let fetched = fake.fetched.lock().unwrap().len();
        let err = verify_signature(
            &resolver,
            &db,
            "did:ad:l",
            &parts,
            &share_body("mallory@sender.example"),
            now_ms(at),
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("Content-Digest"), "{err}");
        assert_eq!(fake.fetched.lock().unwrap().len(), fetched);

        // A jwksUri over plain http is refused.
        let plain = peer("https://plain.example", &[("k", &key)]);
        plain.documents.lock().unwrap().insert(
            "https://plain.example/.well-known/ocm".into(),
            json!({"jwksUri": "http://plain.example/jwks"})
                .to_string()
                .into_bytes(),
        );
        let body = share_body("einstein@plain.example");
        let err = verify_signature(
            &KeyResolver::new(plain),
            &db,
            "did:ad:m",
            &ocm_share(&key, "k", &body, at),
            &body,
            now_ms(at),
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("https"), "{err}");
    }

    #[tokio::test]
    async fn ocm_signatures_follow_the_ocm_rules() {
        let db = Db::init_temp("route_auth_ocm_rules").await.unwrap();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let fake = peer("https://sender.example", &[("sender.example#key1", &key)]);
        let resolver = KeyResolver::new(fake.clone());
        let body = share_body("einstein@sender.example");
        let at = std::time::SystemTime::now();

        // Without `content-length` covered: a plain RFC 9421 signature with
        // the tag added by hand is not enough.
        let mut parts = ocm_share(&key, "sender.example#key1", &body, at);
        let url = url::Url::parse("https://receiver.example/ocm/shares").unwrap();
        let untagged = http_signatures::sign_rfc9421(
            &Ed(key.clone()),
            "sender.example#key1",
            &http_signatures::Outbound {
                method: "POST",
                url: &url,
                body: Some(&body),
            },
            at,
        );
        let input = untagged
            .iter()
            .find(|(n, _)| n == "signature-input")
            .unwrap()
            .1
            .clone()
            + ";tag=\"ocm\"";
        for (name, value) in parts.headers.iter_mut() {
            if name == "signature-input" {
                *value = input.clone();
            }
        }
        let err = verify_signature(&resolver, &db, "did:ad:i", &parts, &body, now_ms(at))
            .await
            .unwrap_err();
        assert!(err.0.contains("content-length"), "{err}");

        // Two OCM-tagged signatures: the whole message is refused.
        let mut parts = ocm_share(&key, "sender.example#key1", &body, at);
        for (name, value) in parts.headers.iter_mut() {
            if name == "signature-input" || name == "signature" {
                *value = format!("{value}, {}", value.replacen("sig1=", "sig2=", 1));
            }
        }
        let err = verify_signature(&resolver, &db, "did:ad:i", &parts, &body, now_ms(at))
            .await
            .unwrap_err();
        assert!(err.0.contains("more than one"), "{err}");

        // `senderDomain` and `sender` must agree.
        for (bad, why) in [
            (
                json!({"senderDomain": "other.example", "sender": "a@sender.example"}),
                "differ",
            ),
            (
                json!({"senderDomain": "sender.example/path"}),
                "not a server domain",
            ),
            (
                json!({"senderDomain": "user@sender.example"}),
                "not a server domain",
            ),
        ] {
            let bytes = bad.to_string().into_bytes();
            let err = verify_signature(
                &resolver,
                &db,
                "did:ad:i",
                &ocm_share(&key, "sender.example#key1", &bytes, at),
                &bytes,
                now_ms(at),
            )
            .await
            .unwrap_err();
            assert!(err.0.contains(why), "{bad}: {err}");
        }
        // Neither in the body (Nextcloud 35's notifications): the keyid's
        // domain, whose own discovery and JWK Set must still have the key.
        let bytes = json!({"notificationType": "SHARE_UNSHARED"})
            .to_string()
            .into_bytes();
        let caller = verify_signature(
            &resolver,
            &db,
            "did:ad:i",
            &ocm_share(&key, "sender.example#key1", &bytes, at),
            &bytes,
            now_ms(at),
        )
        .await
        .unwrap();
        assert_eq!(caller["domain"], "sender.example");
        assert_eq!(
            ocm_signer_domain(br#"{"senderDomain":"Sender.Example:8443"}"#, "k").unwrap(),
            "sender.example:8443"
        );
        assert_eq!(
            ocm_signer_domain(br#"{"sender":"a@b@sender.example"}"#, "k").unwrap(),
            "sender.example"
        );
        assert_eq!(
            ocm_signer_domain(b"{}", "https://Cloud.Example:8443/ocm#ecdsa-p256-sha256-1").unwrap(),
            "cloud.example:8443"
        );
        assert_eq!(
            ocm_signer_domain(b"{}", "sender.example#key1").unwrap(),
            "sender.example"
        );
        // The body still wins over the keyid.
        assert_eq!(
            ocm_signer_domain(br#"{"senderDomain":"a.example"}"#, "b.example#k").unwrap(),
            "a.example"
        );
        for bad in ["#key1", "", "user@sender.example#k", "sender.example/x#k"] {
            assert!(ocm_signer_domain(b"{}", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn es256_jwks_from_nextcloud_verify_ecdsa_p256_signatures() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        // An invented, fixed P-256 key (the scalar is just 0x01..0x20).
        let signing = SigningKey::from_slice(&(1..=32).collect::<Vec<u8>>()).unwrap();
        let public = PublicKey::EcdsaP256(*signing.verifying_key());
        let mut jwk = public.to_jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["alg"], "ES256");
        // The shape Nextcloud 35.0.1 publishes at its jwksUri.
        jwk["kid"] = json!("https://cloud.example/ocm#ecdsa-p256-sha256-1");
        let (key, alg) = PublicKey::from_jwk(&jwk).unwrap();
        assert_eq!(alg, Algorithm::EcdsaP256Sha256);
        assert_eq!(alg.rfc9421_name(), "ecdsa-p256-sha256");
        assert_eq!(key, public);
        assert!(key.to_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
        let base = b"\"@method\": POST";
        let signature: Signature = signing.sign(base);
        assert!(key.verify_with(alg, base, &signature.to_bytes()));
        assert!(!key.verify_with(alg, b"other", &signature.to_bytes()));
        assert!(!key.verify_with(Algorithm::Ed25519, base, &signature.to_bytes()));
        for bad in [
            json!({"kty": "EC", "alg": "ES256", "crv": "P-384", "x": jwk["x"], "y": jwk["y"]}),
            json!({"kty": "EC", "alg": "ES384", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]}),
            json!({"kty": "EC", "alg": "ES256", "crv": "P-256", "x": jwk["x"], "y": jwk["x"]}),
            json!({"kty": "EC", "alg": "ES256", "crv": "P-256", "x": "AAAA", "y": jwk["y"]}),
        ] {
            assert!(PublicKey::from_jwk(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn jwks_round_trip_and_refuse_what_ocm_does_not_allow() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public = PublicKey::Ed25519(key.verifying_key());
        let jwk = public.to_jwk();
        assert_eq!(
            PublicKey::from_jwk(&jwk).unwrap(),
            (public, Algorithm::Ed25519)
        );
        for bad in [
            json!({"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}),
            json!({"kty": "OKP", "crv": "X25519", "alg": "Ed25519", "x": jwk["x"]}),
            json!({"kty": "oct", "alg": "HS256", "k": "AAAA"}),
            json!({"kty": "EC", "alg": "ES256", "crv": "P-256"}),
            json!({"kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "x": "AAAA"}),
        ] {
            assert!(PublicKey::from_jwk(&bad).is_err(), "{bad}");
        }
    }
}
