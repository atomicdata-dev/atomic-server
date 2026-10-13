use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

pub use crate::identifiers::{
    ATOMIC_AGENT_PREFIX, ATOMIC_BLOB_PREFIX, ATOMIC_COMMIT_PREFIX, ATOMIC_NODE_PREFIX,
    ATOMIC_PREFIX, DID_AD_AGENT_PREFIX, DID_AD_BLOB_PREFIX, DID_AD_COMMIT_PREFIX,
    DID_AD_NODE_PREFIX, DID_AD_PREFIX,
};

/// The semantic form of a parsed Atomic identifier (`atomic:` or `did:ad:`).
///
/// This keeps callers from repeating string-prefix checks while the broader
/// end-to-end subject typing migration remains incremental. `Other` covers
/// malformed or future forms without changing `Subject::from_raw`'s
/// intentionally permissive parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidKind {
    Resource,
    Agent,
    Commit,
    Blob,
    Property,
    Lens,
    Node,
    Other,
}

/// The Subject of a Resource.
///
/// In Atomic Data, every subject is a URI.
/// They are differentiated by their scheme:
/// - `internal:` for resources hosted on this server.
/// - `http:` or `https:` for resources on other servers.
/// - `atomic:` (canonical) or `did:ad:` (legacy alias) for content-addressed
///   identifiers. Five forms exist: `atomic:agent:{publicKey}`,
///   `atomic:commit:{signature}`, `atomic:blob:{blake3-hex}`,
///   `atomic:node:{nodeId}`, and the default `atomic:{genesis}` for Resources.
///   See `docs/src/identifiers.md`.
#[derive(Clone, Debug)]
pub enum Subject {
    /// Internal representation for local data.
    /// Format: `internal:/path` (root) or `internal:sub:/path` (tenant).
    Internal {
        url: Url,
        /// Drive shortname (used for subdomain routing).
        subdomain: Option<String>,
    },
    /// External resource identifier (usually over HTTP).
    External(Url),
    /// Content-addressed identifier (`atomic:` or legacy `did:ad:`), including
    /// resources, agents, commits, blobs, and nodes. Contains an optional drive
    /// routing hint.
    Did {
        url: Url,
        drive_hint: Option<String>,
    },
}

/// DID equality is based on the core identifier, without routing query
/// parameters or fragments. For internal and external URLs, the full URL is
/// significant because its query can identify a distinct resource.
impl PartialEq for Subject {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Subject::Did { .. }, Subject::Did { .. }) => self.pure_id() == other.pure_id(),
            _ => self.as_str() == other.as_str(),
        }
    }
}

impl Eq for Subject {}

impl std::hash::Hash for Subject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Subject::Did { .. } => self.pure_id().hash(state),
            _ => self.as_str().hash(state),
        }
    }
}

impl Subject {
    pub fn as_str(&self) -> &str {
        match self {
            Subject::Internal { url, .. } => url.as_str(),
            Subject::External(u) => u.as_str(),
            Subject::Did { url, .. } => url.as_str(),
        }
    }

    /// Returns the drive routing hint (DID or alias) if this is a DID subject.
    pub fn drive_hint(&self) -> Option<&str> {
        match self {
            Subject::Did { drive_hint, .. } => drive_hint.as_deref(),
            _ => None,
        }
    }

    /// Creates a new Internal subject.
    /// subdomain: None for root, Some("sub") for tenant.
    pub fn new_local(path: &str, subdomain: Option<&str>) -> Self {
        let mut path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        if path.len() > 1 && path.ends_with('/') {
            path.pop();
        }
        // The Url::parse might result in internal:path instead of internal:/path
        // if path doesn't start with //, but we want internal:/path
        let mut url = if let Some(s) = subdomain {
            Url::parse(&format!("internal:{}:{}", s, path)).unwrap()
        } else {
            Url::parse(&format!("internal:/{}", &path[1..])).unwrap()
        };

        // Some URL parsers might strip the slash for 'internal:' scheme.
        // We MUST have it for consistent internal subjects.
        //
        // Only for the subdomain-less form. A tenant subject is deliberately
        // `internal:{sub}:/path`, which does not start with `internal:/` and so
        // used to land here too — and the fix-up inserts its slash after the
        // FIRST colon, turning `internal:staging:/drive/x` into
        // `internal:/staging:/drive/x`. That is not a cosmetic difference: the
        // subdomain then reads as part of the path, so `path()` returns
        // `/staging:/drive/x` and `resolve()` emits the subdomain twice
        // (`https://staging.example.com/staging:/drive/x`), while a re-parse
        // sees a leading slash and drops the subdomain entirely. Every tenant
        // subject ever written went through here, which is why stores are full
        // of `internal:/{sub}:/...`.
        if subdomain.is_none()
            && !url.as_str().starts_with("internal:/")
            && url.scheme() == "internal"
        {
            let mut s = url.as_str().to_string();
            if let Some(colon_pos) = s.find(':') {
                s.insert(colon_pos + 1, '/');
                url = Url::parse(&s).expect("Failed to re-parse internal URI with slash");
            }
        }

        Subject::Internal {
            url,
            subdomain: subdomain.map(|s| s.to_string()),
        }
    }

    /// Returns the path part of an Internal subject.
    /// For external subjects, it returns the URL's path.
    pub fn path(&self) -> String {
        match self {
            Subject::Internal { url, .. } => {
                let opaque = url.path();
                if opaque.starts_with('/') {
                    opaque.to_string()
                } else if let Some(slash_pos) = opaque.find('/') {
                    opaque[slash_pos..].to_string()
                } else {
                    "/".to_string()
                }
            }
            Subject::External(u) => u.path().to_string(),
            Subject::Did { .. } => self.as_str().to_string(),
        }
    }

    /// Returns the subdomain part of an Internal subject, if any.
    pub fn subdomain(&self) -> Option<String> {
        match self {
            Subject::Internal { subdomain, .. } => subdomain.clone(),
            _ => None,
        }
    }

    /// Returns a new Subject with the drive_hint set.
    /// Only has an effect on DID subjects.
    pub fn set_drive_hint(&self, drive_hint: String) -> Self {
        match self {
            Subject::Did { url, .. } => {
                let mut u = url.clone();
                // Manually reconstruct query to avoid '+' -> ' ' decoding
                let mut new_query = format!("drive={}", drive_hint);

                if let Some(existing_query) = url.query() {
                    for pair in existing_query.split('&') {
                        if let Some((k, v)) = pair.split_once('=') {
                            if k != "drive" {
                                new_query.push('&');
                                new_query.push_str(k);
                                new_query.push('=');
                                new_query.push_str(v);
                            }
                        } else if !pair.is_empty() {
                            new_query.push('&');
                            new_query.push_str(pair);
                        }
                    }
                }

                u.set_query(Some(&new_query));

                Subject::Did {
                    url: u,
                    drive_hint: Some(drive_hint),
                }
            }
            _ => self.clone(),
        }
    }

    /// Returns true if this is a DID subject.
    pub fn is_did(&self) -> bool {
        matches!(self, Subject::Did { .. })
    }

    /// Classifies Atomic identifiers (`atomic:` or `did:ad:`).
    pub fn did_kind(&self) -> Option<DidKind> {
        let Subject::Did { url, .. } = self else {
            return None;
        };
        crate::identifiers::identifier_kind(url.as_str())
    }

    /// Returns true if this is an unprefixed `atomic:{genesis}` / `did:ad:{genesis}` resource.
    pub fn is_resource_did(&self) -> bool {
        self.did_kind() == Some(DidKind::Resource)
    }

    /// Returns true if this is an Agent subject (`atomic:agent:` / `did:ad:agent:`).
    pub fn is_agent_did(&self) -> bool {
        self.did_kind() == Some(DidKind::Agent)
    }

    /// Returns true if this is a Commit subject (`atomic:commit:` / `did:ad:commit:`).
    pub fn is_commit_did(&self) -> bool {
        self.did_kind() == Some(DidKind::Commit)
    }

    /// Returns true if this is a Blob subject (`atomic:blob:` / `did:ad:blob:`).
    pub fn is_blob_did(&self) -> bool {
        self.did_kind() == Some(DidKind::Blob)
    }

    /// Returns true if this is a Node subject (`atomic:node:` / `did:ad:node:`).
    pub fn is_node_did(&self) -> bool {
        self.did_kind() == Some(DidKind::Node)
    }

    /// If this is a blob subject, returns the hex-encoded BLAKE3 hash
    /// (query / fragment stripped). Returns `None` for any other variant.
    pub fn blob_hash_hex(&self) -> Option<&str> {
        match self {
            Subject::Did { url, .. } => crate::identifiers::blob_hash_hex(url.as_str()),
            _ => None,
        }
    }

    /// Agent public key, if this is an agent identifier.
    pub fn agent_public_key(&self) -> Option<&str> {
        match self {
            Subject::Did { url, .. } => crate::identifiers::agent_public_key(url.as_str()),
            _ => None,
        }
    }

    /// Commit signature, if this is a commit identifier.
    pub fn commit_signature(&self) -> Option<&str> {
        match self {
            Subject::Did { url, .. } => crate::identifiers::commit_signature(url.as_str()),
            _ => None,
        }
    }

    /// Node id, if this is a node identifier.
    pub fn node_id(&self) -> Option<&str> {
        match self {
            Subject::Did { url, .. } => crate::identifiers::node_id(url.as_str()),
            _ => None,
        }
    }

    /// Construct an `atomic:blob:` subject from a 32-byte BLAKE3 hash.
    /// Used on the receiving end of `BLOB_REQUEST`/`BLOB_RESPONSE` frames,
    /// which carry the raw bytes rather than the identifier form.
    pub fn from_blob_hash(hash: &[u8; 32]) -> Self {
        let mut hex = String::with_capacity(ATOMIC_BLOB_PREFIX.len() + 64);
        hex.push_str(ATOMIC_BLOB_PREFIX);
        for byte in hash {
            // Inline lowercase-hex; avoids pulling in the `hex` crate just for this.
            hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            hex.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
        }
        Subject::Did {
            url: Url::parse(&hex).expect("valid atomic:blob: URL"),
            drive_hint: None,
        }
    }

    /// Returns true if this is an internal subject (mapped to the server's base domain).
    pub fn is_internal(&self) -> bool {
        matches!(self, Subject::Internal { .. })
    }

    /// Returns true if this is an external subject (not mapped to the server's base domain).
    pub fn is_external(&self) -> bool {
        matches!(self, Subject::External(_))
    }

    /// Returns true if this subject is local to the server (Internal or Did).
    /// External subjects are not considered local.
    pub fn is_local(&self) -> bool {
        matches!(self, Subject::Internal { .. } | Subject::Did { .. })
    }

    /// Resolves the Subject to an absolute URL string based on the provided origin.
    /// If it's an `Internal` subject, it swaps the `internal:` scheme for the `origin`.
    pub fn resolve(&self, origin: &str) -> String {
        match self {
            Subject::Internal { url, subdomain } => {
                let path = self.path();
                let trimmed_origin = origin.trim_end_matches('/');

                let mut resolved = if let Some(s) = subdomain {
                    if let Some(pos) = trimmed_origin.find("://") {
                        let (proto, rest) = trimmed_origin.split_at(pos + 3);
                        format!("{}{}.{}{}", proto, s, rest, path)
                    } else {
                        format!("{}.{}{}", s, trimmed_origin, path)
                    }
                } else {
                    format!("{}{}", trimmed_origin, path)
                };

                if let Some(q) = url.query() {
                    resolved.push('?');
                    resolved.push_str(q);
                }
                if let Some(f) = url.fragment() {
                    resolved.push('#');
                    resolved.push_str(f);
                }
                resolved
            }
            Subject::External(u) => u.to_string(),
            Subject::Did { url, .. } => url.to_string(),
        }
    }

    /// Undoes [Subject::resolve] for a subject this server serves itself.
    ///
    /// Resources are stored — and the query index is keyed — by the raw
    /// `internal:` subject, but they are localized to absolute URLs on the way
    /// out ([crate::serialize]). A client therefore only ever sees
    /// `https://example.com/x`, and echoes exactly that back when it filters on
    /// a subject-valued property such as `parent`. Compared byte-for-byte
    /// against the stored `internal:/x`, it never matches, and the query
    /// silently returns nothing.
    ///
    /// Returns `None` — leave the caller's string alone — for anything that is
    /// not one of ours:
    ///   - not an absolute URL at all (a plain string filter value, which
    ///     [Subject::from_raw] would otherwise happily turn into a bogus
    ///     `internal:` subject via its trailing path fallback),
    ///   - a `did:` subject, which is already globally addressable,
    ///   - another server's URL, or the shared `atomicdata.dev` vocabulary,
    ///     which stays absolute even on `atomicdata.dev` itself.
    ///
    /// Idempotent: an `internal:` string passed in comes back unchanged, so
    /// callers that normalize twice — or that receive an already-internal
    /// value from an in-process caller — are unaffected.
    pub fn delocalize(raw: &str, base_domain: Option<&str>) -> Option<String> {
        // Guard the fallback in `from_raw`: it treats an unparseable string as
        // a local path, so without this a filter for the literal value "hello"
        // would be rewritten to `internal:/hello`.
        Url::parse(raw).ok()?;

        match Subject::from_raw(raw, base_domain) {
            internal @ Subject::Internal { .. } => Some(internal.to_string()),
            Subject::External(_) | Subject::Did { .. } => None,
        }
    }

    /// The `atomicdata.dev` namespaces that [crate::urls] hardcodes as absolute
    /// `const` strings — the shared vocabulary every Atomic server refers to by
    /// absolute URL.
    ///
    /// These must never be localized, *including on `atomicdata.dev` itself*.
    /// Code looks properties and classes up by these exact constants
    /// (`urls::PUBLIC_KEY`, ...), so if a store localized them to `internal:/...`
    /// the constants would stop resolving and every validation against a
    /// built-in class would fail with "Property internal:/properties/publicKey
    /// missing. Is required in class internal:/classes/Agent".
    ///
    /// On any server other than `atomicdata.dev` this is a no-op: those URLs
    /// already don't match the base domain, so they stay [Subject::External].
    ///
    /// Prefix-matched, so it covers nested paths like
    /// `/ontology/server/property/status`. Compared without a scheme so both
    /// `http://` and `https://` forms are caught.
    const CANONICAL_VOCABULARY_PREFIXES: &'static [&'static str] = &[
        "atomicdata.dev/properties/",
        "atomicdata.dev/classes/",
        "atomicdata.dev/datatypes/",
        // Singular variants — a handful of older constants use these.
        "atomicdata.dev/class/",
        "atomicdata.dev/property/",
        "atomicdata.dev/methods/",
        "atomicdata.dev/ontology/",
        // The AI-message ontology lives under a ULID drive rather than a named
        // namespace, but `urls::TEXT_PART` / `urls::REASONING_PART` still point
        // at it by absolute URL.
        "atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/",
    ];

    /// Exact canonical resources outside the vocabulary namespaces above.
    ///
    /// Deliberately NOT a `/agents/` prefix rule: `urls::PUBLIC_AGENT` is the
    /// only canonical agent, while a real `atomicdata.dev` store holds
    /// thousands of genuine user agents under that namespace which must
    /// localize like any other user data.
    const CANONICAL_VOCABULARY_EXACT: &'static [&'static str] =
        &["atomicdata.dev/agents/publicAgent"];

    /// Whether `s` is part of the shared atomicdata.dev vocabulary and so must
    /// keep its absolute URL. See [Self::CANONICAL_VOCABULARY_PREFIXES].
    fn is_canonical_vocabulary(s: &str) -> bool {
        let bare = s
            .trim_start_matches("https://")
            .trim_start_matches("http://");

        Self::CANONICAL_VOCABULARY_PREFIXES
            .iter()
            .any(|p| bare.starts_with(p))
            || Self::CANONICAL_VOCABULARY_EXACT
                .iter()
                .any(|e| bare == *e || bare.trim_end_matches('/') == *e)
    }

    /// Normalizes a subject string based on a base domain.
    /// If the URL matches the base domain or its subdomains, it becomes an Internal subject.
    pub fn from_raw(s: &str, base_domain: Option<&str>) -> Self {
        if crate::identifiers::is_identifier_path_form(s) {
            return Subject::from_raw(&s[1..], base_domain);
        }

        let s = if s.len() > 1 && s.ends_with('/') {
            if s.starts_with("internal:") {
                // If it's internal:/, don't strip. internal:/path/ -> internal:/path
                if s.len() > 10 {
                    &s[..s.len() - 1]
                } else {
                    s
                }
            } else {
                &s[..s.len() - 1]
            }
        } else {
            s
        };

        if crate::identifiers::is_atomic_identifier(s) {
            if let Ok(u) = Url::parse(s) {
                let mut drive_hint = None;
                if let Some(query) = u.query() {
                    for pair in query.split('&') {
                        if let Some((k, v)) = pair.split_once('=') {
                            if k == "drive" {
                                drive_hint = Some(v.to_string());
                                break;
                            }
                        }
                    }
                }
                return Subject::Did { url: u, drive_hint };
            }
        }

        if s.starts_with("internal:") {
            // Repair the historical mangled tenant spelling on the way in.
            //
            // `new_local` used to emit `internal:/{sub}:/path` (see the note
            // there), and stores are full of it. Read literally the subdomain
            // is lost and the colon becomes part of the path, so the subject
            // resolves to the wrong host — which is how a tenant's drives
            // became unreachable. Normalising here fixes those rows as they are
            // read, with no store rewrite.
            //
            // Deliberately narrow: the segment must be non-empty, contain no
            // slash, and be followed by exactly `:/`. A genuine path segment
            // ending in a colon before a slash would be misread, but
            // `internal:/a:/b` is not a shape anything produces on purpose.
            if let Some(rest) = s.strip_prefix("internal:/") {
                if let Some(colon_pos) = rest.find(':') {
                    let sub = &rest[..colon_pos];
                    if !sub.is_empty() && !sub.contains('/') && rest[colon_pos..].starts_with(":/")
                    {
                        // Rebuild from the original string so any query or
                        // fragment survives.
                        if let Ok(u) = Url::parse(&format!("internal:{}", rest)) {
                            return Subject::Internal {
                                url: u,
                                subdomain: Some(sub.to_string()),
                            };
                        }
                    }
                }
            }

            if let Ok(u) = Url::parse(s) {
                let opaque = u.path();
                // `internal:{sub}:/path` — the subdomain ends at the colon, not
                // at the first slash. Taking it to the slash kept the trailing
                // colon (`"staging:"`), which then failed every comparison
                // against a real subdomain.
                let subdomain = if opaque.starts_with('/') {
                    None
                } else if let Some(colon_pos) = opaque.find(':') {
                    Some(opaque[..colon_pos].to_string())
                } else if let Some(slash_pos) = opaque.find('/') {
                    Some(opaque[..slash_pos].to_string())
                } else {
                    Some(opaque.to_string())
                };

                return Subject::Internal { url: u, subdomain };
            }
        }

        if s.starts_with('/') {
            return Subject::new_local(s, None);
        }

        if let Ok(u) = Url::parse(s) {
            // Shared vocabulary keeps its absolute URL even when it matches the
            // base domain — see `CANONICAL_VOCABULARY_PREFIXES`.
            if Self::is_canonical_vocabulary(s) {
                return Subject::External(u);
            }

            if let Some(base) = base_domain {
                let trimmed_base = base
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_end_matches('/');

                let host = u.host_str().unwrap_or("");
                let authority = if let Some(port) = u.port() {
                    format!("{}:{}", host, port)
                } else {
                    host.to_string()
                };

                let path_and_query = if let Some(q) = u.query() {
                    format!("{}?{}", u.path(), q)
                } else {
                    u.path().to_string()
                };

                if authority == trimmed_base {
                    return Subject::new_local(&path_and_query, None);
                }
                if authority.ends_with(&format!(".{}", trimmed_base)) {
                    let subdomain = &authority[..authority.len() - trimmed_base.len() - 1];
                    return Subject::new_local(&path_and_query, Some(subdomain));
                }
            }
            return Subject::External(u);
        }

        // Fallback: treat as local path
        Subject::new_local(s, None)
    }

    /// Returns a new Subject without query parameters or fragments.
    pub fn without_params(&self) -> Self {
        match self {
            Subject::Internal { url, subdomain } => {
                let mut u = url.clone();
                u.set_query(None);
                u.set_fragment(None);
                Subject::Internal {
                    url: u,
                    subdomain: subdomain.clone(),
                }
            }
            Subject::External(u) => {
                let mut u = u.clone();
                u.set_query(None);
                u.set_fragment(None);
                Subject::External(u)
            }
            Subject::Did { url, .. } => {
                let mut u = url.clone();
                u.set_query(None);
                u.set_fragment(None);
                Subject::Did {
                    url: u,
                    drive_hint: None,
                }
            }
        }
    }

    /// Returns the core identifier as a String, stripping any query parameters or fragments.
    /// This is used for database keys and cryptographic signatures.
    pub fn pure_id(&self) -> String {
        match self {
            Subject::Internal { url, .. } => {
                let mut u = url.clone();
                u.set_query(None);
                u.set_fragment(None);
                let mut s = u.to_string();
                if s.len() > 10 && s.ends_with('/') {
                    s.pop();
                }
                s
            }
            Subject::External(url) => {
                let mut u = url.clone();
                u.set_query(None);
                u.set_fragment(None);
                u.to_string()
            }
            Subject::Did { url, .. } => {
                let mut u = url.clone();
                u.set_query(None);
                u.set_fragment(None);
                let mut s = u.to_string();
                if s.ends_with('/') {
                    s.pop();
                }
                crate::identifiers::canonicalize_scheme(&s)
            }
        }
    }

    /// Whether this subject denotes the given `drive` itself, or a resource
    /// that lives within it. Used to scope drive-wide commit fan-out so a
    /// commit only ever reaches subscribers of its own drive.
    ///
    /// Identity is normalized (`pure_id`), so query hints and trailing slashes
    /// never cause a false negative. Beyond identity:
    /// - **URL subjects** (internal/external) belong to a drive when they share
    ///   its identity prefix up to a path boundary — `…/d/x` is within `…/d`,
    ///   but `…/d2` is *not* within `…/d` (the boundary check is what a raw
    ///   `starts_with` lacks).
    /// - **DID subjects** encode no hierarchy in their id, so they can only
    ///   match by identity. A caller testing a DID *resource*'s membership
    ///   should pass that resource's `drive` propval as `self`, not the
    ///   resource subject itself.
    pub fn is_within_drive(&self, drive: &Subject) -> bool {
        let me = self.pure_id();
        let root = drive.pure_id();

        if me == root {
            return true;
        }

        // DID ids are opaque — no path hierarchy to descend into.
        if matches!(self, Subject::Did { .. }) || matches!(drive, Subject::Did { .. }) {
            return false;
        }

        // Same origin + the drive's path is a path-segment prefix of ours.
        me.starts_with(&root) && me.as_bytes().get(root.len()) == Some(&b'/')
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<String> for Subject {
    fn from(s: String) -> Self {
        Subject::from_raw(&s, None)
    }
}

impl From<&str> for Subject {
    fn from(s: &str) -> Self {
        Subject::from_raw(s, None)
    }
}

impl From<Subject> for String {
    fn from(s: Subject) -> Self {
        s.to_string()
    }
}

impl PartialEq<&str> for Subject {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Subject> for &str {
    fn eq(&self, other: &Subject) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<String> for Subject {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<Subject> for String {
    fn eq(&self, other: &Subject) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Serialize for Subject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Subject::from(s))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A tenant subject must survive being written down and read back.
    ///
    /// It did not. `new_local` emitted `internal:/{sub}:/path` — the fix-up for
    /// parsers that strip the slash after `internal:` fired on the tenant form
    /// too and inserted one after the first colon. The subdomain then read as
    /// part of the path, so `resolve` emitted it twice and a re-parse dropped
    /// it altogether, pointing the subject at the wrong host.
    #[test]
    fn tenant_subjects_round_trip() {
        let base = Some("example.com");
        let origin = "https://example.com";

        let made = Subject::new_local("/drive/abc", Some("tenant"));
        assert_eq!(made.as_str(), "internal:tenant:/drive/abc");
        assert_eq!(made.subdomain().as_deref(), Some("tenant"));
        assert_eq!(made.path(), "/drive/abc");
        assert_eq!(made.resolve(origin), "https://tenant.example.com/drive/abc");

        // Written down and read back: same subject, same resolution.
        let reparsed = Subject::from_raw(made.as_str(), base);
        assert_eq!(reparsed.as_str(), made.as_str());
        assert_eq!(reparsed.subdomain().as_deref(), Some("tenant"));
        assert_eq!(reparsed.resolve(origin), made.resolve(origin));

        // And arriving as a URL agrees with both.
        let from_url = Subject::from_raw("https://tenant.example.com/drive/abc", base);
        assert_eq!(from_url.as_str(), made.as_str());
        assert_eq!(from_url.resolve(origin), made.resolve(origin));
    }

    /// Stores already contain the mangled spelling, so it has to be readable.
    /// Normalising on parse repairs those rows without rewriting the store.
    #[test]
    fn the_mangled_tenant_spelling_is_repaired_on_read() {
        let repaired =
            Subject::from_raw("internal:/staging:/drive/ckggjb1d3md", Some("example.com"));

        assert_eq!(repaired.as_str(), "internal:staging:/drive/ckggjb1d3md");
        assert_eq!(repaired.subdomain().as_deref(), Some("staging"));
        assert_eq!(repaired.path(), "/drive/ckggjb1d3md");
        assert_eq!(
            repaired.resolve("https://example.com"),
            "https://staging.example.com/drive/ckggjb1d3md"
        );
    }

    /// The repair must not swallow ordinary subjects.
    #[test]
    fn plain_internal_subjects_are_left_alone() {
        let base = Some("example.com");

        for raw in [
            "internal:/",
            "internal:/drive/abc",
            "internal:/agents/QmfpRIBn2JYEatT0MjSkMNoBJzstz19orwnT5oT2rcQ=",
        ] {
            let s = Subject::from_raw(raw, base);
            assert_eq!(s.as_str(), raw, "{raw} should be unchanged");
            assert_eq!(s.subdomain(), None, "{raw} has no subdomain");
        }
    }

    /// A query or fragment must survive the repair.
    #[test]
    fn the_repair_keeps_query_and_fragment() {
        let s = Subject::from_raw("internal:/staging:/drive/abc?page=2", Some("example.com"));

        assert_eq!(
            s.resolve("https://example.com"),
            "https://staging.example.com/drive/abc?page=2"
        );
    }

    #[test]
    fn test_did_parsing_and_resolution() {
        let origin = "http://localhost:9883";
        let did = "did:ad:C1PsEdNI7K1D4N2dMVaaHwxwevsl/6pL8rSdejvD+ori3rZb6eafyTgeEVKCHPG0Po3SBQyT7Ea/7pB/Fl8PCg==";
        let with_slash = format!("/{}", did);

        let subject_from_did = Subject::from_raw(did, None);
        assert!(matches!(subject_from_did, Subject::Did { .. }));
        assert_eq!(subject_from_did.as_str(), did);
        assert_eq!(subject_from_did.resolve(origin), did);
        assert_eq!(
            subject_from_did.pure_id(),
            crate::identifiers::canonicalize_scheme(did)
        );

        let subject_from_slash = Subject::from_raw(&with_slash, None);
        assert!(matches!(subject_from_slash, Subject::Did { .. }));
        assert_eq!(subject_from_slash.as_str(), did);
        assert_eq!(subject_from_slash.resolve(origin), did);
    }

    #[test]
    fn test_agent_did_parsing() {
        let agent_did = "did:ad:agent:sLKUH+UJiTMm+dxzbAFf1h3gDonWQaOgU++2HD1bueQ=";
        let subject = Subject::from_raw(agent_did, None);
        assert!(
            matches!(subject, Subject::Did { .. }),
            "Expected Subject::Did, got {:?}",
            subject
        );
        assert_eq!(
            subject.as_str(),
            agent_did,
            "as_str() must preserve + and = without percent-encoding"
        );
        assert!(subject.is_agent_did());
    }

    #[test]
    fn test_did_kind_distinguishes_identifier_forms() {
        let cases = [
            ("did:ad:resource", DidKind::Resource),
            ("did:ad:agent:key", DidKind::Agent),
            ("did:ad:commit:signature", DidKind::Commit),
            ("did:ad:blob:hash", DidKind::Blob),
            ("did:ad:prop:hash", DidKind::Property),
            ("did:ad:lens:hash", DidKind::Lens),
            ("did:ad:node:node-id", DidKind::Node),
            ("did:ad:future:value", DidKind::Other),
        ];

        for (raw, expected) in cases {
            assert_eq!(Subject::from_raw(raw, None).did_kind(), Some(expected));
            let atomic = raw.replacen("did:ad:", "atomic:", 1);
            assert_eq!(
                Subject::from_raw(&atomic, None).did_kind(),
                Some(expected),
                "{atomic}"
            );
        }
        assert_eq!(
            Subject::from_raw("did:key:abc", None).did_kind(),
            None,
            "non-Atomic DID methods are not classified as Atomic identifiers"
        );
        assert_eq!(
            Subject::from_raw("https://example.com", None).did_kind(),
            None
        );
    }

    #[test]
    fn test_did_routing_hint_does_not_affect_equality_or_hash() {
        let pure = Subject::from_raw("did:ad:resource", None);
        let routed = Subject::from_raw(
            "did:ad:resource?drive=did:ad:drive&transport=iroh#peer",
            None,
        );

        assert_eq!(pure, routed);

        let mut subjects = HashSet::new();
        subjects.insert(pure);
        subjects.insert(routed);
        assert_eq!(
            subjects.len(),
            1,
            "equal DID subjects must hash identically"
        );
    }

    #[test]
    fn test_http_query_remains_part_of_identity() {
        let first = Subject::from_raw("https://example.com/query?page=1", None);
        let second = Subject::from_raw("https://example.com/query?page=2", None);
        assert_ne!(first, second);
    }

    #[test]
    fn test_blob_did_parsing() {
        let blob_did =
            "did:ad:blob:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let subject = Subject::from_raw(blob_did, None);

        assert!(matches!(subject, Subject::Did { .. }));
        assert!(subject.is_blob_did());
        assert!(!subject.is_agent_did());
        assert!(!subject.is_commit_did());
        assert_eq!(
            subject.blob_hash_hex(),
            Some("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );

        // Roundtrip via raw bytes.
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let from_bytes = Subject::from_blob_hash(&bytes);
        assert!(from_bytes.is_blob_did());
        assert_eq!(
            from_bytes.blob_hash_hex(),
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );

        // Drive hint is preserved on a blob DID, hash extraction strips it.
        let with_drive = format!("{}?drive=did:ad:abc", blob_did);
        let routed = Subject::from_raw(&with_drive, None);
        assert!(routed.is_blob_did());
        assert_eq!(routed.drive_hint(), Some("did:ad:abc"));
        assert_eq!(
            routed.blob_hash_hex(),
            Some("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
    }

    #[test]
    fn test_did_drive_hint_parsing() {
        let did_with_drive = "did:ad:123?drive=abc";
        let subject = Subject::from_raw(did_with_drive, None);

        assert!(matches!(subject, Subject::Did { .. }));
        assert_eq!(subject.drive_hint(), Some("abc"));
        assert_eq!(subject.pure_id(), "atomic:123");
    }

    #[test]
    fn atomic_and_did_ad_are_the_same_identity() {
        let legacy = Subject::from_raw("did:ad:resource", None);
        let canonical = Subject::from_raw("atomic:resource", None);
        assert_eq!(legacy, canonical);
        assert_eq!(legacy.pure_id(), "atomic:resource");
        assert_eq!(canonical.pure_id(), "atomic:resource");
        assert_eq!(legacy.did_kind(), Some(DidKind::Resource));
        assert_eq!(canonical.did_kind(), Some(DidKind::Resource));

        let agent = Subject::from_raw("atomic:agent:pk", None);
        assert!(agent.is_agent_did());
        assert_eq!(agent.agent_public_key(), Some("pk"));
        assert_eq!(
            Subject::from_raw("did:ad:agent:pk", None).agent_public_key(),
            Some("pk")
        );
    }

    #[test]
    fn test_is_within_drive() {
        let base = Some("localhost:9883");
        let drive = Subject::from_raw("https://localhost:9883/drive1", base);

        // Identity (incl. trailing slash / query-hint normalization).
        assert!(drive.is_within_drive(&drive));
        assert!(Subject::from_raw("https://localhost:9883/drive1/", base).is_within_drive(&drive));

        // Genuine descendant lives within the drive.
        assert!(
            Subject::from_raw("https://localhost:9883/drive1/table/row", base)
                .is_within_drive(&drive)
        );

        // Sibling that merely shares a string prefix is NOT within — the bug a
        // bare `starts_with` would let through.
        assert!(!Subject::from_raw("https://localhost:9883/drive12", base).is_within_drive(&drive));

        // DID drives match only by identity — no hierarchy descent.
        let did_drive = Subject::from_raw("did:ad:drive1", None);
        assert!(did_drive.is_within_drive(&did_drive));
        assert!(
            Subject::from_raw("did:ad:drive1?drive=x", None).is_within_drive(&did_drive),
            "drive_hint / query must not defeat identity"
        );
        assert!(!Subject::from_raw("did:ad:other", None).is_within_drive(&did_drive));
        // A DID resource subject is never `within` a DID drive by its own id.
        assert!(!Subject::from_raw("did:ad:resource", None).is_within_drive(&did_drive));
    }

    #[test]
    fn test_internal_resolution() {
        let origin = "http://localhost:9883";
        let path = "/test";
        let subject = Subject::new_local(path, None);
        assert_eq!(subject.resolve(origin), format!("{}{}", origin, path));
    }

    #[test]
    fn test_resolution_with_query() {
        let origin = "http://localhost:9883";
        let raw = "/test?query=value";
        let subject = Subject::from_raw(raw, None);
        // If this fails, we know resolve() is losing query params
        assert_eq!(subject.resolve(origin), format!("{}{}", origin, raw));
    }

    #[test]
    fn test_from_raw_http_url_preserves_query_params() {
        // Regression test: full HTTP URL with query params must be preserved
        // when converted to an Internal subject (e.g. WS GET for /query endpoint).
        let origin = "http://localhost:9883";
        let raw =
            "http://localhost:9883/query?page_size=30&property=https%3A%2F%2Fexample.com%2Fprop";
        let subject = Subject::from_raw(raw, Some("localhost:9883"));
        assert!(
            matches!(subject, Subject::Internal { .. }),
            "Expected Internal subject"
        );
        assert_eq!(subject.resolve(origin), raw);
    }

    /// On `atomicdata.dev` itself, the shared vocabulary must NOT localize.
    ///
    /// `urls::PUBLIC_KEY` and friends are hardcoded absolute constants, so if
    /// these became `internal:/properties/...` every lookup by constant would
    /// miss and validation against built-in classes would fail with
    /// "Property internal:/properties/publicKey missing. Is required in class
    /// internal:/classes/Agent" — which is exactly what a real migration of the
    /// atomicdata.dev store hit.
    #[test]
    fn canonical_vocabulary_is_not_localized_on_its_own_host() {
        let base = Some("https://atomicdata.dev");

        for raw in [
            crate::urls::PUBLIC_KEY,
            crate::urls::DESCRIPTION,
            crate::urls::AGENT,
            crate::urls::INSERT,
            crate::urls::URL,
            crate::urls::BOOKMARK,
            crate::urls::STATUS,
            crate::urls::TEXT_PART,
            crate::urls::PUBLIC_AGENT,
            "https://atomicdata.dev/datatypes/string",
        ] {
            assert!(
                matches!(Subject::from_raw(raw, base), Subject::External(_)),
                "{raw} must stay External on its own host, got {:?}",
                Subject::from_raw(raw, base)
            );
        }
    }

    /// The carve-out must not swallow real user data that merely lives under a
    /// similar path. `atomicdata.dev` hosts thousands of genuine user agents,
    /// and only `publicAgent` is canonical.
    #[test]
    fn user_data_on_atomicdata_dev_still_localizes() {
        let base = Some("https://atomicdata.dev");

        for raw in [
            "https://atomicdata.dev/agents/QmfpRIBn2JYEatT0MjSkMNoBJzstz19orwnT5oT2rcQ=",
            "https://atomicdata.dev/01jd9n5hc9dpwm8ygf2vh3mprf",
            "https://atomicdata.dev/commits/abc123",
            "https://atomicdata.dev/drive/xyz",
            "https://atomicdata.dev/",
        ] {
            assert!(
                matches!(Subject::from_raw(raw, base), Subject::Internal { .. }),
                "{raw} is user data and must localize, got {:?}",
                Subject::from_raw(raw, base)
            );
        }
    }

    /// The query index is keyed by the stored `internal:` subject, but clients
    /// only ever see the localized URL and filter with that. Without this, a
    /// `parent=` query on a store migrated from the pre-DID era matches
    /// nothing and the sidebar renders empty.
    #[test]
    fn delocalize_undoes_resolve_for_our_own_subjects() {
        let base = Some("https://atomicdata.dev");

        assert_eq!(
            Subject::delocalize("https://atomicdata.dev/", base).as_deref(),
            Some("internal:/")
        );
        assert_eq!(
            Subject::delocalize("https://atomicdata.dev/01jd9n5hc9dpwm8ygf2vh3mprf", base)
                .as_deref(),
            Some("internal:/01jd9n5hc9dpwm8ygf2vh3mprf")
        );
        // Ports are part of the authority, so a dev server on :9883 matches too.
        assert_eq!(
            Subject::delocalize("http://localhost:9883/abc", Some("localhost:9883")).as_deref(),
            Some("internal:/abc")
        );
    }

    #[test]
    fn delocalize_round_trips_with_resolve() {
        let origin = "https://atomicdata.dev";
        for internal in ["internal:/", "internal:/abc", "internal:/abc/def"] {
            let resolved = Subject::from(internal).resolve(origin);
            assert_eq!(
                Subject::delocalize(&resolved, Some(origin)).as_deref(),
                Some(internal),
                "{internal} did not survive resolve -> delocalize (via {resolved})"
            );
        }
    }

    #[test]
    fn delocalize_leaves_everything_else_alone() {
        let base = Some("https://atomicdata.dev");

        for raw in [
            // Not a URL at all: a plain string filter value. `from_raw` would
            // turn this into `internal:/hello` via its local-path fallback.
            "hello",
            "some free text",
            "",
            // Already globally addressable.
            "did:ad:drive:abc",
            // Another server.
            "https://example.com/thing",
            // Shared vocabulary stays absolute even on atomicdata.dev itself.
            "https://atomicdata.dev/properties/parent",
            "https://atomicdata.dev/classes/Drive",
            "https://atomicdata.dev/agents/publicAgent",
        ] {
            assert_eq!(
                Subject::delocalize(raw, base),
                None,
                "{raw} must be left untouched"
            );
        }
    }

    #[test]
    fn delocalize_is_idempotent() {
        let base = Some("https://atomicdata.dev");
        // An in-process caller may already hand us the stored form.
        assert_eq!(
            Subject::delocalize("internal:/abc", base).as_deref(),
            Some("internal:/abc")
        );
        let once = Subject::delocalize("https://atomicdata.dev/abc", base).unwrap();
        assert_eq!(Subject::delocalize(&once, base), Some(once.clone()));
    }

    #[test]
    fn delocalize_without_a_base_domain_changes_nothing() {
        // No base domain configured: we cannot know what is ours.
        assert_eq!(
            Subject::delocalize("https://atomicdata.dev/abc", None),
            None
        );
    }
}
