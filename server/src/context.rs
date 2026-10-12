use crate::appstate::AppState;
use crate::errors::AtomicServerError;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use futures::future::{ready, Ready};

#[derive(Clone, Debug)]
pub struct RequestContext {
    /// The full origin, e.g. "https://atomicdata.dev" or "http://localhost:9883"
    pub origin: String,
}

impl RequestContext {
    pub fn new(req: &HttpRequest, appstate: &AppState) -> Self {
        let headers = req.headers();

        let host = headers
            .get("x-forwarded-host")
            .or_else(|| headers.get("host"))
            .and_then(|v| v.to_str().ok());

        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok());

        // The origin is what signed auth proofs (session cookies, bearer
        // tokens, WS AUTH) are bound to, so it must not be whatever the client
        // says it is: a token captured on server B replays on server A if A
        // will compute B's origin from an `X-Forwarded-Host` the attacker
        // sends. Only hosts this server is configured to answer for are taken
        // from the headers; anything else falls back to the configured origin.
        let origin = match host {
            Some(h) if host_is_served_by(h, appstate) => {
                let configured = appstate.config.get_origin();
                let p = proto.unwrap_or(if configured.starts_with("https://") {
                    "https"
                } else {
                    "http"
                });
                format!("{}://{}", p, h)
            }
            _ => appstate.config.get_origin(),
        };

        Self { origin }
    }
}

/// Whether `host` (as sent in `Host` / `X-Forwarded-Host`, port included) is a
/// name this server is configured to serve: the configured domain, a subdomain
/// of the multi-tenant base domain, or a loopback name. A server left on the
/// default domain (`localhost`) has not told us its public name, so it trusts
/// the header as before; that is the unconfigured dev/desktop case, which is
/// reached over the network only when the operator chose to.
pub(crate) fn host_is_served_here(host: &str, opts: &crate::config::Opts) -> bool {
    let hostname = strip_port(host).to_ascii_lowercase();
    if hostname.is_empty()
        || hostname
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')))
    {
        return false;
    }
    let domain = opts.domain.trim().to_ascii_lowercase();
    if domain.is_empty() || domain == "localhost" {
        return true;
    }
    // `*.localhost` is loopback by definition (RFC 6761; browsers resolve it
    // without DNS), which is how the e2e suite and local multi-tenant setups
    // reach one server under several names.
    if hostname == domain
        || matches!(hostname.as_str(), "localhost" | "127.0.0.1" | "[::1]")
        || hostname.ends_with(".localhost")
    {
        return true;
    }
    // `--served-domain-suffix` takes a comma-separated list: a node that is
    // moving from one domain to another answers for both while links to the
    // old one are still around.
    for suffix in opts.base_domain.as_deref().into_iter().chain(
        opts.served_domain_suffix
            .as_deref()
            .unwrap_or("")
            .split(','),
    ) {
        let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        if !suffix.is_empty() && (hostname == suffix || hostname.ends_with(&format!(".{suffix}"))) {
            return true;
        }
    }
    false
}

/// [`host_is_served_here`], or a host this server has a Drive mapping for.
/// A vanity name the control plane routed here (`ontola.atomic.place`) need
/// not sit under any configured suffix: the mapping itself says this server
/// answers for it, and only the control plane or an admin can install one.
pub(crate) fn host_is_served_by(host: &str, appstate: &AppState) -> bool {
    host_is_served_here(host, &appstate.config.opts)
        || appstate.store.has_drive_mapping(strip_port(host))
}

/// `host:port` -> `host`, leaving IPv6 literals (`[::1]:9883`) intact.
pub(crate) fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    }
}

impl FromRequest for RequestContext {
    type Error = AtomicServerError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let appstate = match req.app_data::<actix_web::web::Data<AppState>>() {
            Some(data) => data,
            None => return ready(Err(AtomicServerError::from("AppState not found"))),
        };

        ready(Ok(RequestContext::new(req, appstate)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn opts(domain: &str, base: Option<&str>) -> crate::config::Opts {
        let mut args = vec!["atomic-server", "--domain", domain];
        if let Some(b) = base {
            args.push("--base-domain");
            args.push(b);
        }
        crate::config::Opts::parse_from(args)
    }

    fn opts_with_served_suffix(domain: &str, suffix: &str) -> crate::config::Opts {
        crate::config::Opts::parse_from([
            "atomic-server",
            "--domain",
            domain,
            "--served-domain-suffix",
            suffix,
        ])
    }

    /// A managed node serving hosted vanity subdomains gets the suffix without
    /// `--base-domain`, so the request origin follows the hostname the visitor
    /// used while the store's subject normalization stays as it was.
    #[test]
    fn a_served_domain_suffix_accepts_tenants_without_a_base_domain() {
        let o = opts_with_served_suffix("node1.atomicserver.eu", "atomicserver.eu");
        assert!(o.base_domain.is_none());

        assert!(host_is_served_here("acme.atomicserver.eu", &o));
        assert!(host_is_served_here("ACME.AtomicServer.eu:443", &o));
        // The node's own name and the apex are both names it answers for.
        assert!(host_is_served_here("node1.atomicserver.eu", &o));
        assert!(host_is_served_here("atomicserver.eu", &o));

        // The same near-misses the base-domain path rejects.
        assert!(!host_is_served_here("notatomicserver.eu", &o));
        assert!(!host_is_served_here("atomicserver.eu.evil.example", &o));
        assert!(!host_is_served_here("evil.example", &o));
    }

    /// A node moving between domains is given both, comma separated, and
    /// answers for names under either.
    #[test]
    fn several_served_domain_suffixes_are_all_served() {
        let o = opts_with_served_suffix("node1.atomicserver.eu", "atomicserver.eu, atomic.place");

        assert!(host_is_served_here("node1.atomicserver.eu", &o));
        assert!(host_is_served_here("acme.atomicserver.eu", &o));
        assert!(host_is_served_here("node1.atomic.place", &o));
        assert!(host_is_served_here("NODE1.Atomic.Place:443", &o));

        assert!(!host_is_served_here("notatomic.place", &o));
        assert!(!host_is_served_here("atomic.place.evil.example", &o));
        assert!(!host_is_served_here("evil.example", &o));
    }

    #[test]
    fn configured_domain_and_tenants_are_served_here() {
        let o = opts("atomicdata.dev", Some("atomicserver.eu"));
        assert!(host_is_served_here("atomicdata.dev", &o));
        assert!(host_is_served_here("AtomicData.dev:443", &o));
        assert!(host_is_served_here("joep.atomicserver.eu", &o));
        assert!(host_is_served_here("localhost:9883", &o));
        assert!(host_is_served_here("[::1]:9883", &o));
    }

    #[test]
    fn dot_localhost_names_are_loopback() {
        // CI serves the SPA at `atomic.localhost` for a server whose domain
        // is `atomic`, so the browser signs for the former.
        let o = opts("atomic", None);
        assert!(host_is_served_here("atomic.localhost:9883", &o));
        assert!(host_is_served_here("tenant.atomic.localhost", &o));
        assert!(!host_is_served_here("localhost.evil.example", &o));
    }

    #[test]
    fn foreign_hosts_fall_back_to_the_configured_origin() {
        let o = opts("atomicdata.dev", Some("atomicserver.eu"));
        assert!(!host_is_served_here("evil.example", &o));
        assert!(!host_is_served_here("atomicdata.dev.evil.example", &o));
        assert!(!host_is_served_here("notatomicserver.eu", &o));
        assert!(!host_is_served_here("a b", &o));
        assert!(!host_is_served_here("", &o));
    }

    #[test]
    fn default_domain_trusts_the_header() {
        let o = opts("localhost", None);
        assert!(host_is_served_here("192.168.1.5:9883", &o));
    }
}
