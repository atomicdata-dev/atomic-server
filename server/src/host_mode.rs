//! Who may put a *new* workspace on this node.
//!
//! A stock node admits every drive ([`atomic_lib::sync::policy::OpenPolicy`]).
//! On a laptop that is right: the person at the keyboard is the only one who
//! can reach it. On a public address it means the welcome screen is an open
//! registration form for free storage on somebody else's disk.
//!
//! [`HostMode::Owner`] closes that. It does not touch reading: what the owner
//! shared stays shared, invited collaborators keep working, and ACL on existing
//! resources is unchanged. The only new refusal is *enrolling a drive this node
//! has never hosted*.
//!
//! # Why the mode is not inferred from the domain
//!
//! The obvious heuristic — "`ATOMIC_DOMAIN` is not localhost, so we must be
//! public" — is wrong in the direction that costs data. `ATOMIC_DOMAIN`
//! defaults to `localhost` and only ever has to be correct for building links
//! and for the LetsEncrypt challenge. Behind Docker with nginx/Caddy/Traefik in
//! front, or behind a Cloudflare/Tailscale tunnel, the process never learns its
//! public name: the domain still reads `localhost` while the whole internet can
//! reach it. Inferring "Open" there would hand out exactly the guarantee we
//! could not keep.
//!
//! So the mode is decided by explicit configuration only, and the reachability
//! signals below are used for *one* thing: deciding whether to warn. A wrong
//! guess then costs a line of log noise instead of a stranger's workspace.

use crate::errors::AtomicServerResult;

/// The identifier prefixes an owner agent may use. Canonical is `atomic:agent:`;
/// `did:ad:agent:` is accepted forever. The owner is named by a public key,
/// never by a URL: an agent identifier needs no server to exist, which is what
/// lets the operator create their identity on a laptop before this node has
/// ever booted.
const AGENT_ID_HINT: &str = "atomic:agent: (or did:ad:agent:)";

/// Whether this node lets a stranger store a workspace here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum HostMode {
    /// Anyone who can reach the node may create a drive on it. The default, and
    /// correct for localhost, a LAN box nobody else is on, and a deliberate
    /// multi-user node.
    Open,
    /// Only the owner agent may enroll a new drive. Everything else — reading
    /// what was shared, collaborating on an invited drive, the owner's other
    /// devices — is unchanged.
    Owner,
}

impl HostMode {
    /// What `/server` reports. Absent on an old node, which clients must read as
    /// [`HostMode::Open`] — that is what an old node does.
    pub fn as_str(self) -> &'static str {
        match self {
            HostMode::Open => "open",
            HostMode::Owner => "owner",
        }
    }

    /// Whether a drive nobody here has seen before may be created by whoever
    /// asks. In Owner mode new drives still appear — but only for the owner, so
    /// the answer to "will you take a drive from anyone" is no.
    pub fn accepts_new_drives(self) -> bool {
        matches!(self, HostMode::Open)
    }
}

/// The resolved decision, and the agent it was resolved for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostModeConfig {
    pub mode: HostMode,
    /// The owner's agent DID. Always `Some` in Owner mode — the mode cannot be
    /// reached without one — and `None` in Open mode.
    pub owner_agent: Option<String>,
}

impl HostModeConfig {
    pub fn is_owner_mode(&self) -> bool {
        matches!(self.mode, HostMode::Owner)
    }

    /// Whether `agent` is the owner. `false` in Open mode: nothing is gated
    /// there, so nothing needs to be the owner.
    pub fn is_owner(&self, agent: &str) -> bool {
        self.owner_agent.as_deref().is_some_and(|owner| {
            atomic_lib::identifiers::canonicalize_scheme(owner)
                == atomic_lib::identifiers::canonicalize_scheme(agent)
        })
    }
}

/// Why we think a stranger might be able to reach this node. Only ever used to
/// decide whether an Open node gets a warning; never to pick the mode.
///
/// Every signal here is a sign of *intent to publish*, not of mere binding. The
/// bind address deliberately is not one: `--ip` defaults to `::`, so a laptop
/// running `atomic-server` with no arguments already listens on every
/// interface. Warning on that would fire on every dev run and every test, and a
/// warning that always fires is one nobody reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reachability {
    /// Terminates TLS itself, which nobody bothers with for a private toy.
    pub https: bool,
    /// `ATOMIC_DOMAIN` names something that is not this machine.
    pub public_domain: bool,
    /// Serves on the standard web ports. `--port 80` is documented as "set this
    /// if you want it available on the network", so taking it is a statement.
    pub web_port: bool,
}

impl Reachability {
    pub fn looks_exposed(self) -> bool {
        self.https || self.public_domain || self.web_port
    }
}

/// Whether `ATOMIC_DOMAIN` names somewhere other than this machine or this LAN.
///
/// Used only for the warning. A false negative (the proxy case) costs a missing
/// nudge; a false positive costs noise on a dev box. Both are cheap, which is
/// the whole reason the *mode* is never decided this way.
pub fn domain_looks_public(domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    // Strip a port, and the brackets an IPv6 literal wears in a URL.
    let host = domain
        .rsplit_once(':')
        .filter(|(head, _)| !head.is_empty() && head.contains(']') || !head.contains(':'))
        .map(|(head, _)| head)
        .unwrap_or(&domain);
    let host = host.trim_start_matches('[').trim_end_matches(']');

    if host.is_empty() {
        return false;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return !(ip.is_loopback() || ip.is_unspecified() || is_private_ip(&ip));
    }

    // Names a home network hands out, and the bare hostname of a LAN machine.
    // A name with no dot in it cannot be resolved from the public internet.
    const LOCAL_SUFFIXES: [&str; 5] = [".local", ".localhost", ".internal", ".lan", ".home.arpa"];

    if host == "localhost" || LOCAL_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return false;
    }

    host.contains('.')
}

/// Said at boot when the server is probably behind a TLS-terminating proxy and
/// has not been told its public URL. Without `--server-url` the store's origin
/// is built from `--https`, i.e. `http://domain`, and every resource the server
/// names itself (WebSocket, sync, `/query`) reaches an `https://` page as
/// mixed content. A warning only: the same flags are a legitimate plain-http
/// setup on a LAN name, so it is never an error.
pub fn proxy_origin_warning(opts: &crate::config::Opts) -> Option<String> {
    let has_server_url = opts
        .server_url
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());

    if opts.https || has_server_url || !domain_looks_public(&opts.domain) {
        return None;
    }

    Some(format!(
        "ATOMIC_HTTPS is off but ATOMIC_DOMAIN is `{}`, which looks like a public name. If a \
         reverse proxy or tunnel terminates TLS in front of this server, set \
         ATOMIC_SERVER_URL=https://{} (or --server-url); otherwise the server advertises \
         itself as http:// and browsers block those requests as mixed content.",
        opts.domain, opts.domain
    ))
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        // `is_unique_local` / `is_unicast_link_local` are still unstable for
        // IPv6, so match the prefixes directly: fc00::/7 and fe80::/10.
        std::net::IpAddr::V6(v6) => {
            let [a, b, ..] = v6.octets();
            (a & 0xfe) == 0xfc || (a == 0xfe && (b & 0xc0) == 0x80)
        }
    }
}

/// Resolve the mode from explicit configuration.
///
/// Precedence, and the reason for it:
///
/// 1. `ATOMIC_HOST_MODE` — the operator said so, in as many words.
/// 2. `ATOMIC_OWNER_AGENT` is set — naming an owner is not a thing anyone does
///    by accident, so it means "gate this".
/// 3. Neither — Open, exactly as this node behaved before the flag existed. An
///    upgrade never changes who may write.
///
/// Errors are boot failures. Owner mode without a usable owner must not
/// silently degrade to Open: a typo'd env var would then be an open hub, which
/// is the failure this whole module exists to prevent.
pub fn resolve(
    explicit: Option<HostMode>,
    owner_agent_raw: Option<&str>,
) -> AtomicServerResult<HostModeConfig> {
    // An env var set to "" is the same as unset. Docker compose and systemd
    // both produce empty strings for a variable someone left blank, and
    // treating that as "owner mode, invalid DID" would refuse to boot over a
    // stray line.
    let raw = owner_agent_raw.map(str::trim).filter(|s| !s.is_empty());

    match explicit {
        Some(HostMode::Owner) => {
            let Some(raw) = raw else {
                return Err(missing_owner_agent_message().into());
            };
            Ok(HostModeConfig {
                mode: HostMode::Owner,
                owner_agent: Some(validate_owner_agent(raw)?),
            })
        }
        // Explicitly Open wins over a set owner agent. Someone running a
        // deliberate multi-user node may still want an owner recorded for
        // later; refusing to boot over it would be obstinate.
        Some(HostMode::Open) => Ok(HostModeConfig {
            mode: HostMode::Open,
            owner_agent: None,
        }),
        None => match raw {
            Some(raw) => Ok(HostModeConfig {
                mode: HostMode::Owner,
                owner_agent: Some(validate_owner_agent(raw)?),
            }),
            None => Ok(HostModeConfig {
                mode: HostMode::Open,
                owner_agent: None,
            }),
        },
    }
}

/// Check that the value names an agent, and say something useful when it does
/// not. Every branch here is a mistake we expect a real person to make.
fn validate_owner_agent(raw: &str) -> AtomicServerResult<String> {
    if looks_like_secret(raw) {
        return Err(format!(
            "ATOMIC_OWNER_AGENT looks like an Agent *secret*, not an Agent ID.\n\
             \n\
             The secret is the private key — this node never needs it, and it \
             must not sit in the environment.\n\
             Use the public ID instead: it starts with `{AGENT_ID_HINT}` and \
             is the `subject` field inside that secret."
        )
        .into());
    }

    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Err(format!(
            "ATOMIC_OWNER_AGENT must be an Agent ID starting with \
             `{AGENT_ID_HINT}`, not a URL.\n\
             \n\
             A `https://` agent lives on whichever server issued it, so it \
             cannot say who owns *this* one. Open Settings in any Atomic client \
             and copy the Agent ID."
        )
        .into());
    }

    let Some(public_key) = atomic_lib::identifiers::agent_public_key(raw) else {
        if raw == "did:ad:agent:" || raw == "atomic:agent:" {
            return Err(format!(
                "ATOMIC_OWNER_AGENT is `{raw}` with no public key after it.\n\
                 \n\
                 {}",
                where_to_find_the_id()
            )
            .into());
        }
        return Err(format!(
            "ATOMIC_OWNER_AGENT must start with `{AGENT_ID_HINT}` \
             (got `{raw}`).\n\
             \n\
             {}",
            where_to_find_the_id()
        )
        .into());
    };

    if public_key.trim().is_empty() {
        return Err(format!(
            "ATOMIC_OWNER_AGENT is `{AGENT_ID_HINT}` with no public key after it.\n\
             \n\
             {}",
            where_to_find_the_id()
        )
        .into());
    }

    Ok(raw.to_string())
}

/// An Atomic secret is base64-encoded JSON holding a private key. People paste
/// it because it is the thing they saved, so recognise both what it looks like
/// raw and what it looks like decoded, and name the mistake precisely — a
/// generic "invalid value" would leave a private key in a `.env` file while the
/// operator hunted for the real problem.
fn looks_like_secret(raw: &str) -> bool {
    if raw.contains("privateKey") || raw.trim_start().starts_with('{') {
        return true;
    }

    use base64::Engine;

    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|decoded| decoded.contains("privateKey"))
}

fn where_to_find_the_id() -> String {
    format!(
        "Where to find it: open Settings in any Atomic client (browser, desktop, \
         or phone) and copy the Agent ID, or read the `subject` field of your \
         saved secret. It starts with `{AGENT_ID_HINT}`."
    )
}

/// What to print instead of booting when Owner mode has no owner. The operator
/// reads this in `journalctl` after the unit failed to start, so it has to
/// carry the whole fix.
fn missing_owner_agent_message() -> String {
    format!(
        "ATOMIC_HOST_MODE=owner needs ATOMIC_OWNER_AGENT to be set, and it is not.\n\
         \n\
         Owner mode means only one Agent may create new Drives here, so this \
         node has to be told which one:\n\
         \n\
             ATOMIC_OWNER_AGENT={AGENT_ID_HINT}...\n\
         \n\
         {}\n\
         \n\
         Refusing to start rather than falling back to an open node, because an \
         open node on a public address lets strangers store their data on this \
         disk.\n\
         To run an open node on purpose: ATOMIC_HOST_MODE=open",
        where_to_find_the_id()
    )
}

/// The banner an Open node prints when it looks like it is on the internet.
///
/// Deliberately not a boot failure: an existing node must keep booting after an
/// upgrade. But it is the only chance to reach an operator who does not know
/// this setting exists, so it says what is true right now, not what is
/// possible.
pub fn exposure_warning(reachability: Reachability) -> String {
    let mut reasons: Vec<&str> = Vec::new();

    if reachability.https {
        reasons.push("it terminates HTTPS");
    }

    if reachability.public_domain {
        reasons.push("ATOMIC_DOMAIN is not a local name");
    }

    if reachability.web_port {
        reasons.push("it serves on a standard web port");
    }

    format!(
        "This node accepts a new Drive from anyone who can reach it, and it may be reachable ({}).\n\
         Anyone who opens it can create an account and store their data on this disk.\n\
         \n\
         If this node is only for you, name yourself as its owner:\n\
         \n\
             ATOMIC_OWNER_AGENT={AGENT_ID_HINT}...   (copy your Agent ID from Settings)\n\
         \n\
         Visitors keep reading whatever you shared, and people you invited keep their access.\n\
         Only creating a *new* Drive here becomes yours alone.\n\
         \n\
         If this node is meant to be open to others, silence this with ATOMIC_HOST_MODE=open.",
        reasons.join(", ")
    )
}

/// Install the admission policy this node's mode calls for.
///
/// Open installs nothing: the default [`atomic_lib::sync::policy::OpenPolicy`]
/// is already what an ungated node wants, and leaving it untouched is what makes
/// this change a no-op for every existing deployment.
pub async fn install_policy(store: &atomic_lib::Db, host_mode: &HostModeConfig) {
    let Some(owner_agent) = host_mode.owner_agent.as_deref() else {
        return;
    };

    if !host_mode.is_owner_mode() {
        return;
    }

    let policy = atomic_lib::sync::policy::OwnerPolicy::new(owner_agent);
    let existing = store.drive_subjects().await;

    tracing::info!(
        "Host mode: owner ({}). Hosting {} existing Drive(s); new Drives here are the owner's alone.",
        owner_agent,
        existing.len()
    );

    policy.enroll_existing(existing);
    store.set_sync_policy(std::sync::Arc::new(policy));
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "did:ad:agent:RqPwpgHv+PK7Pnz/dVab8hmHjYnvTL1YrlVa6L9G9Zg=";

    #[test]
    fn a_public_domain_without_https_or_server_url_warns_about_the_origin() {
        use clap::Parser;
        let parse = |args: &[&str]| {
            let mut full = vec!["atomic-server"];
            full.extend_from_slice(args);
            crate::config::Opts::parse_from(full)
        };

        assert!(proxy_origin_warning(&parse(&["--domain", "atomic.example.de"])).is_some());
        assert!(proxy_origin_warning(&parse(&[])).is_none(), "localhost");
        assert!(proxy_origin_warning(&parse(&["--domain", "nas.local"])).is_none());
        assert!(proxy_origin_warning(&parse(&[
            "--domain",
            "atomic.example.de",
            "--server-url",
            "https://atomic.example.de"
        ]))
        .is_none());
        assert!(proxy_origin_warning(&parse(&[
            "--domain",
            "atomic.example.de",
            "--https",
            "--email",
            "a@b.c"
        ]))
        .is_none());
    }

    #[test]
    fn nothing_configured_stays_open() {
        let resolved = resolve(None, None).unwrap();
        assert_eq!(resolved.mode, HostMode::Open);
        assert_eq!(resolved.owner_agent, None);
    }

    #[test]
    fn naming_an_owner_gates_the_node() {
        let resolved = resolve(None, Some(OWNER)).unwrap();
        assert_eq!(resolved.mode, HostMode::Owner);
        assert_eq!(resolved.owner_agent.as_deref(), Some(OWNER));
        assert!(resolved.is_owner(OWNER));
        assert!(resolved.is_owner("atomic:agent:RqPwpgHv+PK7Pnz/dVab8hmHjYnvTL1YrlVa6L9G9Zg="));
        assert!(!resolved.is_owner("did:ad:agent:someoneelse"));
        assert!(!resolved.is_owner("atomic:agent:someoneelse"));
    }

    #[test]
    fn an_empty_owner_var_is_not_a_claim() {
        // systemd and compose both hand through "" for a blank line. That is an
        // unset variable, not a broken one, and must not refuse boot.
        for blank in ["", "   "] {
            let resolved = resolve(None, Some(blank)).unwrap();
            assert_eq!(resolved.mode, HostMode::Open, "blank {blank:?}");
        }
    }

    #[test]
    fn owner_mode_without_an_owner_refuses_to_boot() {
        let err = resolve(Some(HostMode::Owner), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ATOMIC_OWNER_AGENT"), "{err}");
        // The escape hatch has to be in the message: someone who wanted an open
        // node needs to know that is still allowed.
        assert!(err.contains("ATOMIC_HOST_MODE=open"), "{err}");
    }

    #[test]
    fn explicit_open_wins_over_a_named_owner() {
        let resolved = resolve(Some(HostMode::Open), Some(OWNER)).unwrap();
        assert_eq!(resolved.mode, HostMode::Open);
        assert!(!resolved.is_owner(OWNER));
    }

    #[test]
    fn a_pasted_secret_is_named_as_such() {
        use base64::Engine;
        let secret = base64::engine::general_purpose::STANDARD
            .encode(r#"{"privateKey":"abc","subject":"did:ad:agent:xyz"}"#);

        let err = resolve(None, Some(&secret)).unwrap_err().to_string();
        assert!(err.contains("secret"), "{err}");

        // Raw JSON, for anyone who saved it unencoded.
        let err = resolve(None, Some(r#"{"privateKey":"abc"}"#))
            .unwrap_err()
            .to_string();
        assert!(err.contains("secret"), "{err}");
    }

    #[test]
    fn an_http_agent_cannot_own_this_node() {
        let err = resolve(None, Some("https://example.com/agents/abc"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("atomic:agent:"), "{err}");
        assert!(err.contains("did:ad:agent:"), "{err}");
    }

    #[test]
    fn a_did_with_no_key_is_refused() {
        let err = resolve(None, Some("did:ad:agent:"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("public key"), "{err}");
    }

    #[test]
    fn owner_mode_never_accepts_new_drives_from_anyone() {
        assert!(HostMode::Open.accepts_new_drives());
        assert!(!HostMode::Owner.accepts_new_drives());
    }

    #[test]
    fn the_warning_says_why_it_fired() {
        let warning = exposure_warning(Reachability {
            https: true,
            public_domain: true,
            web_port: false,
        });
        assert!(warning.contains("terminates HTTPS"), "{warning}");
        assert!(warning.contains("ATOMIC_DOMAIN"), "{warning}");
        assert!(!warning.contains("standard web port"), "{warning}");
        // It must carry the fix, not just the diagnosis.
        assert!(warning.contains("ATOMIC_OWNER_AGENT="), "{warning}");
    }

    #[test]
    fn a_loopback_node_is_not_warned() {
        assert!(!Reachability::default().looks_exposed());
    }

    #[test]
    fn a_local_domain_is_not_public() {
        for local in [
            "localhost",
            "localhost:9883",
            "atomic.local",
            "nas.lan",
            "mybox",
            "127.0.0.1",
            "::1",
            "[::1]:9883",
            "192.168.1.40",
            "10.0.0.5",
            "172.16.4.1",
            "fd00::1",
            "fe80::1",
            "0.0.0.0",
            "",
        ] {
            assert!(!domain_looks_public(local), "expected local: {local:?}");
        }
    }

    #[test]
    fn a_routable_name_or_address_is_public() {
        for public in [
            "example.com",
            "atomic.example.com",
            "EXAMPLE.COM",
            "example.com.",
            "203.0.113.10",
            "2606:4700::1111",
        ] {
            assert!(domain_looks_public(public), "expected public: {public:?}");
        }
    }
}
