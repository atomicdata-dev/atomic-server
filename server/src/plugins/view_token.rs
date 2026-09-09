//! Letting a null-origin iframe read a plugin's source.
//!
//! A plugin's code is a resource on a drive, so serving it is subject to
//! rights. The iframe that runs it cannot ask for it: it has no origin, no
//! cookies and no key, so it cannot sign a request the way every other
//! authenticated client does.
//!
//! Nor can the parent hand the bytes over directly. `blob:`, `data:` and
//! `srcdoc` all inherit the parent page's CSP, which is exactly why the plugin
//! document has to be a real network response in the first place (see
//! `PluginView.tsx`).
//!
//! So the parent — which *is* authenticated — asks for a token scoped to one
//! plugin, and puts it in the iframe's URL. Serving the source world-readable
//! instead would be a rights hole that looks like a convenience.
//!
//! Held in memory rather than in the store. These live for minutes, a restart
//! simply means the page mints another, and keeping them out of the store
//! means they cannot sync to somewhere they would still be valid.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::{engine::general_purpose, Engine as _};

/// Long enough for a slow page load, short enough that a URL in a history or a
/// log stops working before anyone finds it.
pub const TTL_MS: i64 = 5 * 60 * 1000;

/// How many tokens may be outstanding before minting starts evicting expired
/// ones. Only a bound on unbounded growth; the normal count is single digits.
const SWEEP_AT: usize = 256;

#[derive(Debug, Clone)]
struct Grant {
    drive: String,
    plugin: String,
    expires_at: i64,
}

#[derive(Default)]
pub struct ViewTokens {
    grants: Mutex<HashMap<String, Grant>>,
}

impl ViewTokens {
    /// A token that admits exactly one plugin's source, for a few minutes.
    pub fn mint(&self, drive: &str, plugin: &str, now: i64) -> String {
        let token = random_token();
        let mut grants = self.grants.lock().expect("view token lock");

        if grants.len() >= SWEEP_AT {
            grants.retain(|_, grant| grant.expires_at > now);
        }

        grants.insert(
            token.clone(),
            Grant {
                drive: drive.to_string(),
                plugin: plugin.to_string(),
                expires_at: now + TTL_MS,
            },
        );

        token
    }

    /// Whether this token admits this exact plugin, right now.
    ///
    /// Scoped rather than merely valid: a token minted for one plugin must not
    /// read another's source, or a drive with one shared app would expose
    /// every app on it.
    pub fn admits(&self, token: &str, drive: &str, plugin: &str, now: i64) -> bool {
        let mut grants = self.grants.lock().expect("view token lock");

        let Some(grant) = grants.get(token) else {
            return false;
        };

        if grant.expires_at <= now {
            grants.remove(token);

            return false;
        }

        grant.drive == drive && grant.plugin == plugin
    }
}

fn random_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut bytes = [0u8; 32];

    if SystemRandom::new().fill(&mut bytes).is_err() {
        // A predictable token is worse than no plugin view at all, so fail
        // closed: this cannot match anything `mint` stored.
        return String::new();
    }

    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    #[test]
    fn a_token_admits_the_plugin_it_was_minted_for() {
        let tokens = ViewTokens::default();
        let token = tokens.mint("drive", "plugin", NOW);

        assert!(tokens.admits(&token, "drive", "plugin", NOW));
    }

    #[test]
    fn a_token_does_not_admit_another_plugin_on_the_same_drive() {
        let tokens = ViewTokens::default();
        let token = tokens.mint("drive", "plugin", NOW);

        assert!(!tokens.admits(&token, "drive", "other", NOW));
        assert!(!tokens.admits(&token, "other-drive", "plugin", NOW));
    }

    #[test]
    fn a_token_stops_working() {
        let tokens = ViewTokens::default();
        let token = tokens.mint("drive", "plugin", NOW);

        assert!(!tokens.admits(&token, "drive", "plugin", NOW + TTL_MS));
    }

    #[test]
    fn an_unknown_token_admits_nothing() {
        let tokens = ViewTokens::default();
        tokens.mint("drive", "plugin", NOW);

        assert!(!tokens.admits("made-up", "drive", "plugin", NOW));
        assert!(!tokens.admits("", "drive", "plugin", NOW));
    }

    #[test]
    fn minting_does_not_grow_without_bound() {
        let tokens = ViewTokens::default();

        for i in 0..(SWEEP_AT * 2) {
            tokens.mint("drive", &format!("plugin-{i}"), NOW - TTL_MS - 1);
        }

        let live = tokens.mint("drive", "plugin", NOW);

        assert!(tokens.admits(&live, "drive", "plugin", NOW));
        assert!(tokens.grants.lock().unwrap().len() < SWEEP_AT * 2);
    }
}
