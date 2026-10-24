//! Pairing codes: what a QR shows and what is pasted instead. Port of
//! `PairScreen.parsePeerInfo` / `formatQrValue` in
//! `flutter/lib/screens/pair_screen.dart`; wire format in
//! `planning/device-pairing.md`.
//!
//! A code is routing only: it says which node to reach and optionally where
//! else to find it. It grants nothing, the node dialed still proves it holds
//! the same agent key before any resource crosses.

use crate::types::PairingCode;

const NODE: &str = "atomic:node:";
const NODE_DID: &str = "did:ad:node:";

fn is_node_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

fn from_query(node_id: &str, query: &str) -> Option<PairingCode> {
    let pairs = query_pairs(query);
    let first = |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    if first("v").is_some_and(|v| v != "1") {
        return None;
    }
    // A code that carries a secret is not a pairing code.
    if first("secret").is_some() {
        return None;
    }
    let drives: Vec<String> = pairs
        .iter()
        .filter(|(k, v)| k == "drives" && v != "*")
        .map(|(_, v)| v.clone())
        .collect();
    Some(PairingCode {
        node_id: node_id.to_string(),
        name: String::new(),
        server_url: first("url").filter(|u| !u.is_empty()),
        drives,
    })
}

/// The node a pasted or scanned code names, `None` when it is not a pairing code.
pub fn parse(input: &str) -> Option<PairingCode> {
    let trimmed = input.trim();

    // Legacy `atomic://pair?node=atomic:node:<id>&url=...`.
    if let Some(query) = trimmed
        .strip_prefix("atomic://pair?")
        .or_else(|| trimmed.strip_prefix("atomic:pair?"))
    {
        let pairs = query_pairs(query);
        let node = pairs.iter().find(|(k, _)| k == "node")?.1.clone();
        let id = node.strip_prefix(NODE).or_else(|| node.strip_prefix(NODE_DID))?;
        if !is_node_hex(id) {
            return None;
        }
        return from_query(id, query);
    }

    // `atomic:node:<id>[?v=1&drives=*&url=...]` or `did:ad:node:<id>[...]`.
    let head = trimmed.split(['?', '#']).next().unwrap_or("");
    for prefix in [NODE, NODE_DID] {
        if let Some(value) = head.strip_prefix(prefix) {
            if is_node_hex(value) {
                let id = value.to_lowercase();
                return match trimmed.split_once('?') {
                    None => Some(PairingCode { node_id: id, name: String::new(), server_url: None, drives: vec![] }),
                    Some((_, query)) => from_query(&id, query),
                };
            }
        }
    }

    // `atomic:node:<id>:<name>` (what the app's own QR shows), `iroh:<id>`, or a bare id.
    let mut value = trimmed;
    let mut name = String::new();
    for prefix in [NODE, NODE_DID] {
        if let Some(rest) = value.strip_prefix(prefix) {
            value = rest;
            if value.len() > 64 && value.as_bytes()[64] == b':' {
                name = decode(&value[65..]);
                value = &value[..64];
            }
            break;
        }
    }
    let value = value.strip_prefix("iroh:").unwrap_or(value);
    if is_node_hex(value) && value.bytes().all(|b| !b.is_ascii_uppercase()) {
        return Some(PairingCode { node_id: value.to_string(), name, server_url: None, drives: vec![] });
    }
    None
}

/// What this device's QR shows: its node id and, when it has one, its name.
pub fn format(node_id: &str, device_name: &str) -> String {
    if device_name.is_empty() {
        format!("{NODE}{node_id}")
    } else {
        format!("{NODE}{node_id}:{}", encode(device_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn what_this_device_shows_is_read_back_with_its_name() {
        let code = parse(&format(ID, "Joep's phone")).unwrap();
        assert_eq!((code.node_id.as_str(), code.name.as_str()), (ID, "Joep's phone"));
        assert_eq!(parse(&format(ID, "")).unwrap().node_id, ID);
    }

    #[test]
    fn routing_hints_are_read_and_a_secret_or_wrong_version_refused() {
        let code = parse(&format!("atomic:node:{ID}?v=1&drives=*&drives=did:ad:x&url=https%3A%2F%2Fa.example")).unwrap();
        assert_eq!(code.drives, vec!["did:ad:x".to_string()]);
        assert_eq!(code.server_url.as_deref(), Some("https://a.example"));
        assert!(parse(&format!("atomic:node:{ID}?v=2")).is_none());
        assert!(parse(&format!("atomic:node:{ID}?secret=abc")).is_none());
    }

    #[test]
    fn did_ids_bare_ids_and_legacy_uris_are_accepted_and_junk_is_not() {
        assert_eq!(parse(&format!("did:ad:node:{ID}")).unwrap().node_id, ID);
        assert_eq!(parse(&format!("  {ID}  ")).unwrap().node_id, ID);
        assert_eq!(parse(&format!("iroh:{ID}")).unwrap().node_id, ID);
        let legacy = parse(&format!("atomic://pair?v=1&node=atomic:node:{ID}&url=http://x.example")).unwrap();
        assert_eq!((legacy.node_id.as_str(), legacy.server_url.as_deref()), (ID, Some("http://x.example")));
        assert!(parse("did:ad:node:short").is_none());
        assert!(parse("hello").is_none());
        assert!(parse("").is_none());
    }
}
