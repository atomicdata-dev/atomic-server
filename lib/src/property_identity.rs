//! Content-addressed Property identifiers: `atomic:prop:{blake3-hex}`.
//!
//! A Property's ID is a hash of exactly three fields: its ontology, its
//! shortname and its datatype. Labels, descriptions and every other
//! constraint stay outside the hash.
//!
//! See `docs/src/schema/property-identity.md`.

use crate::{
    datatype::{match_datatype, DataType},
    errors::AtomicResult,
    identifiers::{self, ATOMIC_PROP_PREFIX},
    values::SLUG_REGEX,
};
use regex::Regex;
use serde_json::json;

/// Domain separation for property IDs. Keeps them apart from blob hashes.
const PROPERTY_CONTEXT: &str = "atomic property identity v1";

/// The `atomic:prop:{hex}` ID for the given ontology, shortname and datatype.
pub fn property_id(ontology: &str, shortname: &str, datatype: &str) -> AtomicResult<String> {
    if !Regex::new(SLUG_REGEX).unwrap().is_match(shortname) {
        return Err(format!("Not a valid shortname: '{shortname}'").into());
    }
    if matches!(match_datatype(datatype), DataType::Unsupported(_)) {
        return Err(format!("Unknown datatype: '{datatype}'").into());
    }
    let ontology = identifiers::canonicalize_scheme(ontology);
    // serde_json maps sort their keys; JCS orders them again regardless.
    let canonical = serde_jcs::to_string(&json!({
        "datatype": datatype,
        "ontology": ontology,
        "shortname": shortname,
    }))
    .map_err(|e| format!("Could not canonicalize property identity: {e}"))?;
    let mut hasher = blake3::Hasher::new_derive_key(PROPERTY_CONTEXT);
    hasher.update(canonical.as_bytes());
    Ok(format!(
        "{ATOMIC_PROP_PREFIX}{}",
        hasher.finalize().to_hex()
    ))
}

/// Check that `subject` (either prefix) is the ID of this ontology, shortname
/// and datatype.
pub fn verify_property_id(
    subject: &str,
    ontology: &str,
    shortname: &str,
    datatype: &str,
) -> AtomicResult<()> {
    if !is_property_id(subject) {
        return Err(format!("Not a property identifier: '{subject}'").into());
    }
    let expected = property_id(ontology, shortname, datatype)?;
    if identifiers::canonicalize_scheme(subject) != expected {
        return Err(format!(
            "Property ID mismatch: '{subject}' is not the hash of its ontology, shortname and datatype (expected '{expected}')"
        )
        .into());
    }
    Ok(())
}

/// True for a well-formed `atomic:prop:` / `did:ad:prop:` identifier.
pub fn is_property_id(subject: &str) -> bool {
    identifiers::prop_hash_hex(subject).is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urls;

    const ONTOLOGY: &str = "atomic:ontologyGenesis";

    #[test]
    fn fixed_vectors() {
        for (o, n, d, want) in [
            (
                "atomic:ontologyGenesis",
                "name",
                urls::STRING,
                "atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74",
            ),
            (
                "did:ad:ontologyGenesis",
                "name",
                urls::STRING,
                "atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74",
            ),
            (
                "https://atomicdata.dev/ontology/core",
                "name",
                urls::STRING,
                "atomic:prop:2476b0c536e851a71bc0c1991bf3746c9370085c3e6e52a0dd8255e61be1a862",
            ),
            (
                "atomic:ontologyGenesis",
                "name",
                urls::SLUG,
                "atomic:prop:d744c0c58cf42bff6246a015b5e1429c93f1ca505c3355dd84c695c8da6e6626",
            ),
        ] {
            assert_eq!(property_id(o, n, d).unwrap(), want, "{o} {n} {d}");
        }
    }

    #[test]
    fn did_ontology_matches_atomic_form() {
        assert_eq!(
            property_id("did:ad:ontologyGenesis", "name", urls::STRING).unwrap(),
            property_id(ONTOLOGY, "name", urls::STRING).unwrap()
        );
    }

    #[test]
    fn datatype_changes_the_id() {
        assert_ne!(
            property_id(ONTOLOGY, "name", urls::STRING).unwrap(),
            property_id(ONTOLOGY, "name", urls::SLUG).unwrap()
        );
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "Name", "my name", "-a", "a-", "a--b", "a_b"] {
            assert!(property_id(ONTOLOGY, bad, urls::STRING).is_err(), "{bad}");
        }
        assert!(property_id(ONTOLOGY, "name", "https://example.com/not-a-datatype").is_err());
        assert!(property_id(ONTOLOGY, "name", "").is_err());
    }

    #[test]
    fn verify_accepts_both_prefixes_and_rejects_mismatch() {
        let id = property_id(ONTOLOGY, "name", urls::STRING).unwrap();
        assert!(is_property_id(&id));
        verify_property_id(&id, ONTOLOGY, "name", urls::STRING).unwrap();
        let legacy = id.replace("atomic:prop:", "did:ad:prop:");
        assert!(is_property_id(&legacy));
        verify_property_id(&legacy, ONTOLOGY, "name", urls::STRING).unwrap();
        assert!(verify_property_id(&id, ONTOLOGY, "name", urls::SLUG).is_err());
        assert!(verify_property_id(&id, ONTOLOGY, "title", urls::STRING).is_err());
        assert!(verify_property_id("atomic:blob:ab", ONTOLOGY, "name", urls::STRING).is_err());
    }

    #[test]
    fn is_property_id_is_strict() {
        assert!(!is_property_id("atomic:prop:"));
        assert!(!is_property_id("atomic:prop:ABCD"));
        assert!(!is_property_id(&format!("atomic:prop:{}", "A".repeat(64))));
        assert!(!is_property_id(&format!("atomic:blob:{}", "a".repeat(64))));
        assert!(is_property_id(&format!("atomic:prop:{}", "a".repeat(64))));
    }
}
