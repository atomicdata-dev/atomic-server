//! Chat log entries: messages kept inside a `ChatLog` page's Loro document.
//!
//! A [`urls::CHAT_LOG`] page stores its messages in a root Loro map `entries`,
//! a sibling of `properties` and `datatypes`. Entries are not properties: they
//! are never materialized into propvals, indexes or search. See
//! `planning/chat-log.md`.
//!
//! Entry key: `<createdAt ms, lowercase hex>-<8 random hex>`, so keys sort by
//! time. Entry value: a plain Loro map *value* (not a container), replaced
//! whole on edit, with fields `a` (author agent), `t` (text), `c` (createdAt
//! ms) and optionally `r`, `e`, `k`, plus any extra fields.

use crate::errors::AtomicResult;
use crate::loro::AtomicLoroDoc;
use loro::LoroValue;
use std::collections::{BTreeMap, HashMap};

/// Name of the root Loro map that holds the entries.
pub const ENTRIES: &str = "entries";

/// The server refuses entries whose `c` lies further than this ahead of its clock.
pub const MAX_FUTURE_MS: i64 = 10 * 60 * 1000;

/// Field names of an entry value.
pub const FIELD_AUTHOR: &str = "a";
pub const FIELD_TEXT: &str = "t";
pub const FIELD_CREATED_AT: &str = "c";
pub const FIELD_REPLY_TO: &str = "r";
pub const FIELD_EDITED_AT: &str = "e";
pub const FIELD_KINDS: &str = "k";

/// `<createdAt hex>-<8 random hex>`.
pub fn new_entry_key(created_at: i64) -> String {
    use rand::Rng;
    let random: u32 = rand::thread_rng().gen();
    format!("{created_at:x}-{random:08x}")
}

/// The entry key of a migrated `Message` resource:
/// `<createdAt hex>-<first 8 hex chars of SHA-256 of the old subject's id>`.
///
/// Deterministic, so a re-run, a second migrating peer or a stale cached copy
/// of the old resource recognises an entry that already exists. The id is the
/// part after the `did:ad:` / `atomic:` scheme, without query or fragment, so
/// both spellings of one subject give one key. Mirrored in
/// `browser/lib/src/chat-log.ts` (`migratedEntryKey`).
pub fn migrated_entry_key(created_at: i64, old_subject: &str) -> String {
    use sha2::{Digest, Sha256};
    let body = crate::identifiers::identifier_body(old_subject)
        .unwrap_or_else(|| old_subject.split(['?', '#']).next().unwrap_or(old_subject));
    let digest = Sha256::digest(body.as_bytes());
    format!("{:x}-{}", created_at.max(0), hex::encode(&digest[..4]))
}

/// A chat entry as the application writes it.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Author agent subject (`a`).
    pub author: String,
    /// Text, markdown (`t`).
    pub text: String,
    /// Creation time in ms (`c`).
    pub created_at: i64,
    /// Entry key being replied to (`r`).
    pub reply_to: Option<String>,
    /// Edited-at in ms (`e`).
    pub edited_at: Option<i64>,
    /// Extra kinds (`k`), for example `FollowEvent`.
    pub kinds: Option<LoroValue>,
    /// Any further fields, passed through untouched (`role`, `parts`, `s`, ...).
    pub extra: BTreeMap<String, LoroValue>,
}

impl Entry {
    pub fn new(author: impl Into<String>, text: impl Into<String>, created_at: i64) -> Self {
        Self {
            author: author.into(),
            text: text.into(),
            created_at,
            reply_to: None,
            edited_at: None,
            kinds: None,
            extra: BTreeMap::new(),
        }
    }

    /// The plain Loro map value stored under the entry key.
    pub fn to_loro_value(&self) -> LoroValue {
        let mut map: HashMap<String, LoroValue> = HashMap::new();
        for (k, v) in &self.extra {
            map.insert(k.clone(), v.clone());
        }
        map.insert(FIELD_AUTHOR.into(), self.author.as_str().into());
        map.insert(FIELD_TEXT.into(), self.text.as_str().into());
        map.insert(FIELD_CREATED_AT.into(), self.created_at.into());
        if let Some(r) = &self.reply_to {
            map.insert(FIELD_REPLY_TO.into(), r.as_str().into());
        }
        if let Some(e) = self.edited_at {
            map.insert(FIELD_EDITED_AT.into(), e.into());
        }
        if let Some(k) = &self.kinds {
            map.insert(FIELD_KINDS.into(), k.clone());
        }
        LoroValue::from(map)
    }
}

fn field<'a>(entry: &'a LoroValue, name: &str) -> Option<&'a LoroValue> {
    match entry {
        LoroValue::Map(m) => m.get(name),
        _ => None,
    }
}

/// The author (`a`) of an entry value.
pub fn entry_author(entry: &LoroValue) -> Option<&str> {
    match field(entry, FIELD_AUTHOR) {
        Some(LoroValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// The createdAt (`c`) of an entry value, in ms.
pub fn entry_created_at(entry: &LoroValue) -> Option<i64> {
    match field(entry, FIELD_CREATED_AT) {
        Some(LoroValue::I64(i)) => Some(*i),
        Some(LoroValue::Double(f)) if f.is_finite() => Some(*f as i64),
        _ => None,
    }
}

/// The text (`t`) of an entry value.
pub fn entry_text(entry: &LoroValue) -> Option<&str> {
    match field(entry, FIELD_TEXT) {
        Some(LoroValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// All entries of a doc, sorted by key (so by time).
pub type Entries = BTreeMap<String, LoroValue>;

/// One entry key that differs between two states of a doc.
#[derive(Clone, Debug, PartialEq)]
pub struct EntryChange {
    pub key: String,
    pub before: Option<LoroValue>,
    pub after: Option<LoroValue>,
}

/// The keys that were added, changed or removed between `before` and `after`.
pub fn diff_entries(before: &Entries, after: &Entries) -> Vec<EntryChange> {
    let mut changes = Vec::new();
    for (key, new) in after {
        if before.get(key) != Some(new) {
            changes.push(EntryChange {
                key: key.clone(),
                before: before.get(key).cloned(),
                after: Some(new.clone()),
            });
        }
    }
    for (key, old) in before {
        if !after.contains_key(key) {
            changes.push(EntryChange {
                key: key.clone(),
                before: Some(old.clone()),
                after: None,
            });
        }
    }
    changes
}

impl AtomicLoroDoc {
    /// Add or replace the entry under `key`.
    pub fn put_entry(&self, key: &str, entry: &Entry) -> AtomicResult<()> {
        self.doc()
            .get_map(ENTRIES)
            .insert(key, entry.to_loro_value())
            .map_err(|e| format!("Loro entry insert error: {e}"))?;
        Ok(())
    }

    /// Add `entry` under a fresh key and return the key.
    pub fn add_entry(&self, entry: &Entry) -> AtomicResult<String> {
        let key = new_entry_key(entry.created_at);
        self.put_entry(&key, entry)?;
        Ok(key)
    }

    /// Remove the entry under `key`.
    pub fn remove_entry(&self, key: &str) -> AtomicResult<()> {
        self.doc()
            .get_map(ENTRIES)
            .delete(key)
            .map_err(|e| format!("Loro entry delete error: {e}"))?;
        Ok(())
    }

    /// The entry under `key`.
    pub fn get_entry(&self, key: &str) -> Option<LoroValue> {
        self.entries().remove(key)
    }

    /// Every entry, keyed and sorted by key.
    pub fn entries(&self) -> Entries {
        let root = self.doc().get_map(ENTRIES);
        let mut result = Entries::new();
        root.for_each(|key, value| {
            let v = match value.into_value() {
                Ok(v) => v,
                Err(container) => container.get_deep_value(),
            };
            result.insert(key.to_string(), v);
        });
        result
    }

    /// Every entry as `(key, value)`, sorted by key (oldest first).
    pub fn list_entries(&self) -> Vec<(String, LoroValue)> {
        self.entries().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same vectors are in `browser/lib/src/chat-log.test.ts`.
    #[test]
    fn migrated_key_is_the_same_in_both_spellings_and_ignores_query() {
        let want = "1a122ad6665-ba7816bf";
        for subject in [
            "did:ad:abc",
            "atomic:abc",
            "did:ad:abc?drive=did:ad:xyz",
            "atomic:abc#frag",
        ] {
            assert_eq!(
                migrated_entry_key(0x1a122ad6665, subject),
                want,
                "{subject}"
            );
        }
        assert_ne!(migrated_entry_key(0x1a122ad6665, "did:ad:abd"), want);
    }

    #[test]
    fn key_sorts_by_time_and_is_hex() {
        let a = new_entry_key(0x1000);
        let b = new_entry_key(0x1001);
        assert!(a < b);
        assert!(a.starts_with("1000-"));
        assert_eq!(a.len(), "1000-".len() + 8);
    }

    #[test]
    fn put_list_remove_roundtrip() {
        let doc = AtomicLoroDoc::new();
        let mut e = Entry::new("did:ad:agent:x", "hello", 1_700_000_000_000);
        e.reply_to = Some("abc-00000000".into());
        e.extra.insert("role".into(), "user".into());
        let k1 = doc.add_entry(&e).unwrap();
        let k2 = doc
            .add_entry(&Entry::new("did:ad:agent:x", "later", 1_700_000_001_000))
            .unwrap();
        let list = doc.list_entries();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, k1);
        assert_eq!(list[1].0, k2);
        assert_eq!(entry_author(&list[0].1), Some("did:ad:agent:x"));
        assert_eq!(entry_text(&list[0].1), Some("hello"));
        assert_eq!(entry_created_at(&list[0].1), Some(1_700_000_000_000));
        assert!(field(&list[0].1, "role").is_some());
        assert!(field(&list[0].1, FIELD_REPLY_TO).is_some());

        doc.remove_entry(&k1).unwrap();
        assert_eq!(doc.list_entries().len(), 1);
        assert!(doc.get_entry(&k1).is_none());
        // Entries never show up as properties.
        assert!(doc.get_all_properties().is_empty());
    }

    #[test]
    fn diff_detects_add_change_remove() {
        let doc = AtomicLoroDoc::new();
        let a = doc.add_entry(&Entry::new("x", "1", 1)).unwrap();
        let b = doc.add_entry(&Entry::new("x", "2", 2)).unwrap();
        let before = doc.entries();
        doc.remove_entry(&a).unwrap();
        doc.put_entry(&b, &Entry::new("x", "2 edited", 2)).unwrap();
        let c = doc.add_entry(&Entry::new("x", "3", 3)).unwrap();
        let changes = diff_entries(&before, &doc.entries());
        assert_eq!(changes.len(), 3);
        assert!(changes.iter().any(|ch| ch.key == a && ch.after.is_none()));
        assert!(changes
            .iter()
            .any(|ch| ch.key == b && ch.before.is_some() && ch.after.is_some()));
        assert!(changes.iter().any(|ch| ch.key == c && ch.before.is_none()));
    }

    /// Snapshot written by `@tomic/lib`'s `putChatLogEntry` (loro-crdt JS):
    /// `c` is a JS number. Generated once; see browser/lib/src/chat-log.ts.
    const JS_SNAPSHOT_HEX: &str = "6c6f726f000000000000000000000000c4134a640003b50000004c4f524f0000010001011001010000000000000001010000000000050100000100060104010000081b0c3365382d303030303030303101630174016107656e7472696573000e010402010002010002010b02010100200803010380d095ffbc31020502686903050e6469643a61643a6167656e743a78000200667201010000020076760101020000710079000300bad2fd7801000000050000000c0000000000000000010000000000020076769628d58792000000740000004c4f524f00000100010c3365382d3030303030303031060301630380a0abfef9620174040268690161040e6469643a61643a6167656e743a7800010100000000000000000000000100afb22e5e010000000500000009008007656e74726965730009008007656e747269657392b4c4714d00000000000000";

    #[test]
    fn created_at_written_by_the_js_helper_decodes() {
        let bytes: Vec<u8> = (0..JS_SNAPSHOT_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&JS_SNAPSHOT_HEX[i..i + 2], 16).unwrap())
            .collect();
        let doc = AtomicLoroDoc::from_snapshot(&bytes).unwrap();
        let entry = doc.get_entry("3e8-00000001").unwrap();
        assert_eq!(entry_created_at(&entry), Some(1_700_000_000_000));
        assert_eq!(entry_author(&entry), Some("did:ad:agent:x"));
    }

    #[test]
    fn created_at_decodes_as_integer_or_float() {
        for c in [LoroValue::I64(42), LoroValue::Double(42.0)] {
            let mut m: HashMap<String, LoroValue> = HashMap::new();
            m.insert(FIELD_CREATED_AT.into(), c);
            assert_eq!(entry_created_at(&LoroValue::from(m)), Some(42));
        }
    }
}
