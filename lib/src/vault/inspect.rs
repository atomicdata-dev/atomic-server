//! Read-only accounting of retained backup contents. This deliberately has no
//! database or restore dependency: inspecting an old copy must not resurrect it.
use super::{dek::DriveVaultKey, envelope, envelope::ObjectKind, pack::Pack};
use crate::{errors::AtomicResult, loro::AtomicLoroDoc, urls};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetainedEntry {
    pub subject: String,
    /// A title from this saved copy, not a claim about the current live title.
    pub name: Option<String>,
    pub update_bytes: usize,
    pub envelope_bytes: usize,
    pub blob_hashes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackInspection {
    pub entries: Vec<RetainedEntry>,
    pub blobs: Vec<super::blobs::BlobDependency>,
    /// Everything outside update/envelope payloads, including MessagePack,
    /// deletion records, dependency metadata and authenticated encryption.
    pub structure_bytes: usize,
}

pub fn inspect_pack(key: &DriveVaultKey, sealed: &[u8]) -> AtomicResult<PackInspection> {
    let (header, plaintext) = envelope::open(key, sealed)?;
    if !matches!(header.kind, ObjectKind::Pack | ObjectKind::Checkpoint) {
        return Err("vault object is not a resource pack".into());
    }
    let pack = Pack::decode(&plaintext)?;
    let mut payload_bytes = 0usize;
    let entries = pack
        .entries
        .into_iter()
        .map(|entry| {
            let envelope_bytes = entry.envelopes.iter().map(String::len).sum::<usize>();
            payload_bytes += entry.update.len() + envelope_bytes;
            // A delta need not contain its title or blob reference. Keep that
            // absence explicit; another saved copy may supply the display metadata.
            let doc = AtomicLoroDoc::from_snapshot(&entry.update).ok();
            let name = doc.as_ref().and_then(|doc| {
                doc.get_string_property(urls::NAME)
                    .or_else(|| doc.get_string_property(urls::FILENAME))
            });
            let blob_hashes = doc
                .as_ref()
                .map(|doc| {
                    let properties = doc.get_all_properties();
                    let values: Vec<String> = match properties.get(urls::CHUNKS) {
                        Some(loro::LoroValue::List(values)) => values
                            .iter()
                            .filter_map(|v| {
                                if let loro::LoroValue::String(value) = v {
                                    Some(value.to_string())
                                } else {
                                    None
                                }
                            })
                            .collect(),
                        _ => doc.get_string_property(urls::BLOB).into_iter().collect(),
                    };
                    values
                        .into_iter()
                        .filter_map(|value| {
                            crate::Subject::from_raw(&value, None)
                                .blob_hash_hex()
                                .map(str::to_owned)
                        })
                        .collect()
                })
                .unwrap_or_default();
            RetainedEntry {
                subject: entry.subject,
                name,
                update_bytes: entry.update.len(),
                envelope_bytes,
                blob_hashes,
            }
        })
        .collect();
    let structure_bytes = sealed
        .len()
        .checked_sub(payload_bytes)
        .ok_or("vault payload sizes exceed the stored object")?;
    Ok(PackInspection {
        entries,
        blobs: pack.blobs,
        structure_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        values::Value,
        vault::{envelope::seal, pack::PackEntry},
    };

    #[test]
    fn measures_actual_payloads_and_accounts_for_every_stored_byte() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(urls::NAME, &Value::String("Project notes".into()))
            .unwrap();
        let update = doc.export_snapshot();
        let key = DriveVaultKey::from_bytes([7; 32], 1);
        let pack = Pack::new(
            vec![PackEntry {
                subject: "atomic:test".into(),
                update: update.clone(),
                envelopes: vec!["signed é".into()],
            }],
            vec!["atomic:deleted".into()],
        );
        // Historical integer-array encoding and current binary encoding both
        // reconcile without estimating or dividing shared overhead among items.
        for plaintext in [
            pack.encode().unwrap(),
            rmp_serde::to_vec_named(&pack).unwrap(),
        ] {
            let sealed = seal(&key, ObjectKind::Checkpoint, &plaintext).unwrap();
            let result = inspect_pack(&key, &sealed).unwrap();
            let entry = &result.entries[0];
            assert_eq!(entry.name.as_deref(), Some("Project notes"));
            assert_eq!(entry.update_bytes, update.len());
            assert_eq!(entry.envelope_bytes, "signed é".len());
            assert_eq!(
                entry.update_bytes + entry.envelope_bytes + result.structure_bytes,
                sealed.len()
            );
            assert!(inspect_pack(&DriveVaultKey::from_bytes([8; 32], 1), &sealed).is_err());
        }
    }

    #[test]
    fn reads_file_names_and_references_without_importing_a_store() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(urls::FILENAME, &Value::String("Design brief.txt".into()))
            .unwrap();
        let hash = "a".repeat(64);
        doc.set_property(urls::BLOB, &Value::String(format!("atomic:blob:{hash}")))
            .unwrap();
        let pack = Pack::new(
            vec![PackEntry {
                subject: "atomic:file".into(),
                update: doc.export_snapshot(),
                envelopes: vec![],
            }],
            vec![],
        );
        let key = DriveVaultKey::from_bytes([7; 32], 1);
        let sealed = seal(&key, ObjectKind::Pack, &pack.encode().unwrap()).unwrap();
        let report = inspect_pack(&key, &sealed).unwrap();
        assert_eq!(report.entries[0].name.as_deref(), Some("Design brief.txt"));
        assert_eq!(report.entries[0].blob_hashes, vec![hash]);
    }

    #[test]
    fn refuses_corrupt_foreign_or_non_pack_objects() {
        let key = DriveVaultKey::from_bytes([7; 32], 1);
        let pack = Pack::new(vec![], vec![]).encode().unwrap();
        let mut sealed = seal(&key, ObjectKind::Pack, &pack).unwrap();
        assert!(inspect_pack(&DriveVaultKey::from_bytes([7; 32], 2), &sealed).is_err());
        sealed[32] ^= 1;
        assert!(inspect_pack(&key, &sealed).is_err());
        assert!(inspect_pack(&key, &seal(&key, ObjectKind::Blob, &pack).unwrap()).is_err());
    }
}
