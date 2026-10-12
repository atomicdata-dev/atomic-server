//! Compresses the biggest values in the store.
//!
//! A chat message cost about 10 KB on disk, and a third of that was three
//! trees whose values are base64 and msgpack: the stored resource, the Loro
//! snapshot and the signed commit envelope. Their property URLs and Loro
//! structure repeat within one value, so deflate takes roughly 40% off them.
//!
//! [`CompressedKv`] wraps any [`KvStore`] and does this per tree, so every
//! reader and writer (sync, vault, WASM) sees the plain bytes.
//!
//! A Loro snapshot is stored as a delta on the resource's genesis commit when
//! it can be: the commit row already keeps the signed `loroUpdate`, and the
//! snapshot of a resource nobody has edited is that same data plus a few
//! server-written changes. Only what comes after the genesis is kept (about
//! 250 bytes for a chat message instead of 1 KB), and a read puts the two
//! back together. It falls back to the whole snapshot whenever the commit row
//! is missing (a resource that arrived by sync) or the rebuild does not match.
//!
//! Layout of a compressed value: `0x00`, a codec byte, then the payload.
//! `0x00` is the marker because no value these trees held before can start
//! with it: msgpack maps open with `0x80..=0x8f`, `0xde` or `0xdf`, Loro
//! snapshots with `loro` and envelopes with `{`. A value without the marker
//! is a row an older store wrote and is returned as it is. Writing never
//! rewrites old rows by itself; a row is recompressed the next time its
//! resource changes.

use crate::errors::AtomicResult;

use super::{
    kv_store::{KvIter, KvPair, KvStore},
    trees::{Method, Operation, Tree},
};
use std::sync::Arc;

const MARKER: u8 = 0;
const CODEC_RAW: u8 = 0;
const CODEC_DEFLATE: u8 = 1;
/// A snapshot as the deflated updates after the genesis commit.
const CODEC_SNAPSHOT_DELTA: u8 = 2;
/// miniz_oxide level 6, the usual speed/size trade.
const LEVEL: u8 = 6;
/// Below this a value is not worth the extra step.
const MIN_LEN: usize = 128;

pub(super) fn is_compressed_tree(tree: Tree) -> bool {
    matches!(
        tree,
        Tree::Resources | Tree::LoroSnapshots | Tree::Envelopes
    )
}

pub(super) fn encode(value: &[u8]) -> Vec<u8> {
    if value.len() >= MIN_LEN {
        let packed = miniz_oxide::deflate::compress_to_vec(value, LEVEL);
        if packed.len() + 2 < value.len() {
            let mut out = Vec::with_capacity(packed.len() + 2);
            out.extend_from_slice(&[MARKER, CODEC_DEFLATE]);
            out.extend_from_slice(&packed);
            return out;
        }
    }
    if value.first() == Some(&MARKER) {
        // Cannot happen for today's values, but a raw value that looks like
        // the marker would be misread, so say it is raw.
        let mut out = Vec::with_capacity(value.len() + 2);
        out.extend_from_slice(&[MARKER, CODEC_RAW]);
        out.extend_from_slice(value);
        return out;
    }
    value.to_vec()
}

fn decode(value: Vec<u8>) -> AtomicResult<Vec<u8>> {
    if value.first() != Some(&MARKER) {
        return Ok(value);
    }
    match value.get(1) {
        Some(&CODEC_RAW) => Ok(value[2..].to_vec()),
        Some(&CODEC_DEFLATE) => miniz_oxide::inflate::decompress_to_vec(&value[2..])
            .map_err(|e| format!("Could not decompress a stored value: {e:?}").into()),
        Some(&CODEC_SNAPSHOT_DELTA) => Err("A snapshot delta can only be read with its key"
            .to_string()
            .into()),
        other => Err(format!("Unknown storage codec {other:?}").into()),
    }
}

/// The resource-tree key of the genesis commit of the resource a snapshot
/// key names, when its id was derived from that commit's signature.
fn genesis_commit_key(snapshot_key: &[u8]) -> Option<Vec<u8>> {
    let key = std::str::from_utf8(snapshot_key).ok()?;
    let signature = key.strip_prefix(crate::identifiers::ATOMIC_PREFIX)?;
    if signature.is_empty() || signature.contains(':') {
        return None;
    }
    Some(crate::identifiers::commit_subject(signature).into_bytes())
}

/// The signed `loroUpdate` of a genesis commit row, as stored.
fn base_from_row(row: &[u8]) -> Option<Vec<u8>> {
    let row = decode(row.to_vec()).ok()?;
    match super::encoding::decode_propvals(&row)
        .ok()?
        .remove(crate::urls::LORO_UPDATE)?
    {
        crate::Value::LoroDoc(bytes) if !bytes.is_empty() => Some(bytes),
        _ => None,
    }
}

fn base_from_store(inner: &dyn KvStore, snapshot_key: &[u8]) -> Option<Vec<u8>> {
    let commit_key = genesis_commit_key(snapshot_key)?;
    let row = inner.get(Tree::Resources, &commit_key).ok()??;
    base_from_row(&row)
}

fn rebuild_snapshot(base: &[u8], delta: &[u8]) -> AtomicResult<Vec<u8>> {
    let doc = crate::loro::AtomicLoroDoc::new();
    doc.import_update(base)?;
    doc.import_update(delta)?;
    Ok(doc.export_snapshot())
}

/// `snapshot` as a delta on `base`, when that is clearly smaller and
/// rebuilds the same document.
fn encode_snapshot_delta(base: &[u8], snapshot: &[u8]) -> Option<Vec<u8>> {
    let full = crate::loro::AtomicLoroDoc::from_snapshot(snapshot).ok()?;
    let base_doc = crate::loro::AtomicLoroDoc::new();
    base_doc.import_update(base).ok()?;
    let delta = full.export_updates_since(&base_doc.oplog_vv());
    let packed = miniz_oxide::deflate::compress_to_vec(&delta, LEVEL);
    if packed.len() * 2 >= snapshot.len() {
        return None;
    }
    let rebuilt =
        crate::loro::AtomicLoroDoc::from_snapshot(&rebuild_snapshot(base, &delta).ok()?).ok()?;
    if rebuilt.oplog_vv() != full.oplog_vv() {
        return None;
    }
    let mut out = Vec::with_capacity(packed.len() + 2);
    out.extend_from_slice(&[MARKER, CODEC_SNAPSHOT_DELTA]);
    out.extend_from_slice(&packed);
    Some(out)
}

fn decode_snapshot(inner: &dyn KvStore, key: &[u8], value: Vec<u8>) -> AtomicResult<Vec<u8>> {
    if value.get(..2) != Some(&[MARKER, CODEC_SNAPSHOT_DELTA][..]) {
        return decode(value);
    }
    let delta = miniz_oxide::inflate::decompress_to_vec(&value[2..])
        .map_err(|e| format!("Could not decompress a stored snapshot: {e:?}"))?;
    let base = base_from_store(inner, key).ok_or_else(|| {
        format!(
            "The genesis commit a snapshot is stored against is missing for {}",
            String::from_utf8_lossy(key)
        )
    })?;
    rebuild_snapshot(&base, &delta)
}

fn decode_value(
    inner: &dyn KvStore,
    tree: Tree,
    key: &[u8],
    value: Vec<u8>,
) -> AtomicResult<Vec<u8>> {
    if tree == Tree::LoroSnapshots {
        decode_snapshot(inner, key, value)
    } else {
        decode(value)
    }
}

pub struct CompressedKv {
    inner: Arc<dyn KvStore>,
}

impl CompressedKv {
    pub fn new(inner: Arc<dyn KvStore>) -> Self {
        Self { inner }
    }

    fn decoded(&self, tree: Tree, iter: KvIter) -> KvIter {
        if is_compressed_tree(tree) {
            let inner = self.inner.clone();
            Box::new(iter.map(move |pair| {
                let (key, value) = pair?;
                let value = decode_value(inner.as_ref(), tree, &key, value)?;
                Ok((key, value))
            }))
        } else {
            iter
        }
    }

    /// The value to write for `val`. `pending` are the operations written in
    /// the same batch, which may hold the genesis commit a snapshot is
    /// stored against.
    pub(super) fn encoded(
        &self,
        tree: Tree,
        key: &[u8],
        val: &[u8],
        pending: &[Operation],
    ) -> Vec<u8> {
        if tree == Tree::LoroSnapshots {
            let base = genesis_commit_key(key).and_then(|commit_key| {
                pending
                    .iter()
                    .rev()
                    .find(|op| {
                        op.tree == Tree::Resources
                            && op.key == commit_key
                            && matches!(op.method, Method::Insert)
                    })
                    .and_then(|op| op.val.as_deref())
                    .and_then(base_from_row)
                    .or_else(|| base_from_store(self.inner.as_ref(), key))
            });
            if let Some(delta) = base.and_then(|base| encode_snapshot_delta(&base, val)) {
                return delta;
            }
        }
        encode(val)
    }
}

impl KvStore for CompressedKv {
    fn get(&self, tree: Tree, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        let found = self.inner.get(tree, key)?;
        match found {
            Some(value) if is_compressed_tree(tree) => {
                Ok(Some(decode_value(self.inner.as_ref(), tree, key, value)?))
            }
            other => Ok(other),
        }
    }

    fn insert(&self, tree: Tree, key: &[u8], val: &[u8]) -> AtomicResult<()> {
        if is_compressed_tree(tree) {
            self.inner
                .insert(tree, key, &self.encoded(tree, key, val, &[]))
        } else {
            self.inner.insert(tree, key, val)
        }
    }

    fn remove(&self, tree: Tree, key: &[u8]) -> AtomicResult<()> {
        self.inner.remove(tree, key)
    }

    fn contains_key(&self, tree: Tree, key: &[u8]) -> AtomicResult<bool> {
        self.inner.contains_key(tree, key)
    }

    fn scan_prefix(&self, tree: Tree, prefix: &[u8]) -> KvIter {
        self.decoded(tree, self.inner.scan_prefix(tree, prefix))
    }

    fn range(&self, tree: Tree, start: Vec<u8>, end: Vec<u8>, reverse: bool) -> KvIter {
        self.decoded(tree, self.inner.range(tree, start, end, reverse))
    }

    fn range_page(
        &self,
        tree: Tree,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: usize,
    ) -> AtomicResult<Vec<KvPair>> {
        let page = self.inner.range_page(tree, start, end, limit)?;
        if is_compressed_tree(tree) {
            page.into_iter()
                .map(|(k, v)| {
                    let v = decode_value(self.inner.as_ref(), tree, &k, v)?;
                    Ok((k, v))
                })
                .collect()
        } else {
            Ok(page)
        }
    }

    fn iter_tree(&self, tree: Tree) -> KvIter {
        self.decoded(tree, self.inner.iter_tree(tree))
    }

    fn first_entry(&self, tree: Tree) -> AtomicResult<Option<KvPair>> {
        match self.inner.first_entry(tree)? {
            Some((key, value)) if is_compressed_tree(tree) => {
                let value = decode_value(self.inner.as_ref(), tree, &key, value)?;
                Ok(Some((key, value)))
            }
            other => Ok(other),
        }
    }

    fn clear_tree(&self, tree: Tree) -> AtomicResult<()> {
        self.inner.clear_tree(tree)
    }

    fn apply_batch(&self, operations: &[Operation]) -> AtomicResult<()> {
        if !operations
            .iter()
            .any(|op| is_compressed_tree(op.tree) && op.val.is_some())
        {
            return self.inner.apply_batch(operations);
        }
        let encoded: Vec<Operation> = operations
            .iter()
            .map(|op| Operation {
                tree: op.tree,
                method: match op.method {
                    Method::Insert => Method::Insert,
                    Method::Delete => Method::Delete,
                },
                key: op.key.clone(),
                val: match (&op.val, is_compressed_tree(op.tree)) {
                    (Some(val), true) => Some(self.encoded(op.tree, &op.key, val, operations)),
                    (val, _) => val.clone(),
                },
            })
            .collect();
        self.inner.apply_batch(&encoded)
    }

    fn flush(&self) -> AtomicResult<()> {
        self.inner.flush()
    }

    fn begin_batch(&self) {
        self.inner.begin_batch()
    }

    fn commit_batch(&self) -> AtomicResult<()> {
        self.inner.commit_batch()
    }

    fn len(&self, tree: Tree) -> AtomicResult<usize> {
        self.inner.len(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip_and_old_rows_pass_through() {
        let json = br#"{"@id":"atomic:commit:abc","https://atomicdata.dev/properties/isA":["https://atomicdata.dev/classes/Commit"]}"#
            .repeat(8);
        let packed = encode(&json);
        assert_eq!(&packed[..2], &[MARKER, CODEC_DEFLATE]);
        assert!(packed.len() < json.len());
        assert_eq!(decode(packed).unwrap(), json);

        // A row an older store wrote has no marker and is returned as it is.
        assert_eq!(decode(json.clone()).unwrap(), json);
        let snapshot = b"loro\x00\x00\x00".to_vec();
        assert_eq!(decode(snapshot.clone()).unwrap(), snapshot);

        // Short values stay raw, and a raw value that opens with the marker
        // byte is wrapped so it is not misread.
        assert_eq!(encode(b"{}"), b"{}".to_vec());
        let odd = vec![0u8, 1, 2];
        assert_eq!(decode(encode(&odd)).unwrap(), odd);
    }
}
