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
    write_log::{logged_subject, WriteLog},
};
use std::sync::{Arc, Mutex};

const MARKER: u8 = 0;
const CODEC_RAW: u8 = 0;
const CODEC_DEFLATE: u8 = 1;
/// A snapshot as the deflated updates after the genesis commit.
const CODEC_SNAPSHOT_DELTA: u8 = 2;
/// Like [`CODEC_SNAPSHOT_DELTA`] for a resource whose id is not its commit's
/// signature: the payload opens with the length and the signature of the
/// genesis commit row the delta is against.
const CODEC_SNAPSHOT_DELTA_OF: u8 = 3;
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
        Some(&CODEC_SNAPSHOT_DELTA | &CODEC_SNAPSHOT_DELTA_OF) => {
            Err("A snapshot delta can only be read with its key"
                .to_string()
                .into())
        }
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

/// The `loroUpdate` of `row` when it is the genesis commit of `subject`.
fn genesis_base_of(row: &[u8], subject: &[u8]) -> Option<Vec<u8>> {
    let mut propvals = super::encoding::decode_propvals(&decode(row.to_vec()).ok()?).ok()?;
    let named = propvals.remove(crate::urls::SUBJECT)?.to_string();
    match (
        propvals.remove(crate::urls::LORO_UPDATE)?,
        propvals.get(crate::urls::IS_GENESIS),
    ) {
        (crate::Value::LoroDoc(bytes), Some(crate::Value::Boolean(true)))
            if named.as_bytes() == subject && !bytes.is_empty() =>
        {
            Some(bytes)
        }
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
    let of_commit = value.get(..2) == Some(&[MARKER, CODEC_SNAPSHOT_DELTA_OF][..]);
    if !of_commit && value.get(..2) != Some(&[MARKER, CODEC_SNAPSHOT_DELTA][..]) {
        return decode(value);
    }
    let (commit_key, payload) = if of_commit {
        let len = *value.get(2).ok_or("A stored snapshot is cut short")? as usize;
        let signature = value
            .get(3..3 + len)
            .ok_or("A stored snapshot is cut short")?;
        (
            Some(
                crate::identifiers::commit_subject(&String::from_utf8_lossy(signature))
                    .into_bytes(),
            ),
            &value[3 + len..],
        )
    } else {
        (genesis_commit_key(key), &value[2..])
    };
    let delta = miniz_oxide::inflate::decompress_to_vec(payload)
        .map_err(|e| format!("Could not decompress a stored snapshot: {e:?}"))?;
    let base = commit_key.and_then(|commit_key| {
        let row = inner.get(Tree::Resources, &commit_key).ok()??;
        base_from_row(&row)
    });
    let base = base.ok_or_else(|| {
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

fn logged_ops(operations: &[Operation]) -> Vec<String> {
    operations
        .iter()
        .filter_map(|op| logged_subject(op.tree, &op.key))
        .collect()
}

pub struct CompressedKv {
    inner: Arc<dyn KvStore>,
    log: Arc<WriteLog>,
    /// Subjects written since `begin_batch`; logged once `commit_batch`
    /// succeeds, so the log never counts a write a reader cannot see yet.
    batched: Mutex<Option<Vec<String>>>,
}

impl CompressedKv {
    #[cfg(test)]
    pub fn new(inner: Arc<dyn KvStore>) -> Self {
        Self::with_log(inner, Arc::new(WriteLog::default()))
    }

    pub fn with_log(inner: Arc<dyn KvStore>, log: Arc<WriteLog>) -> Self {
        Self {
            inner,
            log,
            batched: Mutex::new(None),
        }
    }

    /// Log a finished write (or buffer it while batching).
    fn wrote(&self, subjects: Vec<String>) {
        if subjects.is_empty() {
            return;
        }
        match self.batched.lock() {
            Ok(mut batch) => match batch.as_mut() {
                Some(buffer) => buffer.extend(subjects),
                None => self.log.record(subjects),
            },
            Err(_) => self.log.invalidate_all(),
        }
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
            // A resource named by a genesis certificate: the genesis commit
            // is the one queued in this batch, and the row says which.
            {
                let found = pending.iter().rev().find_map(|op| {
                    // Cheap checks first: decoding a row is the costly part and
                    // a bulk batch asks this once per snapshot.
                    if op.tree != Tree::Resources || !matches!(op.method, Method::Insert) {
                        return None;
                    }
                    let signature = op
                        .key
                        .strip_prefix(crate::identifiers::ATOMIC_COMMIT_PREFIX.as_bytes())?;
                    let row = op.val.as_deref()?;
                    // The row names the snapshot's subject; skip the decode
                    // for every other commit in the batch.
                    if !row.windows(key.len()).any(|w| w == key) {
                        return None;
                    }
                    let base = genesis_base_of(row, key)?;
                    Some((signature, base))
                });
                if let Some((signature, base)) = found {
                    if let Some(delta) = encode_snapshot_delta(&base, val) {
                        let mut out = vec![MARKER, CODEC_SNAPSHOT_DELTA_OF, signature.len() as u8];
                        out.extend_from_slice(signature);
                        out.extend_from_slice(&delta[2..]);
                        return out;
                    }
                }
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
                .insert(tree, key, &self.encoded(tree, key, val, &[]))?;
        } else {
            self.inner.insert(tree, key, val)?;
        }
        self.wrote(logged_subject(tree, key).into_iter().collect());
        Ok(())
    }

    fn remove(&self, tree: Tree, key: &[u8]) -> AtomicResult<()> {
        self.inner.remove(tree, key)?;
        self.wrote(logged_subject(tree, key).into_iter().collect());
        Ok(())
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

    fn range_value_sizes(
        &self,
        tree: Tree,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: usize,
    ) -> AtomicResult<Vec<(Vec<u8>, u64)>> {
        if is_compressed_tree(tree) {
            // Stored length is not the logical length: decode.
            return Ok(self
                .range_page(tree, start, end, limit)?
                .into_iter()
                .map(|(key, value)| (key, value.len() as u64))
                .collect());
        }
        self.inner.range_value_sizes(tree, start, end, limit)
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
        self.inner.clear_tree(tree)?;
        if matches!(tree, Tree::Resources | Tree::LoroSnapshots) {
            self.log.invalidate_all();
        }
        Ok(())
    }

    fn apply_batch(&self, operations: &[Operation]) -> AtomicResult<()> {
        if !operations
            .iter()
            .any(|op| is_compressed_tree(op.tree) && op.val.is_some())
        {
            self.inner.apply_batch(operations)?;
            self.wrote(logged_ops(operations));
            return Ok(());
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
        self.inner.apply_batch(&encoded)?;
        self.wrote(logged_ops(operations));
        Ok(())
    }

    fn flush(&self) -> AtomicResult<()> {
        self.inner.flush()
    }

    fn begin_batch(&self) {
        if let Ok(mut batch) = self.batched.lock() {
            batch.get_or_insert_with(Vec::new);
        }
        self.inner.begin_batch()
    }

    fn commit_batch(&self) -> AtomicResult<()> {
        let committed = self.inner.commit_batch();
        let buffered = self.batched.lock().ok().and_then(|mut b| b.take());
        if let Err(e) = committed {
            // Unknown how much landed.
            self.log.invalidate_all();
            return Err(e);
        }
        self.wrote(buffered.unwrap_or_default());
        Ok(())
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
