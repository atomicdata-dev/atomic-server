use rmp_serde::Serializer;
use serde::Serialize;

use crate::{
    db::{
        plugin_meta::{PluginMeta, PluginMetaKey},
        query_index::QueryFilter,
    },
    errors::AtomicResult,
    resources::PropVals,
};

/// Encode PropVals to a message pack binary format
#[tracing::instrument(skip_all)]
pub fn encode_propvals(propvals: &PropVals) -> AtomicResult<Vec<u8>> {
    let bin =
        rmp_serde::to_vec(&propvals).map_err(|e| format!("Could not serialize PropVals: {}", e))?;

    Ok(bin)
}

/// Decode PropVals from a message pack binary format
#[tracing::instrument(skip_all)]
pub fn decode_propvals(bin: &[u8]) -> AtomicResult<PropVals> {
    let propvals: PropVals =
        rmp_serde::from_slice(bin).map_err(|e| format!("Could not deserialize PropVals: {}", e))?;

    Ok(propvals)
}

// QueryFilter key layout (used as `Tree::WatchedQueries` key AND as the
// q_filter_bytes prefix in `Tree::QueryMembers` keys):
//
//   [drive_len: u32 LE][drive_bytes][msgpack of {property, value, sort_by}]
//
// The drive prefix lets us scan only the bucket of watched queries for a
// given drive (via `drive_scan_prefix`), which matters during populate/commit
// where every atom would otherwise force decoding every watched query in the
// store. For on-disk space this is strictly smaller than the old all-msgpack
// layout (the drive string sits raw, not wrapped in a msgpack string marker).
//
// Bump `watched_queries_v2` → `watched_queries_v3` when deploying this so old
// entries aren't read with the new decoder. Same for `members_index_v2` →
// `members_index_v3` since its keys embed the QueryFilter bytes.
impl super::query_index::QueryFilter {
    #[tracing::instrument(skip_all)]
    pub fn encode(&self) -> AtomicResult<Vec<u8>> {
        let drive_bytes = self.drive.as_str().as_bytes();
        let drive_len = u32::try_from(drive_bytes.len())
            .map_err(|_| "QueryFilter drive string exceeds u32::MAX")?;

        let mut rest_bin = Vec::new();
        // Serialize only the non-drive fields. A small helper struct mirrors
        // the shape so we can reuse the same msgpack encoding without the
        // drive field.
        let rest = QueryFilterRest {
            filters: &self.filters,
            sort_by: &self.sort_by,
        };
        rest.serialize(&mut Serializer::new(&mut rest_bin))
            .map_err(|e| format!("Error encoding QueryFilter rest: {}", e))?;

        let mut out = Vec::with_capacity(4 + drive_bytes.len() + rest_bin.len());
        out.extend_from_slice(&drive_len.to_le_bytes());
        out.extend_from_slice(drive_bytes);
        out.extend_from_slice(&rest_bin);
        Ok(out)
    }

    #[tracing::instrument(skip_all)]
    pub fn from_bytes(bytes: &[u8]) -> AtomicResult<QueryFilter> {
        if bytes.len() < 4 {
            return Err("QueryFilter bytes too short to contain drive length".into());
        }
        let drive_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let end_drive = 4usize.checked_add(drive_len).ok_or("drive_len overflow")?;
        if bytes.len() < end_drive {
            return Err("QueryFilter bytes truncated before drive_bytes".into());
        }
        let drive_str = std::str::from_utf8(&bytes[4..end_drive])
            .map_err(|e| format!("QueryFilter drive is not valid UTF-8: {e}"))?;
        let drive = crate::Subject::from(drive_str.to_string());

        let rest: QueryFilterRestOwned = rmp_serde::from_slice(&bytes[end_drive..])
            .map_err(|e| format!("Error decoding QueryFilter rest: {}", e))?;

        Ok(QueryFilter {
            filters: rest.filters,
            sort_by: rest.sort_by,
            drive,
        })
    }

    /// Returns the key prefix for all WatchedQueries entries scoped to a
    /// specific drive. `scan_prefix(Tree::WatchedQueries, &prefix)` then only
    /// touches that drive's bucket. Used by the per-atom matching loop to
    /// avoid iterating watched queries for unrelated drives.
    pub fn drive_scan_prefix(drive_str: &str) -> Vec<u8> {
        let drive_bytes = drive_str.as_bytes();
        let drive_len = drive_bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + drive_bytes.len());
        out.extend_from_slice(&drive_len.to_le_bytes());
        out.extend_from_slice(drive_bytes);
        out
    }
}

#[derive(Serialize)]
struct QueryFilterRest<'a> {
    filters: &'a Vec<crate::db::query_index::PropVal>,
    sort_by: &'a Option<String>,
}

#[derive(serde::Deserialize)]
struct QueryFilterRestOwned {
    filters: Vec<crate::db::query_index::PropVal>,
    sort_by: Option<String>,
}

impl crate::db::plugin_meta::PluginMeta {
    pub fn encode(&self) -> AtomicResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))
            .map_err(|e| format!("Failed to encode PluginMeta: {}", e))?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> AtomicResult<PluginMeta> {
        let plugin_meta: PluginMeta = rmp_serde::from_slice(bytes)
            .map_err(|e| format!("Failed to decode PluginMeta: {}", e))?;
        Ok(plugin_meta)
    }
}

impl crate::db::plugin_secret::PluginSecret {
    pub fn encode(&self) -> AtomicResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))
            .map_err(|e| format!("Failed to encode PluginSecret: {}", e))?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> AtomicResult<crate::db::plugin_secret::PluginSecret> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| format!("Failed to decode PluginSecret: {}", e).into())
    }
}

impl crate::db::plugin_secret::PluginSecretKey {
    /// `drive \0 plugin \0 name`.
    ///
    /// Not msgpack, unlike the value beside it: listing a plugin's secrets is a
    /// prefix scan, and a msgpack struct is an array whose length is in the
    /// first byte — so a two-field prefix is not a prefix of a three-field key.
    /// Subjects cannot contain a NUL and names are validated not to, so the
    /// separator is unambiguous.
    pub fn encode(&self) -> AtomicResult<Vec<u8>> {
        let mut buf = Self::plugin_prefix(&self.drive, &self.plugin);
        buf.extend_from_slice(self.name.as_bytes());
        Ok(buf)
    }

    /// Every secret of one plugin shares this prefix.
    pub fn plugin_prefix(drive: &str, plugin: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(drive.len() + plugin.len() + 2);
        buf.extend_from_slice(drive.as_bytes());
        buf.push(0);
        buf.extend_from_slice(plugin.as_bytes());
        buf.push(0);
        buf
    }

    /// The secret's name, read back out of a key produced by `encode`.
    pub fn name_from_key(key: &[u8]) -> AtomicResult<String> {
        let name = key
            .split(|b| *b == 0)
            .nth(2)
            .ok_or("Malformed plugin secret key")?;

        String::from_utf8(name.to_vec())
            .map_err(|e| format!("Plugin secret name is not UTF-8: {}", e).into())
    }
}

impl crate::db::plugin_meta::PluginMetaKey {
    pub fn encode(&self) -> AtomicResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))
            .map_err(|e| format!("Failed to encode PluginMetaKey: {}", e))?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> AtomicResult<PluginMetaKey> {
        let plugin_meta_key: PluginMetaKey = rmp_serde::from_slice(bytes)
            .map_err(|e| format!("Failed to decode PluginMetaKey: {}", e))?;
        Ok(plugin_meta_key)
    }
}
