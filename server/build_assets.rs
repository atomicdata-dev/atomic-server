//! Content-validated cache for build-time compression, outside the staged assets.

use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

/// Returns compressed bytes and whether a verified cache entry supplied them.
pub fn compress_cached(
    data: &[u8],
    cache: &Path,
    quality: u32,
    window: u32,
) -> std::io::Result<(Vec<u8>, bool)> {
    let key = format!(
        "brotli8-q{quality}-w{window}-{}.br",
        blake3::hash(data).to_hex()
    );
    let entry = cache.join(&key);
    if let Ok(compressed) = fs::read(&entry) {
        // A content-derived filename alone cannot detect a truncated/corrupted
        // cache file. Decode with a bound before embedding bytes in the server.
        let mut decoded = Vec::new();
        let valid = brotli::Decompressor::new(compressed.as_slice(), 4096)
            .take(data.len() as u64 + 1)
            .read_to_end(&mut decoded)
            .is_ok()
            && decoded == data;
        if valid {
            return Ok((compressed, true));
        }
    }

    let mut compressed = Vec::with_capacity(data.len() / 3);
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, quality, window);
        writer.write_all(data)?;
        writer.flush()?;
    }

    // Cache writes are optional. Publish atomically so concurrent equal inputs
    // never observe partial bytes, and leave no temporary file on failure.
    if fs::create_dir_all(cache).is_ok() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temporary = cache.join(format!(
            "{key}.{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if fs::write(&temporary, &compressed).is_ok() {
            let _ = fs::rename(&temporary, &entry);
        }
        let _ = fs::remove_file(temporary);
    }
    Ok((compressed, false))
}
