use super::*;

#[cfg(test)]
mod pending_blob_request_ttl_tests {
    use super::*;

    /// F4 follow-up: a `BLOB_REQUEST` the server issued but the peer never
    /// answers must not sit in `pending_blob_requests` forever — that's an
    /// unbounded leak, one entry per missing blob a peer never delivers.
    /// `note_pending_blob_request` lazily prunes anything older than
    /// `PENDING_BLOB_REQUEST_TTL` on every insert; this reaches the private
    /// map directly to backdate an entry past the TTL without an actual
    /// 300s sleep, then drives the prune through the public API.
    #[tokio::test]
    async fn stale_entry_is_pruned_on_next_insert() {
        let db = Db::init_temp("pending_blob_ttl_prune").await.unwrap();

        let stale_hash = [1u8; 32];
        let backdated = web_time::Instant::now()
            .checked_sub(PENDING_BLOB_REQUEST_TTL + std::time::Duration::from_secs(1))
            .expect("test host must have been up longer than the TTL");
        db.pending_blob_requests.write().unwrap().insert(
            stale_hash,
            ("https://example.com/old-drive".into(), backdated),
        );

        // Insert a second, fresh entry — this is what triggers the prune.
        let fresh_hash = [2u8; 32];
        db.note_pending_blob_request(fresh_hash, "https://example.com/new-drive".into());

        assert!(
            db.take_pending_blob_request(&stale_hash).is_none(),
            "an entry older than the TTL must be pruned, not returned"
        );
        assert_eq!(
            db.take_pending_blob_request(&fresh_hash),
            Some("https://example.com/new-drive".to_string()),
            "a fresh entry inserted in the same call must survive its own prune"
        );
    }

    /// Sanity check for the inverse: a request answered promptly (the
    /// normal case) is unaffected by the TTL machinery.
    #[tokio::test]
    async fn fresh_entry_survives_take() {
        let db = Db::init_temp("pending_blob_ttl_fresh").await.unwrap();

        let hash = [3u8; 32];
        db.note_pending_blob_request(hash, "https://example.com/drive".into());

        assert_eq!(
            db.take_pending_blob_request(&hash),
            Some("https://example.com/drive".to_string())
        );
    }
}
