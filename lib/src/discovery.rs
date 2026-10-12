//! Peer discovery via pkarr relay.
//!
//! Publishes and resolves Iroh NodeIDs for drives using the pkarr relay network.
//! Works through any NAT — uses HTTP, not raw UDP like mainline DHT.
//!
//! Key = drive DID. We derive a pkarr ed25519 keypair from the first 32 bytes
//! of the drive's genesis signature (the DID's decoded payload). Any node
//! that knows the DID can derive the same keypair — so **replicas can
//! announce without holding the drive's private key**, matching the
//! "any node can replicate and serve a Drive" principle in `docs/src/did.md`.
//!
//! Trust comes from commit signatures at the data layer, not from who
//! published the pkarr record — so the keypair being publicly derivable is
//! fine. A malicious peer that announces itself for a drive gets rejected
//! the moment the client checks commit signatures.
//!
//! Addressing (relay URL, direct addresses) is handled by Iroh's
//! `discovery_n0()`. Pkarr only maps: drive_did → [NodeID, NodeID, ...].

use crate::errors::AtomicResult;

/// The pkarr relay URL to use for publishing and resolving.
const RELAY_URL: &str = "https://dns.iroh.link/pkarr";

/// TXT label holding the JSON array of Iroh NodeIDs.
const NODES_LABEL: &str = "_atomic_nodes";
/// TXT label holding the JSON array of public https origins. A browser tab
/// cannot dial Iroh, but it can read the relay over https and fetch from these.
pub const HTTP_LABEL: &str = "_atomic_http";
const NODES_TTL: u32 = 300;
const HTTP_TTL: u32 = 3600;

/// What a drive's pkarr record holds: where its replicas can be reached.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DriveRecord {
    /// Iroh NodeIDs (`_atomic_nodes`).
    pub node_ids: Vec<String>,
    /// Public https origins (`_atomic_http`), normalized.
    pub http_origins: Vec<String>,
}

/// Turn a configured public URL into the origin we may announce, or `None`
/// when it is not reachable by anyone else: not https, `localhost`, an IP
/// address, a single-label or `.local` host, or not a URL at all.
pub fn public_https_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = match parsed.host()? {
        url::Host::Domain(d) => d.to_ascii_lowercase(),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    let host = host.trim_end_matches('.');
    if !host.contains('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return None;
    }
    Some(match parsed.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

/// Add `item` to `list` unless it is already there.
fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|i| i == item) {
        list.push(item.to_string());
    }
}

/// Build the signed packet for a drive. Both TXT records are written when
/// their list is not empty.
fn build_packet(
    keypair: &pkarr::Keypair,
    record: &DriveRecord,
) -> AtomicResult<pkarr::SignedPacket> {
    let mut builder = pkarr::SignedPacket::builder();
    let nodes = serde_json::to_string(&record.node_ids)
        .map_err(|e| format!("Failed to serialize NodeID list: {e}"))?;
    let origins = serde_json::to_string(&record.http_origins)
        .map_err(|e| format!("Failed to serialize origin list: {e}"))?;
    if !record.node_ids.is_empty() {
        builder = builder.txt(
            NODES_LABEL.try_into().unwrap(),
            nodes
                .as_str()
                .try_into()
                .map_err(|e| format!("NodeID list does not fit a TXT record: {e}"))?,
            NODES_TTL,
        );
    }
    if !record.http_origins.is_empty() {
        builder = builder.txt(
            HTTP_LABEL.try_into().unwrap(),
            origins
                .as_str()
                .try_into()
                .map_err(|e| format!("Origin list does not fit a TXT record: {e}"))?,
            HTTP_TTL,
        );
    }
    builder
        .build(keypair)
        .map_err(|e| format!("Failed to build signed packet: {e}").into())
}

/// Publish this replica for a drive: its Iroh NodeID and / or its public https
/// origin. Existing entries (other replicas, and the record this call does not
/// touch) are kept, so the packet always carries every known value.
/// `http_origin` goes through [`public_https_origin`]; an unusable one is
/// skipped. Does nothing when there is nothing to publish.
pub async fn publish_drive_record(
    drive_did: &str,
    iroh_node_id: Option<&str>,
    http_origin: Option<&str>,
) -> AtomicResult<()> {
    let origin = http_origin.and_then(public_https_origin);
    if iroh_node_id.is_none() && origin.is_none() {
        return Ok(());
    }
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    let client = build_client()?;
    let mut record = resolve_record_raw(&client, &keypair.public_key()).await;

    if let Some(id) = iroh_node_id {
        push_unique(&mut record.node_ids, id);
    }
    if let Some(origin) = &origin {
        push_unique(&mut record.http_origins, origin);
    }

    let packet = build_packet(&keypair, &record)?;
    client
        .publish(&packet, None)
        .await
        .map_err(|e| format!("Failed to publish to pkarr relay: {e}"))?;

    tracing::debug!(
        "Discovery: published drive {} ({} NodeIDs, {} origins)",
        drive_did,
        record.node_ids.len(),
        record.http_origins.len()
    );
    Ok(())
}

/// Publish an Iroh NodeID for a drive via the pkarr relay.
/// The record is keyed by a pkarr keypair derived from the drive's DID.
/// Multiple NodeIDs (one per replica) are stored as a JSON array in a TXT record.
pub async fn publish_node_id(drive_did: &str, iroh_node_id: &str) -> AtomicResult<()> {
    publish_drive_record(drive_did, Some(iroh_node_id), None).await
}

/// Resolve the public https origins announced for a drive.
pub async fn resolve_http_origins(drive_did: &str) -> AtomicResult<Vec<String>> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    let client = build_client()?;
    Ok(resolve_record_raw(&client, &keypair.public_key())
        .await
        .http_origins)
}

/// Resolve Iroh NodeIDs for a drive via the pkarr relay.
/// Returns the first NodeID that isn't our own.
pub async fn resolve_node_id(drive_did: &str) -> AtomicResult<String> {
    #[cfg(feature = "iroh")]
    let my_node_id = crate::sync::peer::get_node_id().map(|s| s.to_string());
    #[cfg(not(feature = "iroh"))]
    let my_node_id: Option<String> = None;

    resolve_node_id_filtered(drive_did, my_node_id.as_deref()).await
}

/// Resolve Iroh NodeIDs for a drive, filtering out `exclude_node_id` if provided.
pub async fn resolve_node_id_filtered(
    drive_did: &str,
    exclude_node_id: Option<&str>,
) -> AtomicResult<String> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    let client = build_client()?;
    let node_ids = resolve_node_ids_raw(&client, &keypair.public_key()).await;

    if node_ids.is_empty() {
        return Err(format!("No peers found for drive {drive_did}").into());
    }

    let peer = node_ids
        .iter()
        .find(|id| {
            if let Some(exclude) = exclude_node_id {
                id.as_str() != exclude
            } else {
                true
            }
        })
        .ok_or_else(|| {
            format!(
                "Found {} NodeID(s) but all are ours ({})",
                node_ids.len(),
                exclude_node_id.unwrap_or("?")
            )
        })?;

    tracing::debug!(
        "Discovery: resolved peer {} for drive {}",
        &peer[..peer.len().min(16)],
        drive_did
    );
    Ok(peer.clone())
}

/// Resolve all NodeIDs from the pkarr relay for a given public key.
async fn resolve_node_ids_raw(
    client: &pkarr::Client,
    public_key: &pkarr::PublicKey,
) -> Vec<String> {
    resolve_record_raw(client, public_key).await.node_ids
}

/// Resolve both lists from the pkarr relay for a given public key.
async fn resolve_record_raw(client: &pkarr::Client, public_key: &pkarr::PublicKey) -> DriveRecord {
    match client.resolve(public_key).await {
        Some(packet) => parse_record(&packet),
        None => DriveRecord::default(),
    }
}

/// The JSON string array in the TXT record named `label`, or empty.
fn txt_json_list(packet: &pkarr::SignedPacket, label: &str) -> Vec<String> {
    for record in packet.all_resource_records() {
        if record.name.to_string().split('.').next() != Some(label) {
            continue;
        }
        if let pkarr::dns::rdata::RData::TXT(txt) = &record.rdata {
            if let Ok(content) = String::try_from(txt.clone()) {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&content) {
                    return list;
                }
            }
        }
    }
    vec![]
}

fn parse_record(packet: &pkarr::SignedPacket) -> DriveRecord {
    DriveRecord {
        node_ids: txt_json_list(packet, NODES_LABEL),
        // Re-normalize: the packet is public, anyone may have written to it.
        http_origins: txt_json_list(packet, HTTP_LABEL)
            .iter()
            .filter_map(|o| public_https_origin(o))
            .collect(),
    }
}

/// Derive a pkarr keypair from a drive DID.
///
/// A `did:ad:{genesis}` subject encodes the drive's 64-byte ed25519 genesis
/// signature as base64. We use the first 32 bytes of that signature as the
/// pkarr keypair seed. This is deterministic from the public DID string, so
/// any node (including replicas that don't hold the drive owner's key) can
/// derive the same keypair and publish records for the drive.
///
/// Accepts DID strings with an optional `?drive=...` routing hint, which is
/// stripped before decoding.
fn drive_did_to_pkarr_keypair(drive_did: &str) -> AtomicResult<pkarr::Keypair> {
    let raw = crate::identifiers::identifier_rest(drive_did)
        .ok_or_else(|| format!("Not an atomic: / did:ad: identifier: {drive_did}"))?;
    // Agent DIDs and commit DIDs aren't drives; they have different payload
    // lengths and semantics. Reject early rather than silently producing a
    // meaningless keypair.
    if raw.starts_with("agent:") || raw.starts_with("commit:") {
        return Err(
            format!("drive_did_to_pkarr_keypair called with non-drive DID: {drive_did}").into(),
        );
    }
    let genesis_b64 = raw.split('?').next().unwrap_or(raw);
    let sig = crate::agents::decode_base64(genesis_b64)
        .map_err(|e| format!("DID genesis base64 decode failed: {e}"))?;
    if sig.len() != 64 {
        return Err(format!(
            "Expected 64-byte genesis signature, got {} bytes",
            sig.len()
        )
        .into());
    }
    let seed: [u8; 32] = sig[..32]
        .try_into()
        .expect("slice [..32] of 64-byte vec is always 32 bytes");
    Ok(pkarr::Keypair::from_secret_key(&seed))
}

fn build_client() -> AtomicResult<pkarr::Client> {
    let mut builder = pkarr::Client::builder();
    builder.no_default_network();
    builder
        .relays(&[RELAY_URL])
        .map_err(|e| format!("Invalid relay URL: {e}"))?;
    let client = builder
        .build()
        .map_err(|e| format!("Failed to build pkarr client: {e}"))?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `did:ad:{...}` whose base64 payload decodes to exactly
    /// 64 bytes, satisfying `drive_did_to_pkarr_keypair`'s shape check.
    fn fake_drive_did(seed_byte: u8) -> String {
        let sig = [seed_byte; 64];
        format!("did:ad:{}", crate::agents::encode_base64(&sig))
    }

    #[test]
    fn drive_did_to_keypair_roundtrip_is_deterministic() {
        let did = fake_drive_did(0x42);
        let k1 = drive_did_to_pkarr_keypair(&did).unwrap();
        let k2 = drive_did_to_pkarr_keypair(&did).unwrap();
        assert_eq!(k1.public_key().to_string(), k2.public_key().to_string());
    }

    #[test]
    fn packet_carries_both_txt_records() {
        let keypair = drive_did_to_pkarr_keypair(&fake_drive_did(0x21)).unwrap();
        let record = DriveRecord {
            node_ids: vec!["aa".repeat(32)],
            http_origins: vec!["https://a.example.com".into()],
        };
        let packet = build_packet(&keypair, &record).unwrap();
        assert_eq!(parse_record(&packet), record);
        let names: Vec<String> = packet
            .all_resource_records()
            .map(|r| r.name.to_string())
            .collect();
        assert!(names.iter().any(|n| n.starts_with("_atomic_nodes.")));
        assert!(names.iter().any(|n| n.starts_with("_atomic_http.")));
        assert_eq!(packet.public_key(), keypair.public_key());
    }

    #[test]
    fn packet_with_only_origins_has_no_nodes_record() {
        let keypair = drive_did_to_pkarr_keypair(&fake_drive_did(0x22)).unwrap();
        let record = DriveRecord {
            node_ids: vec![],
            http_origins: vec!["https://a.example.com".into()],
        };
        let packet = build_packet(&keypair, &record).unwrap();
        assert_eq!(parse_record(&packet), record);
    }

    #[test]
    fn merging_keeps_other_origins_and_does_not_duplicate() {
        let mut origins = vec!["https://other.example.org".to_string()];
        push_unique(&mut origins, "https://mine.example.com");
        push_unique(&mut origins, "https://mine.example.com");
        assert_eq!(
            origins,
            vec!["https://other.example.org", "https://mine.example.com"]
        );
    }

    #[test]
    fn many_origins_survive_txt_chunking() {
        let keypair = drive_did_to_pkarr_keypair(&fake_drive_did(0x23)).unwrap();
        let origins: Vec<String> = (0..8)
            .map(|i| format!("https://replica-number-{i}.example.com"))
            .collect();
        let record = DriveRecord {
            node_ids: vec![],
            http_origins: origins,
        };
        let packet = build_packet(&keypair, &record).unwrap();
        assert_eq!(parse_record(&packet), record);
    }

    #[test]
    fn unusable_origins_are_skipped() {
        for bad in [
            "http://atomic.example.com",
            "https://localhost",
            "https://localhost:9884",
            "https://foo.localhost",
            "https://127.0.0.1",
            "https://192.168.1.4:9884",
            "https://[::1]",
            "https://intranet",
            "https://printer.local",
            "not a url",
            "",
        ] {
            assert_eq!(public_https_origin(bad), None, "{bad}");
        }
        assert_eq!(
            public_https_origin("https://Atomic.Example.com/some/path?x=1").as_deref(),
            Some("https://atomic.example.com")
        );
        assert_eq!(
            public_https_origin("https://atomic.example.com:8443/").as_deref(),
            Some("https://atomic.example.com:8443")
        );
        assert_eq!(
            public_https_origin("https://atomic.example.com:443/").as_deref(),
            Some("https://atomic.example.com")
        );
    }

    #[test]
    fn parsing_drops_bad_origins_from_a_public_packet() {
        let keypair = drive_did_to_pkarr_keypair(&fake_drive_did(0x24)).unwrap();
        let record = DriveRecord {
            node_ids: vec![],
            http_origins: vec![
                "http://insecure.example.com".into(),
                "https://ok.example.com".into(),
            ],
        };
        let packet = build_packet(&keypair, &record).unwrap();
        assert_eq!(
            parse_record(&packet).http_origins,
            vec!["https://ok.example.com"]
        );
    }

    /// Prints a packet for the TypeScript fixture. Run with
    /// `cargo test -p atomic_lib --features db-redb --lib print_ts_fixture -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn print_ts_fixture() {
        let did = fake_drive_did(0x42);
        let keypair = drive_did_to_pkarr_keypair(&did).unwrap();
        let record = DriveRecord {
            node_ids: vec!["aa".repeat(32)],
            http_origins: vec![
                "https://atomic.example.com".into(),
                "https://replica.example.org:8443".into(),
            ],
        };
        let packet = build_packet(&keypair, &record).unwrap();
        println!("DID={did}");
        println!("Z32={}", keypair.public_key().to_z32());
        println!("HEX={}", hex_of(packet.as_bytes()));
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rejects_non_drive_dids() {
        assert!(drive_did_to_pkarr_keypair("did:ad:agent:foo").is_err());
        assert!(drive_did_to_pkarr_keypair("did:ad:commit:foo").is_err());
        assert!(drive_did_to_pkarr_keypair("https://example.com/").is_err());
    }

    // Network test — requires outbound HTTPS to the pkarr relay. Ignored by
    // default; run explicitly with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn publish_and_resolve_via_pkarr_relay() {
        let drive_did = fake_drive_did(0x17);
        let node_id = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        publish_node_id(&drive_did, node_id)
            .await
            .expect("publish should succeed via pkarr relay");

        let resolved = resolve_node_id_filtered(&drive_did, None)
            .await
            .expect("resolve should find the published NodeID");

        assert_eq!(resolved, node_id);
        println!("SUCCESS: pkarr relay publish + resolve works");
    }
}
