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
//! `discovery_n0()`. Pkarr maps: drive_did → [NodeID, NodeID, ...] in the
//! `_atomic_nodes` TXT record, and drive_did → [http origin, ...] in the
//! `_atomic_http` TXT record, for clients that speak HTTP but not Iroh, such
//! as a browser opening a capability link that names only the drive.

use crate::errors::AtomicResult;

/// The pkarr relay URL to use for publishing and resolving.
const RELAY_URL: &str = "https://dns.iroh.link/pkarr";

/// TXT record holding the JSON array of Iroh NodeIDs serving a drive.
const NODES_RECORD: &str = "_atomic_nodes";
/// TXT record holding the JSON array of http(s) origins serving a drive.
const HTTP_RECORD: &str = "_atomic_http";

/// Publish an Iroh NodeID for a drive via the pkarr relay.
/// The record is keyed by a pkarr keypair derived from the drive's DID.
/// Multiple NodeIDs (one per replica) are stored as a JSON array in a TXT record.
pub async fn publish_node_id(drive_did: &str, iroh_node_id: &str) -> AtomicResult<()> {
    publish(drive_did, Some(iroh_node_id), None).await
}

/// Publish what this node offers for a drive: its Iroh NodeID, its http(s)
/// origin, or both. Existing entries in the record are kept, so replicas add
/// themselves rather than overwrite each other.
pub async fn publish(
    drive_did: &str,
    iroh_node_id: Option<&str>,
    http_origin: Option<&str>,
) -> AtomicResult<()> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;

    let client = build_client()?;
    let existing = client.resolve(&keypair.public_key()).await;
    let mut node_ids = existing
        .as_ref()
        .map(|p| txt_json_list(p, NODES_RECORD))
        .unwrap_or_default();
    let mut origins = existing
        .as_ref()
        .map(|p| txt_json_list(p, HTTP_RECORD))
        .unwrap_or_default();

    if let Some(id) = iroh_node_id {
        if !node_ids.iter().any(|x| x == id) {
            node_ids.push(id.to_string());
        }
    }
    if let Some(origin) = http_origin {
        if !origins.iter().any(|x| x == origin) {
            origins.push(origin.to_string());
        }
    }

    let mut builder = pkarr::SignedPacket::builder();
    if !node_ids.is_empty() {
        let value = serde_json::to_string(&node_ids)
            .map_err(|e| format!("Failed to serialize NodeID list: {e}"))?;
        builder = builder.txt(
            NODES_RECORD.try_into().unwrap(),
            value.as_str().try_into().unwrap(),
            300,
        );
    }
    if !origins.is_empty() {
        let value = serde_json::to_string(&origins)
            .map_err(|e| format!("Failed to serialize origin list: {e}"))?;
        builder = builder.txt(
            HTTP_RECORD.try_into().unwrap(),
            value.as_str().try_into().unwrap(),
            300,
        );
    }

    let packet = builder
        .build(&keypair)
        .map_err(|e| format!("Failed to build signed packet: {e}"))?;

    client
        .publish(&packet, None)
        .await
        .map_err(|e| format!("Failed to publish to pkarr relay: {e}"))?;

    tracing::debug!(
        "Discovery: published for drive {} ({} peers, {} http origins)",
        drive_did,
        node_ids.len(),
        origins.len()
    );
    Ok(())
}

/// Resolve the http(s) origins that serve a drive, via the pkarr relay.
pub async fn resolve_http_origins(drive_did: &str) -> AtomicResult<Vec<String>> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    let client = build_client()?;
    Ok(client
        .resolve(&keypair.public_key())
        .await
        .map(|p| txt_json_list(&p, HTTP_RECORD))
        .unwrap_or_default())
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
    client
        .resolve(public_key)
        .await
        .map(|p| txt_json_list(&p, NODES_RECORD))
        .unwrap_or_default()
}

/// The JSON string array stored in the TXT record called `name`, or empty.
fn txt_json_list(packet: &pkarr::SignedPacket, name: &str) -> Vec<String> {
    for record in packet.all_resource_records() {
        if !record.name.to_string().contains(name) {
            continue;
        }
        if let pkarr::dns::rdata::RData::TXT(txt) = &record.rdata {
            if let Ok(text) = String::try_from(txt.clone()) {
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&text) {
                    return list;
                }
            }
        }
    }
    vec![]
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
    let raw = drive_did
        .strip_prefix("did:ad:")
        .ok_or_else(|| format!("Not a did:ad DID: {drive_did}"))?;
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

    /// Pinned so the browser library's derivation (`pkarr.ts`) can be checked
    /// against this one: same DID, same relay key.
    #[test]
    fn keypair_matches_browser_vector() {
        let did = fake_drive_did(0x42);
        let k = drive_did_to_pkarr_keypair(&did).unwrap();
        assert_eq!(
            k.public_key().to_string(),
            "rfjxtwc5xrq1etj1emoi6mimp15h96u5pjxpgyrz1a8ypgrb5cjy"
        );
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

        // A second replica adds its http origin; the NodeID stays.
        publish(&drive_did, None, Some("https://drive.example.org"))
            .await
            .expect("publish origin should succeed via pkarr relay");
        let origins = resolve_http_origins(&drive_did)
            .await
            .expect("resolve origins");
        assert!(origins.contains(&"https://drive.example.org".to_string()));
        assert_eq!(
            resolve_node_id_filtered(&drive_did, None).await.unwrap(),
            node_id
        );
        println!("SUCCESS: pkarr relay publish + resolve works");
    }
}
