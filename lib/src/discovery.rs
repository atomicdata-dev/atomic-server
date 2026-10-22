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
/// How many NodeIDs a record keeps. Every install publishes a fresh one and
/// nothing removes it, so without a cap the record fills with dead devices
/// (and stops fitting a TXT record). The newest replicas are kept.
const MAX_NODE_IDS: usize = 6;
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

/// Put `id` first (resolvers try the list in order) and drop the oldest
/// entries beyond [`MAX_NODE_IDS`].
fn add_node_id(node_ids: &mut Vec<String>, id: &str) {
    node_ids.retain(|existing| existing != id);
    node_ids.insert(0, id.to_string());
    node_ids.truncate(MAX_NODE_IDS);
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
///
/// The record is shared by every replica of the drive, so this is a
/// read-modify-write by many writers. Two rules keep one writer from erasing
/// the others:
/// - when the current record cannot be read (relay unreachable, a timeout, a
///   5xx), nothing is published: a packet built from an empty read would name
///   this replica alone and drop every other device from the drive;
/// - the write names the timestamp it read (compare-and-swap); when another
///   replica wrote in between, the record is read again and merged again.
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

    const ATTEMPTS: usize = 3;
    let mut last_conflict = String::new();
    for attempt in 0..ATTEMPTS {
        let current = fetch_packet(&keypair.public_key()).await.map_err(|e| {
            format!("Not publishing drive record: could not read the current one first ({e})")
        })?;
        let mut record = current.as_ref().map(parse_record).unwrap_or_default();
        let cas = current.as_ref().map(|p| p.timestamp());
        let before = record.clone();

        if let Some(id) = iroh_node_id {
            add_node_id(&mut record.node_ids, id);
        }
        if let Some(origin) = &origin {
            push_unique(&mut record.http_origins, origin);
        }

        let packet = build_packet(&keypair, &record)?;
        match client.publish(&packet, cas).await {
            Ok(()) => {
                tracing::info!(
                    "Discovery: published drive {} ({} NodeIDs, {} origins; read {} NodeIDs{})",
                    short(drive_did),
                    record.node_ids.len(),
                    record.http_origins.len(),
                    before.node_ids.len(),
                    if attempt > 0 {
                        ", after a conflict"
                    } else {
                        ""
                    }
                );
                return Ok(());
            }
            Err(pkarr::errors::PublishError::Concurrency(e)) => {
                tracing::info!(
                    "Discovery: drive {} changed while publishing ({e}), merging again",
                    short(drive_did)
                );
                last_conflict = e.to_string();
                continue;
            }
            Err(e) => return Err(format!("Failed to publish to pkarr relay: {e}").into()),
        }
    }
    Err(
        format!("Failed to publish to pkarr relay after {ATTEMPTS} conflicts: {last_conflict}")
            .into(),
    )
}

fn short(did: &str) -> &str {
    &did[..did.len().min(24)]
}

/// Publish an Iroh NodeID for a drive via the pkarr relay.
/// The record is keyed by a pkarr keypair derived from the drive's DID.
/// Multiple NodeIDs (one per replica) are stored as a JSON array in a TXT record.
pub async fn publish_node_id(drive_did: &str, iroh_node_id: &str) -> AtomicResult<()> {
    publish_drive_record(drive_did, Some(iroh_node_id), None).await
}

/// Resolve Iroh NodeIDs for a drive via the pkarr relay.
/// Returns the first NodeID that isn't our own.
pub async fn resolve_node_id(drive_did: &str) -> AtomicResult<String> {
    #[cfg(feature = "iroh")]
    let my_node_id = crate::sync::peer::get_node_id().map(|s| s.to_string());
    #[cfg(not(feature = "iroh"))]
    let my_node_id: Option<String> = None;

    let ids = resolve_node_ids_filtered(drive_did, my_node_id.as_deref()).await?;
    Ok(ids.into_iter().next().expect("not empty"))
}

/// Every NodeID the drive's record names except `exclude_node_id`, newest
/// first. Records keep the replicas of uninstalled apps too, so a caller
/// should try several rather than trust the first. Errors when none is left.
/// The NodeIDs the drive's pkarr record names, without `exclude_node_id`
/// (this device's own). Empty, not an error, when the record names no other
/// device: for a drive on one device that is the normal case, nothing went
/// wrong.
pub async fn resolve_other_node_ids(
    drive_did: &str,
    exclude_node_id: Option<&str>,
) -> AtomicResult<Vec<String>> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    let node_ids = resolve_record_raw(&keypair.public_key()).await?.node_ids;
    let others = other_node_ids(node_ids.clone(), exclude_node_id);
    tracing::info!(
        "Discovery: drive {} names {} NodeIDs, {} of other devices",
        short(drive_did),
        node_ids.len(),
        others.len()
    );
    Ok(others)
}

fn other_node_ids(node_ids: Vec<String>, exclude_node_id: Option<&str>) -> Vec<String> {
    node_ids
        .into_iter()
        .filter(|id| Some(id.as_str()) != exclude_node_id)
        .collect()
}

pub async fn resolve_node_ids_filtered(
    drive_did: &str,
    exclude_node_id: Option<&str>,
) -> AtomicResult<Vec<String>> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    let node_ids = resolve_record_raw(&keypair.public_key()).await?.node_ids;

    if node_ids.is_empty() {
        return Err(format!("No peers found for drive {drive_did}").into());
    }
    let total = node_ids.len();
    let peers = other_node_ids(node_ids, exclude_node_id);
    if peers.is_empty() {
        return Err(format!(
            "Found {total} NodeID(s) but all are ours ({})",
            exclude_node_id.unwrap_or("?")
        )
        .into());
    }
    tracing::debug!(
        "Discovery: resolved {} peers for drive {}",
        peers.len(),
        drive_did
    );
    Ok(peers)
}

/// The newest NodeID [`resolve_node_ids_filtered`] finds.
pub async fn resolve_node_id_filtered(
    drive_did: &str,
    exclude_node_id: Option<&str>,
) -> AtomicResult<String> {
    Ok(resolve_node_ids_filtered(drive_did, exclude_node_id)
        .await?
        .remove(0))
}

/// What the pkarr relay says about where a drive lives: its replicas' Iroh
/// NodeIDs and public https origins. Anyone may have written to the record, so
/// an origin from it proves nothing until its genesis answer passes
/// [`genesis_body_verifies`].
pub async fn resolve_drive_record(drive_did: &str) -> AtomicResult<DriveRecord> {
    let keypair = drive_did_to_pkarr_keypair(drive_did)?;
    resolve_record_raw(&keypair.public_key()).await
}

const MAX_GENESIS_BODY_BYTES: usize = 256 * 1024;

/// Whether `body` (the answer of `GET /genesis?subject=<drive>`) carries the
/// drive's own genesis certificate and it verifies against the DID.
///
/// The DID is the genesis signature, so this is self-certifying: nobody
/// without the owner's key can produce a certificate that signs to it,
/// wherever they host it. A server that merely answers, or serves some other
/// drive, does not pass.
pub fn genesis_body_verifies(body: &str, drive_did: &str) -> bool {
    if body.len() > MAX_GENESIS_BODY_BYTES {
        return false;
    }
    let Some(signature) = crate::identifiers::identifier_body(drive_did) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(encoded) = json
        .get(crate::urls::GENESIS)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    else {
        return false;
    };
    let Ok(bytes) = crate::agents::decode_base64(encoded) else {
        return false;
    };
    crate::genesis::GenesisCert::decode(&bytes)
        .and_then(|cert| cert.verify_signed_bytes(&bytes, signature))
        .is_ok()
}

/// Resolve both lists from the pkarr relay for a given public key. Empty when
/// the relay has no record; an error when the relay could not be asked, so a
/// caller can tell "no other device announced this drive" from "we could not
/// look" (`pkarr::Client::resolve` folds both into `None`).
async fn resolve_record_raw(public_key: &pkarr::PublicKey) -> AtomicResult<DriveRecord> {
    Ok(fetch_packet(public_key)
        .await?
        .as_ref()
        .map(parse_record)
        .unwrap_or_default())
}

/// The relay's current packet for `public_key`: `None` for a 404, an error for
/// anything that is not an answer (no network, DNS, TLS, a timeout, a 5xx, a
/// packet that does not verify).
async fn fetch_packet(public_key: &pkarr::PublicKey) -> AtomicResult<Option<pkarr::SignedPacket>> {
    fetch_packet_from(RELAY_URL, public_key).await
}

async fn fetch_packet_from(
    relay: &str,
    public_key: &pkarr::PublicKey,
) -> AtomicResult<Option<pkarr::SignedPacket>> {
    let url = format!("{relay}/{}", public_key.to_z32());
    let client = crate::client::helpers::http_client_builder()
        .build()
        .map_err(|e| format!("pkarr relay client: {e}"))?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("pkarr relay {relay} unreachable: {e}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("pkarr relay {relay} answered {status}").into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("pkarr relay {relay}: reading the answer failed: {e}"))?;
    if body.is_empty() {
        return Ok(None);
    }
    pkarr::SignedPacket::from_relay_payload(public_key, &body)
        .map(Some)
        .map_err(|e| format!("pkarr relay {relay} sent a packet that does not verify: {e}").into())
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

    /// A relay that cannot be reached is an error, not an empty record: an
    /// empty read is what made a publish erase every other device from the
    /// drive's record, and what made a lookup say "no peers online".
    #[tokio::test]
    async fn an_unreachable_relay_is_an_error_not_an_empty_record() {
        let keypair = drive_did_to_pkarr_keypair(&fake_drive_did(0x31)).unwrap();
        let result = fetch_packet_from("http://127.0.0.1:9/pkarr", &keypair.public_key()).await;
        let err = result.expect_err("unreachable relay must be an error");
        assert!(err.to_string().contains("unreachable"), "{err}");
    }

    #[test]
    fn only_our_own_node_id_is_no_other_device() {
        let ours = "aa".repeat(32);
        let theirs = "bb".repeat(32);
        assert!(other_node_ids(vec![ours.clone()], Some(&ours)).is_empty());
        assert_eq!(
            other_node_ids(vec![ours.clone(), theirs.clone()], Some(&ours)),
            vec![theirs]
        );
        assert!(other_node_ids(vec![], Some(&ours)).is_empty());
    }

    /// Builds a `did:ad:{...}` whose base64 payload decodes to exactly
    /// 64 bytes, satisfying `drive_did_to_pkarr_keypair`'s shape check.
    fn fake_drive_did(seed_byte: u8) -> String {
        let sig = [seed_byte; 64];
        format!("did:ad:{}", crate::agents::encode_base64(&sig))
    }

    /// An agent's private-drive DID and the body `GET /genesis` answers for it.
    fn genesis_answer() -> (String, String) {
        let agent = crate::agents::Agent::new(Some("t")).unwrap();
        let private_key = agent.private_key.clone().unwrap();
        let did = crate::genesis::GenesisCert::private_drive_subject(&private_key).unwrap();
        let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
        let body = serde_json::json!({
            "@id": did,
            crate::urls::GENESIS: crate::agents::encode_base64(&cert.encode()),
        })
        .to_string();
        (did, body)
    }

    #[test]
    fn a_genesis_answer_for_the_drive_verifies() {
        let (did, body) = genesis_answer();
        assert!(genesis_body_verifies(&body, &did));
    }

    #[test]
    fn a_genesis_answer_for_another_drive_does_not() {
        let (_, body) = genesis_answer();
        let (other_did, _) = genesis_answer();
        assert!(!genesis_body_verifies(&body, &other_did));
    }

    #[test]
    fn a_missing_or_broken_genesis_does_not_verify() {
        let (did, body) = genesis_answer();
        assert!(!genesis_body_verifies("not json", &did));
        assert!(!genesis_body_verifies("{}", &did));
        let mut json: serde_json::Value = serde_json::from_str(&body).unwrap();
        json[crate::urls::GENESIS] = "AAAA".into();
        assert!(!genesis_body_verifies(&json.to_string(), &did));
        assert!(!genesis_body_verifies(&body, "did:ad:nonsense"));
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
    fn newest_node_id_goes_first_and_old_ones_drop_off() {
        let mut ids: Vec<String> = (0..MAX_NODE_IDS).map(|i| format!("old{i}")).collect();
        add_node_id(&mut ids, "old3");
        assert_eq!(ids[0], "old3");
        assert_eq!(ids.len(), MAX_NODE_IDS);
        add_node_id(&mut ids, "new");
        assert_eq!(ids[0], "new");
        assert_eq!(ids.len(), MAX_NODE_IDS);
        assert!(!ids.contains(&format!("old{}", MAX_NODE_IDS - 1)));
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

        let resolved = resolve_node_ids_filtered(&drive_did, None)
            .await
            .expect("resolve should find the published NodeID");

        assert_eq!(resolved, [node_id]);
        println!("SUCCESS: pkarr relay publish + resolve works");
    }
}
