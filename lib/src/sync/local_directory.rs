//! Finding the devices that hold a drive without the internet: on the same
//! machine or Wi-Fi.
//!
//! Iroh's mDNS discovery (`discovery_local_network()`) resolves addresses for
//! node ids we already know. Which devices hold a drive normally comes from
//! pkarr (see `host::peer_search`), and offline nobody answers. This module
//! closes that gap with the *user data* of Iroh's discovery: each device
//! advertises a short opaque tag for every drive it searches, and listens to
//! the other devices on the network doing the same. A node whose tags contain
//! a drive's tag holds (or looks for) that drive.
//!
//! - The tag ([`drive_tag`]) is the first 8 bytes of SHA-256 of the drive
//!   subject, base64url: the raw DID never goes on the network.
//! - The user data ([`encode_user_data`]) is `ad1:` plus the tags, comma
//!   separated, and must fit Iroh's [`UserData::MAX_LENGTH`] (245 bytes). That
//!   is [`MAX_TAGS`] drives. Past it the drives *after* the first
//!   [`MAX_TAGS`] of the list are simply not advertised (the caller lists the
//!   active drive first); they are still found through pkarr.
//! - [`listen`] records every discovery item with such user data in a table,
//!   [`nearby`] reads it (newest first).
//!
//! The tags are part of the endpoint's user data, so Iroh publishes them to
//! its other discovery services (the n0 DNS record) too, not only to mDNS.
//! They are a truncated hash, they identify a drive only to someone who
//! already knows its subject.

use base64::Engine;
use iroh::discovery::UserData;
use iroh::Endpoint;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Prefix of our user data, so other users of the field are ignored.
const PREFIX: &str = "ad1:";
/// Bytes of the hash in a tag.
const TAG_BYTES: usize = 8;
/// A tag is 8 bytes in base64url without padding: 11 characters.
const TAG_LEN: usize = 11;
/// How many drives fit the user data: `4 + n * 11 + (n - 1) <= 245`.
pub const MAX_TAGS: usize = (UserData::MAX_LENGTH - PREFIX.len() + 1) / (TAG_LEN + 1);

/// A node seen on the network is forgotten after this long without being
/// heard again (devices re-announce every few seconds).
pub const SEEN_TTL: Duration = Duration::from_secs(120);

/// The opaque tag of a drive, as advertised on the local network.
pub fn drive_tag(drive: &str) -> String {
    let hash = Sha256::digest(drive.trim().as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash[..TAG_BYTES])
}

/// The user data for these drives: tags of the first [`MAX_TAGS`] distinct
/// drives, in order. `None` for no drives.
pub fn encode_user_data(drives: &[String]) -> Option<UserData> {
    let mut tags: Vec<String> = Vec::new();
    for drive in drives {
        let tag = drive_tag(drive);
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    if tags.is_empty() {
        return None;
    }
    if tags.len() > MAX_TAGS {
        tracing::warn!(
            "[local_directory] {} drives, advertising the first {MAX_TAGS} on the local network",
            tags.len()
        );
        tags.truncate(MAX_TAGS);
    }
    format!("{PREFIX}{}", tags.join(",")).parse().ok()
}

/// The tags in a device's user data; `None` when it is not ours.
pub fn parse_user_data(data: &str) -> Option<Vec<String>> {
    let rest = data.strip_prefix(PREFIX)?;
    Some(
        rest.split(',')
            .filter(|t| t.len() == TAG_LEN)
            .map(String::from)
            .collect(),
    )
}

struct Seen {
    tags: Vec<String>,
    at: Instant,
}

/// Nodes heard on the local network, by lowercase node id.
static SEEN: Mutex<Option<HashMap<String, Seen>>> = Mutex::new(None);
/// The tags to advertise, kept to apply when the endpoint starts later.
static ADVERTISED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record(node_id: &str, tags: Vec<String>) {
    SEEN.lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(
            node_id.to_ascii_lowercase(),
            Seen {
                tags,
                at: Instant::now(),
            },
        );
}

/// Node ids heard on the local network within [`SEEN_TTL`] that advertise
/// `drive`, most recently heard first. `own` (this device) is left out.
pub fn nearby(drive: &str, own: &str) -> Vec<String> {
    nearby_within(drive, own, SEEN_TTL)
}

fn nearby_within(drive: &str, own: &str, ttl: Duration) -> Vec<String> {
    let tag = drive_tag(drive);
    let own = own.trim().to_ascii_lowercase();
    let guard = SEEN.lock().unwrap();
    let Some(map) = guard.as_ref() else {
        return Vec::new();
    };
    let mut found: Vec<(&String, Instant)> = map
        .iter()
        .filter(|(id, s)| **id != own && s.at.elapsed() <= ttl && s.tags.contains(&tag))
        .map(|(id, s)| (id, s.at))
        .collect();
    found.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
    found.into_iter().map(|(id, _)| id.clone()).collect()
}

/// Advertise these drives on `endpoint` (replacing the previous list).
pub fn advertise_on(endpoint: &Endpoint, drives: &[String]) {
    endpoint.set_user_data_for_discovery(encode_user_data(drives));
}

/// Advertise these drives on the endpoint [`super::peer::start`] started; if
/// it is not up yet, they are applied when it starts.
pub fn advertise(drives: &[String]) {
    *ADVERTISED.lock().unwrap() = drives.to_vec();
    if let Some(endpoint) = super::peer::endpoint() {
        advertise_on(endpoint, drives);
    }
}

/// The drives last given to [`advertise`], for an endpoint that starts after.
pub(crate) fn advertised_drives() -> Vec<String> {
    ADVERTISED.lock().unwrap().clone()
}

/// Listen to the discovery items of `endpoint` and record the nodes that
/// advertise tags. Runs until the endpoint is dropped. Only the local network
/// provenance counts: tags that came through a relay's DNS record are not
/// "nearby".
pub fn listen(endpoint: &Endpoint) -> tokio::task::JoinHandle<()> {
    use futures::StreamExt;
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let stream = endpoint.discovery_stream();
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let Ok(item) = item else { continue };
            if item.provenance() != iroh::discovery::mdns::NAME {
                continue;
            }
            let Some(data) = item.user_data() else {
                continue;
            };
            if let Some(tags) = parse_user_data(&data.to_string()) {
                record(&item.node_id().to_string(), tags);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_eleven_url_safe_characters_and_hides_the_drive() {
        let tag = drive_tag("did:ad:drive-one");
        assert_eq!(tag.len(), TAG_LEN);
        assert!(tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!tag.contains("drive"));
        assert_eq!(tag, drive_tag(" did:ad:drive-one "), "trimmed");
        assert_ne!(tag, drive_tag("did:ad:drive-two"));
    }

    #[test]
    fn user_data_round_trips_and_ignores_duplicates() {
        let drives = vec!["did:ad:a".to_string(), "did:ad:b".into(), "did:ad:a".into()];
        let data = encode_user_data(&drives).unwrap().to_string();
        let tags = parse_user_data(&data).unwrap();
        assert_eq!(tags, vec![drive_tag("did:ad:a"), drive_tag("did:ad:b")]);
        assert!(encode_user_data(&[]).is_none());
        assert!(parse_user_data("something else").is_none());
        assert!(parse_user_data("ad1:short,").unwrap().is_empty());
    }

    #[test]
    fn past_the_limit_only_the_first_drives_are_advertised() {
        assert_eq!(MAX_TAGS, 20);
        let drives: Vec<String> = (0..MAX_TAGS + 5).map(|i| format!("did:ad:{i}")).collect();
        let data = encode_user_data(&drives).unwrap().to_string();
        assert!(data.len() <= UserData::MAX_LENGTH);
        let tags = parse_user_data(&data).unwrap();
        assert_eq!(tags.len(), MAX_TAGS);
        assert_eq!(
            tags[0],
            drive_tag("did:ad:0"),
            "the first (active) drive stays"
        );
        assert!(!tags.contains(&drive_tag(&format!("did:ad:{MAX_TAGS}"))));
    }

    #[test]
    fn nearby_matches_the_drive_tag_newest_first_and_expires() {
        let drive = "did:ad:nearby-test-drive";
        record("nearby-old", vec![drive_tag(drive)]);
        std::thread::sleep(Duration::from_millis(5));
        record("NEARBY-NEW", vec![drive_tag("did:ad:x"), drive_tag(drive)]);
        record("nearby-other", vec![drive_tag("did:ad:other")]);
        record("nearby-me", vec![drive_tag(drive)]);
        assert_eq!(
            nearby(drive, "NEARBY-ME"),
            vec!["nearby-new", "nearby-old"],
            "own id and other drives left out"
        );
        assert!(nearby_within(drive, "x", Duration::ZERO).is_empty());
    }

    /// Two endpoints in one process, no relay and no pkarr: B learns that A
    /// holds the drive from A's mDNS user data alone.
    #[tokio::test]
    async fn two_endpoints_find_each_other_through_local_discovery_user_data() {
        use iroh::RelayMode;
        let drive = "did:ad:two-endpoints-drive";
        let bind = || async {
            Endpoint::builder()
                .relay_mode(RelayMode::Disabled)
                .discovery_local_network()
                .bind()
                .await
                .unwrap()
        };
        let a = bind().await;
        let b = bind().await;
        let _listener = listen(&b);
        advertise_on(&a, &[drive.to_string(), "did:ad:another".to_string()]);

        let a_id = a.node_id().to_string();
        let b_id = b.node_id().to_string();
        let found = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let ids = nearby(drive, &b_id);
                if ids.contains(&a_id) {
                    return ids;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("B never heard A's drive tag over mDNS");
        assert_eq!(found, vec![a_id.clone()]);
        assert!(nearby("did:ad:not-advertised", &b_id).is_empty());
    }
}
