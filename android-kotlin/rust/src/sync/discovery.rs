//! Finding and asking servers: where a drive is hosted (pkarr), what a server
//! says about itself and what a drive costs on it.

use crate::{
    error::CoreResult,
    state::db,
    types::{DiscoveryResult, DriveUsage, ServerInfo},
};
use atomic_lib::Storelike;
use serde_json::Value as Json;
use std::time::Duration;

const PKARR_RESOLVE_TIMEOUT: Duration = Duration::from_secs(12);
/// How long one origin may take to show its genesis certificate.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_ORIGINS: usize = 3;

/// `GET {origin}/genesis?subject=<drive>` and check the answer is the drive's
/// own certificate (self-certifying: the DID is the genesis signature). The
/// pkarr record is public and anyone may add to it, so no origin is trusted
/// before this passes.
async fn probe(origin: &str, drive: &str) -> Result<(), String> {
    let url = format!("{origin}/genesis?subject={}", url_encode(drive));
    let body = tokio::time::timeout(
        PROBE_TIMEOUT,
        atomic_lib::client::fetch_body(&url, atomic_lib::parse::JSON_AD_MIME, None),
    )
    .await
    .map_err(|_| "timed out".to_string())?
    .map_err(|e| short(&e.to_string()))?;
    if atomic_lib::discovery::genesis_body_verifies(&body, drive) {
        Ok(())
    } else {
        Err("its answer is not this drive's certificate".into())
    }
}

fn short(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() > 140 {
        format!("{}…", text.chars().take(140).collect::<String>())
    } else {
        text.to_string()
    }
}

fn url_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Ask pkarr which https servers announce `drive`, then check each one's
/// genesis certificate (in parallel, a short deadline each); the first that
/// verifies is connected to as the home server. `log` says what happened, for
/// showing when nothing was found.
pub(crate) async fn discover_home_server(drive: &str) -> CoreResult<DiscoveryResult> {
    let mut log = Vec::new();
    let record = tokio::time::timeout(PKARR_RESOLVE_TIMEOUT, atomic_lib::discovery::resolve_drive_record(drive))
        .await
        .map_err(|_| "Server lookup timed out (pkarr)".to_string())?
        .map_err(|e| e.to_string())?;
    let origins: Vec<String> = record.http_origins.into_iter().take(MAX_ORIGINS).collect();
    if origins.is_empty() {
        return Ok(DiscoveryResult { origin: None, log });
    }
    let drive_owned = drive.to_string();
    let mut probes = tokio::task::JoinSet::new();
    for origin in origins {
        let drive = drive_owned.clone();
        probes.spawn(async move {
            let result = probe(&origin, &drive).await;
            (origin, result)
        });
    }
    let mut found = None;
    while let Some(done) = probes.join_next().await {
        let Ok((origin, result)) = done else { continue };
        match result {
            Ok(()) => {
                found = Some(origin);
                break;
            }
            Err(e) => log.push(format!("{origin}: {e}")),
        }
    }
    probes.abort_all();
    let Some(origin) = found else {
        return Ok(DiscoveryResult { origin: None, log });
    };
    log.push(format!("{origin}: certificate verified, connecting"));
    if let Err(e) = connect_home_server(&origin).await {
        log.push(format!("{origin}: {}", short(&e.to_string())));
        return Err(e);
    }
    Ok(DiscoveryResult { origin: Some(origin), log })
}

/// Connect to the server that hosts the active drive: fetches the drive and
/// follows its commits over WS, then, in the background, follows the drives the
/// personal drive lists. Call it only for an origin whose genesis verified.
pub(crate) async fn connect_home_server(origin: &str) -> CoreResult<()> {
    let store = db()?;
    super::ws::open_ws_sync(origin).await?;
    let Some(drive) = store.get_active_drive() else {
        return Err("No active drive".into());
    };
    if !crate::session::drive_exists(store).await {
        return Err(format!("{origin} did not send the drive").into());
    }
    tokio::spawn(super::peers::follow_listed_drives(drive));
    Ok(())
}

/// What `origin` says about itself (`GET /server`, public). Unknown fields
/// when it is unreachable or too old to describe itself.
pub(crate) async fn server_info(origin: &str) -> ServerInfo {
    const P: &str = "https://atomicdata.dev/properties/server/";
    if origin.is_empty() {
        return ServerInfo::default();
    }
    let fetched = tokio::time::timeout(
        Duration::from_secs(6),
        atomic_lib::client::fetch_body(&format!("{origin}/server"), atomic_lib::parse::JSON_AD_MIME, None),
    )
    .await;
    let Ok(Ok(body)) = fetched else { return ServerInfo::default() };
    parse_server_info(&body, P)
}

fn parse_server_info(body: &str, prefix: &str) -> ServerInfo {
    let Ok(json) = serde_json::from_str::<Json>(body) else { return ServerInfo::default() };
    let text = |name: &str| {
        json[format!("{prefix}{name}")].as_str().filter(|s| !s.is_empty()).map(str::to_string)
    };
    ServerInfo {
        node_id: text("nodeId"),
        version: text("version"),
        managed: json[format!("{prefix}managed")].as_bool().unwrap_or(false),
        portal_url: text("portalUrl"),
    }
}

/// What `drive` stores on `origin` (`GET /drive-usage`, signed as this
/// device's agent). `None` when unreachable, not readable or not there.
pub(crate) async fn drive_usage(origin: &str, drive: &str) -> Option<DriveUsage> {
    let agent = db().ok()?.get_default_agent().ok()?;
    let url = format!("{origin}/drive-usage?subject={}", url_encode(drive));
    let body = tokio::time::timeout(
        Duration::from_secs(8),
        atomic_lib::client::fetch_body(&url, "application/json", Some(&agent)),
    )
    .await
    .ok()?
    .ok()?;
    parse_drive_usage(&body)
}

fn parse_drive_usage(body: &str) -> Option<DriveUsage> {
    let json: Json = serde_json::from_str(body).ok()?;
    let count = |key: &str| json[key].as_u64().unwrap_or(0);
    Some(DriveUsage {
        drive_name: json["name"].as_str().filter(|s| !s.is_empty()).map(str::to_string),
        resource_count: count("resourceCount"),
        blob_bytes: count("blobBytes"),
        loro_bytes: count("loroBytes"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_describes_itself_and_an_old_one_says_nothing() {
        let body = r#"{"https://atomicdata.dev/properties/server/version":"0.41","https://atomicdata.dev/properties/server/managed":true,"https://atomicdata.dev/properties/server/portalUrl":"https://portal.example","https://atomicdata.dev/properties/server/nodeId":""}"#;
        let info = parse_server_info(body, "https://atomicdata.dev/properties/server/");
        assert_eq!(info.version.as_deref(), Some("0.41"));
        assert!(info.managed);
        assert_eq!(info.node_id, None, "an empty id is no id");
        assert_eq!(parse_server_info("not json", "x"), ServerInfo::default());
    }

    #[test]
    fn drive_usage_reads_counts_and_tolerates_missing_fields() {
        let usage = parse_drive_usage(r#"{"name":"Mine","resourceCount":12,"blobBytes":2048}"#).unwrap();
        assert_eq!(usage.drive_name.as_deref(), Some("Mine"));
        assert_eq!((usage.resource_count, usage.blob_bytes, usage.loro_bytes), (12, 2048, 0));
        assert!(parse_drive_usage("<html>").is_none());
    }

    #[test]
    fn the_drive_subject_is_encoded_in_the_query() {
        assert_eq!(url_encode("did:ad:abc"), "did%3Aad%3Aabc");
    }

    #[tokio::test]
    async fn an_unreachable_origin_fails_its_probe_without_hanging() {
        let started = std::time::Instant::now();
        assert!(probe("http://127.0.0.1:1", "did:ad:abc").await.is_err());
        assert!(started.elapsed() < Duration::from_secs(6));
    }
}
