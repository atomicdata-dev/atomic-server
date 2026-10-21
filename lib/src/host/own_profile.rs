//! This device's own agent as the person sees and edits it: the name,
//! description and picture of their profile.
//!
//! Reading prefers what the store holds (a profile saved here, or synced in);
//! an agent the store only knows by its key falls back to the profile the
//! connected server has ([`AgentProfiles`]). Saving is a commit by the agent on
//! its own resource, applied locally, queued in the outbox and handed to the
//! host's [`LocalWritePusher`], like every other local edit. It builds on the
//! stored state, so the Loro history the resource has here is kept.

use super::{own_commit_opts, profiles::AgentProfiles, LocalWritePusher};
use crate::{
    commit::CommitBuilder, errors::AtomicResult, runtime::AtomicNode, urls, Commit, Db, Resource,
    Storelike, Value,
};
use serde_json::{json, Map, Value as Json};

/// The agent's picture: a File resource (what the web app's profile editor
/// writes).
pub const ICON: &str = "https://atomicdata.dev/properties/icon";

/// The older picture property (a File subject), still read for agents that
/// carry it.
pub const IMAGE: &str = "https://atomicdata.dev/properties/image";

/// The largest picture [`file_bytes`] hands out.
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

/// The bytes of a File resource's blob, when this store holds both (the File
/// and its bytes). `None` when either is missing (not synced yet) or the file
/// is larger than [`MAX_FILE_BYTES`].
pub async fn file_bytes(store: &Db, file: &str) -> AtomicResult<Option<Vec<u8>>> {
    let Ok(resource) = store.get_resource_shallow(&file.into()) else {
        return Ok(None);
    };
    let Some(hash) = resource.blob_hash() else {
        return Ok(None);
    };
    let bytes = store.get_blob(&hash).await?;
    Ok(bytes.filter(|b| !b.is_empty() && b.len() <= MAX_FILE_BYTES))
}

/// Whether `bytes` look like a picture: the type the server gave or the
/// File's `mimetype` says `image/*`, or (for a generic `octet-stream`) the
/// leading bytes are a known image format.
fn looks_like_image(declared: &[Option<&str>], bytes: &[u8]) -> bool {
    if declared
        .iter()
        .flatten()
        .any(|t| t.to_ascii_lowercase().starts_with("image/"))
    {
        return true;
    }
    // A server that does not know the type says so generically; anything it
    // labels otherwise (text/html, application/json, ...) is not a picture.
    let generic = declared
        .iter()
        .flatten()
        .all(|t| t.is_empty() || t.eq_ignore_ascii_case("application/octet-stream"));
    if !generic {
        return false;
    }
    let head = &bytes[..bytes.len().min(512)];
    head.starts_with(b"\x89PNG")
        || head.starts_with(b"\xff\xd8\xff")
        || head.starts_with(b"GIF8")
        || (head.starts_with(b"RIFF") && head.get(8..12) == Some(b"WEBP"))
        || String::from_utf8_lossy(head).contains("<svg")
}

/// What the server says of a File: the hash of its blob, its `downloadURL`
/// and `mimetype`. Read from the store when it has the File, else from the
/// server (the agent signs that request).
async fn file_facts(
    store: &Db,
    file: &str,
    origins: &[String],
) -> AtomicResult<(Option<[u8; 32]>, Option<String>, Option<String>)> {
    let text = |v: Option<&Json>| v.and_then(Json::as_str).map(str::to_string);
    if let Ok(resource) = store.get_resource_shallow(&file.into()) {
        let get = |p: &str| resource.get(p).ok().map(|v| v.to_string());
        let hash = resource.blob_hash();
        if hash.is_some() || get(urls::DOWNLOAD_URL).is_some() {
            return Ok((hash, get(urls::DOWNLOAD_URL), get(urls::MIMETYPE)));
        }
    }
    let agent = store.get_default_agent().ok();
    let mut last: Option<crate::errors::AtomicError> = None;
    for origin in origins {
        let url = if file.starts_with("http") {
            file.to_string()
        } else {
            format!("{}/{}", origin.trim_end_matches('/'), file)
        };
        match crate::client::fetch_body(&url, crate::parse::JSON_AD_MIME, agent.as_ref()).await {
            Ok(body) => {
                let props: Map<String, Json> = serde_json::from_str(&body)
                    .map_err(|e| format!("File {file} is not JSON-AD: {e}"))?;
                let hash = text(props.get(urls::BLOB))
                    .and_then(|b| crate::Subject::from_raw(&b, None).blob_hash());
                return Ok((
                    hash,
                    text(props.get(urls::DOWNLOAD_URL)),
                    text(props.get(urls::MIMETYPE)),
                ));
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| "No server to ask for the file".into()))
}

fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    matches!(u.scheme(), "http" | "https").then(|| u.origin().ascii_serialization())
}

/// The bytes of a File resource: from this store when it holds them, else
/// downloaded from a server the way the web app does (the blob is
/// content-addressed, the server serves it at `/download/files/<hash>`; a File
/// with only a `downloadURL` is fetched from that). Requests to the agent's
/// own server are signed. The bytes must be an image no larger than
/// [`MAX_FILE_BYTES`] and must match the blob's BLAKE3 hash; a verified blob
/// is kept in the store, so the next read (and offline) is local.
///
/// `origins` are the servers to ask, best first (the connected server).
/// Errors say what failed, with the HTTP status.
pub async fn fetch_file_bytes(store: &Db, file: &str, origins: &[String]) -> AtomicResult<Vec<u8>> {
    if let Some(bytes) = file_bytes(store, file).await? {
        return Ok(bytes);
    }
    let (hash, download_url, mimetype) = file_facts(store, file, origins).await?;
    let agent = store.get_default_agent().ok();

    // Where the bytes may be, best first, without repeating a URL.
    let mut urls_to_try: Vec<String> = Vec::new();
    if let Some(hash) = hash {
        let hex = hex::encode(hash);
        let mut hosts: Vec<String> = Vec::new();
        for o in download_url
            .as_deref()
            .and_then(origin_of)
            .into_iter()
            .chain(origin_of(file))
            .chain(origins.iter().filter_map(|o| origin_of(o)))
        {
            if !hosts.contains(&o) {
                hosts.push(o);
            }
        }
        urls_to_try.extend(hosts.iter().map(|o| format!("{o}/download/files/{hex}")));
    }
    if let Some(u) = download_url.filter(|u| u.starts_with("http")) {
        if !urls_to_try.contains(&u) {
            urls_to_try.push(u);
        }
    }
    if urls_to_try.is_empty() {
        return Err(format!("File {file} has no blob or download URL to fetch").into());
    }

    let mut last: Option<crate::errors::AtomicError> = None;
    for url in urls_to_try {
        let fetched = match crate::client::fetch_bytes(&url, MAX_FILE_BYTES, agent.as_ref()).await {
            Ok(f) => f,
            Err(e) => {
                last = Some(e);
                continue;
            }
        };
        if fetched.bytes.is_empty() {
            last = Some(format!("{url} answered with no bytes").into());
            continue;
        }
        if let Some(hash) = hash {
            if blake3::hash(&fetched.bytes).as_bytes() != &hash {
                last = Some(format!("{url} sent bytes that do not match the file's hash").into());
                continue;
            }
        }
        if !looks_like_image(
            &[fetched.content_type.as_deref(), mimetype.as_deref()],
            &fetched.bytes,
        ) {
            last = Some(
                format!(
                    "{url} is not an image ({})",
                    fetched.content_type.as_deref().unwrap_or("unknown type")
                )
                .into(),
            );
            continue;
        }
        if let Some(hash) = hash {
            // Kept so the next read is local; a store that cannot keep it
            // still hands the bytes out.
            if let Err(e) = store.put_blob(&hash, &fetched.bytes).await {
                tracing::warn!("Could not keep the bytes of {file}: {e}");
            }
        }
        return Ok(fetched.bytes);
    }
    Err(last.expect("at least one URL was tried"))
}

/// The profile of this device's agent as JSON `{subject, name, description,
/// emoji?, imageUrl?, iconFile?}`. `imageUrl` is the download URL of the
/// `icon` (or older `image`) File when this store has that File with one, else
/// the agent's `imageUrl`. `iconFile` is that File's subject whenever the
/// agent has one: files the web app makes are blobs without a download URL,
/// their bytes come from [`file_bytes`].
pub async fn own_profile(store: &Db, profiles: &AgentProfiles) -> AtomicResult<Json> {
    let agent = store.get_default_agent()?;
    let subject = agent.subject.to_string();
    let local = store
        .get_resource_shallow(&agent.subject)
        .ok()
        .filter(|r| r.get(urls::NAME).is_ok())
        .and_then(|r| r.to_json_ad(None).ok());
    let json_ad = match local {
        Some(ad) => Some(ad),
        None => profiles.get(&subject).await,
    };
    let props: Map<String, Json> = json_ad
        .and_then(|ad| serde_json::from_str(&ad).ok())
        .unwrap_or_default();
    let text = |p: &str| {
        props
            .get(p)
            .and_then(Json::as_str)
            .map(str::trim)
            .unwrap_or_default()
            .to_string()
    };
    let name = match text(urls::NAME) {
        n if n.is_empty() => agent.name.clone().unwrap_or_default(),
        n => n,
    };
    let mut out = json!({
        "subject": subject,
        "name": name,
        "description": text(urls::DESCRIPTION),
    });
    let emoji = text(urls::EMOJI);
    if !emoji.is_empty() {
        out["emoji"] = json!(emoji);
    }
    let icon = match text(ICON) {
        i if i.is_empty() => text(IMAGE),
        i => i,
    };
    if !icon.is_empty() {
        out["iconFile"] = json!(icon);
    }
    let from_icon = (!icon.is_empty())
        .then(|| store.get_resource_shallow(&icon.as_str().into()).ok())
        .flatten()
        .and_then(|file| file.get(urls::DOWNLOAD_URL).ok().map(|v| v.to_string()))
        .filter(|u| u.starts_with("http"));
    let image = from_icon.unwrap_or_else(|| text(urls::IMAGE_URL));
    if image.starts_with("http") {
        out["imageUrl"] = json!(image);
    }
    Ok(out)
}

/// Make a File of a picked picture and set it as the agent's `icon`, the way
/// the web app's profile editor does: the bytes go into the local blob store,
/// the File (filename, filesize, mimetype, `internalId`, `blob`, and a
/// `downloadURL` when the server's `origin` is known) is created under `drive`
/// as a commit by the agent, queued in the outbox; the server asks for the
/// blob on the next sync and gets it then. Returns the File's subject.
///
/// The picture must be an image (`image/*`) of at most [`MAX_FILE_BYTES`].
pub async fn upload_own_picture(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    drive: &str,
    origin: Option<&str>,
    filename: &str,
    mimetype: &str,
    bytes: &[u8],
) -> AtomicResult<String> {
    if drive.trim().is_empty() {
        return Err("No drive to keep the picture in".into());
    }
    if bytes.is_empty() {
        return Err("The picture is empty".into());
    }
    if bytes.len() > MAX_FILE_BYTES {
        return Err("The picture is larger than 16 MB".into());
    }
    let mimetype = mimetype.trim().to_ascii_lowercase();
    if !mimetype.starts_with("image/") {
        return Err(format!("A profile picture must be an image, not {mimetype}").into());
    }
    let filename = match filename.trim() {
        "" => "profile-picture",
        f => f,
    };
    let store = node.db();
    let agent = store.get_default_agent()?;
    let hash = blake3::hash(bytes);
    let hex = hash.to_hex().to_string();
    store.put_blob(hash.as_bytes(), bytes).await?;

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::FILE.into()]),
    );
    builder.set(urls::PARENT.into(), Value::AtomicUrl(drive.into()));
    builder.set(urls::FILENAME.into(), Value::String(filename.into()));
    builder.set(urls::FILESIZE.into(), Value::Integer(bytes.len() as i64));
    builder.set(urls::MIMETYPE.into(), Value::String(mimetype));
    builder.set(urls::INTERNAL_ID.into(), Value::String(hex.clone()));
    builder.set(
        urls::BLOB.into(),
        Value::AtomicUrl(crate::identifiers::blob_subject(&hex).into()),
    );
    if let Some(origin) = origin.filter(|o| o.starts_with("http")) {
        builder.set(
            urls::DOWNLOAD_URL.into(),
            Value::String(format!(
                "{}/download/files/{hex}",
                origin.trim_end_matches('/')
            )),
        );
    }
    let commit = Commit::create_did(builder, &agent, store).await?;
    let subject = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok(subject)
}

/// Save the agent's own profile: `name` (required), `description` (empty
/// removes it) and, when given, `icon`, the subject of a File (empty removes
/// the picture; `None` leaves it). Signed by the agent, synced like any edit.
pub async fn set_own_profile(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    name: &str,
    description: &str,
    icon: Option<&str>,
) -> AtomicResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err("A profile needs a name".into());
    }
    let store = node.db();
    let mut agent = store.get_default_agent()?;
    // The stored resource (with its Loro state) when there is one; else the
    // one the store derives from the key, which this commit then makes real.
    let mut resource: Resource = store.get_resource(&agent.subject).await?;
    resource.set_string(urls::NAME.into(), name, store).await?;
    match description.trim() {
        "" => {
            if resource.get(urls::DESCRIPTION).is_ok() {
                resource.remove_propval(urls::DESCRIPTION)?;
            }
        }
        d => {
            resource
                .set_string(urls::DESCRIPTION.into(), d, store)
                .await?;
        }
    }
    match icon.map(str::trim) {
        None => {}
        Some("") => {
            if resource.get(ICON).is_ok() {
                resource.remove_propval(ICON)?;
            }
        }
        Some(file) => {
            resource.set_unsafe(ICON.into(), Value::AtomicUrl(file.into()))?;
        }
    }
    let response = node.save_locally(&mut resource).await?;
    pusher.push(&response).await;
    // The agent in memory carries the name too (what the app shows for "you").
    agent.name = Some(name.to_string());
    store.set_default_agent(agent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{embed::EmbedHost, test_support::Device, NoPush};
    use std::sync::Arc;

    #[tokio::test]
    async fn a_saved_profile_is_read_back_and_kept() {
        let d = Device::new().await;
        set_own_profile(&d.node, &NoPush, " Pelican ", "Likes fish", None)
            .await
            .unwrap();

        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["name"], "Pelican");
        assert_eq!(p["description"], "Likes fish");
        assert!(p.get("imageUrl").is_none());
        assert_eq!(
            d.store.get_default_agent().unwrap().name.as_deref(),
            Some("Pelican")
        );

        // Signing in again with the secret (every app start) keeps it.
        let secret = d.store.get_default_agent().unwrap().build_secret().unwrap();
        let loaded = d.store.load_agent_from_secret(&secret).await.unwrap();
        assert_eq!(loaded.agent.name.as_deref(), Some("Pelican"));

        // An empty description removes it; an empty name is refused.
        set_own_profile(&d.node, &NoPush, "Pelican", "", None)
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["description"], "");
        assert!(set_own_profile(&d.node, &NoPush, "  ", "", None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_saved_profile_is_a_commit_the_page_reads_with_its_state() {
        let d = Device::new().await;
        let agent = d.store.get_default_agent().unwrap().subject.to_string();
        set_own_profile(&d.node, &NoPush, "Pelican", "", None)
            .await
            .unwrap();
        assert!(d.node.outbox().has_pending(&agent), "queued for sync");

        let host = EmbedHost::new(d.node.clone(), Arc::new(NoPush), AgentProfiles::none());
        let rows: Json = serde_json::from_str(
            &host
                .call("getResourcesWithSnapshots", &json!([[agent]]).to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(rows[0]["jsonAd"].as_str().unwrap().contains("Pelican"));
        // The page edits on top of the stored Loro state, not a blank one.
        assert!(rows[0]["snapshot"].is_string());
    }

    /// The web app's pictures are blobs with no download URL: the profile
    /// names the File and the host hands out its bytes.
    #[tokio::test]
    async fn a_blob_icon_is_named_and_its_bytes_are_readable() {
        let d = Device::new().await;
        let bytes = b"\x89PNG not really";
        let hash = blake3::hash(bytes);
        d.store.put_blob(hash.as_bytes(), bytes).await.unwrap();
        let blob = |hex: String| {
            Some(vec![(
                urls::BLOB,
                Value::AtomicUrl(format!("did:ad:blob:{hex}").into()),
            )])
        };
        let file = d
            .store
            .create_resource(
                urls::FILE,
                &d.drive,
                "me.png",
                blob(hash.to_hex().to_string()),
            )
            .await
            .unwrap();
        assert!(file_bytes(&d.store, "https://example.test/none")
            .await
            .unwrap()
            .is_none());
        set_own_profile(&d.node, &NoPush, "Pelican", "", Some(&file))
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert!(p.get("imageUrl").is_none());
        assert_eq!(p["iconFile"], file.as_str());
        assert_eq!(
            file_bytes(&d.store, &file).await.unwrap().as_deref(),
            Some(&bytes[..])
        );
        // The File is here but its bytes are not (yet).
        let lost = d
            .store
            .create_resource(urls::FILE, &d.drive, "lost.png", blob("ab".repeat(32)))
            .await
            .unwrap();
        assert!(file_bytes(&d.store, &lost).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_picture_is_the_icon_files_download_url() {
        let d = Device::new().await;
        let file = d
            .store
            .create_resource(urls::FILE, &d.drive, "me.png", None)
            .await
            .unwrap();
        let mut f = d.store.get_resource(&file.as_str().into()).await.unwrap();
        f.set_unsafe(
            urls::DOWNLOAD_URL.into(),
            Value::String("https://example.test/download/me.png".into()),
        )
        .unwrap();
        d.node.save_locally(&mut f).await.unwrap();

        set_own_profile(&d.node, &NoPush, "Pelican", "", Some(&file))
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["imageUrl"], "https://example.test/download/me.png");

        set_own_profile(&d.node, &NoPush, "Pelican", "", Some(""))
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert!(p.get("imageUrl").is_none());
    }

    /// Signed in with a secret on a new device: the store knows the agent only
    /// by its key. Saving makes the profile real here, and the page then
    /// reads it from the store instead of the server's copy.
    #[tokio::test]
    async fn a_profile_saved_by_an_agent_known_only_by_its_key() {
        let store = Db::init_redb(None).await.unwrap();
        let secret = crate::agents::Agent::new(None)
            .unwrap()
            .build_secret()
            .unwrap();
        store.load_agent_from_secret(&secret).await.unwrap();
        let node = AtomicNode::from_db(store.clone());
        let agent = store.get_default_agent().unwrap().subject.to_string();

        set_own_profile(&node, &NoPush, "Pelican", "From the app", None)
            .await
            .unwrap();

        let p = own_profile(&store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["name"], "Pelican");
        let host = EmbedHost::new(node.clone(), Arc::new(NoPush), AgentProfiles::none());
        let rows: Json = serde_json::from_str(
            &host
                .call("getResourcesWithSnapshots", &json!([[agent]]).to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(rows[0]["jsonAd"].as_str().unwrap().contains("From the app"));
        assert!(rows[0]["snapshot"].is_string());
    }

    /// A loopback server answering each request with `respond(path)`
    /// (status line + headers + body); the request heads it saw are kept.
    async fn fake_server(
        respond: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                log.lock().unwrap().push(head);
                let _ = stream.write_all(&respond(&path)).await;
                let _ = stream.shutdown().await;
            }
        });
        (origin, seen)
    }

    fn http(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    async fn blob_file(d: &Device, hash: &blake3::Hash) -> String {
        d.store
            .create_resource(
                urls::FILE,
                &d.drive,
                "me.png",
                Some(vec![(
                    urls::BLOB,
                    Value::AtomicUrl(format!("did:ad:blob:{}", hash.to_hex()).into()),
                )]),
            )
            .await
            .unwrap()
    }

    /// A picture that lives on the server (SaaS drive): the File is here, its
    /// bytes are not. They are fetched at the content-addressed route with a
    /// signed request, checked against the hash and kept.
    #[tokio::test]
    async fn a_picture_missing_here_is_fetched_signed_verified_and_kept() {
        let d = Device::new().await;
        let bytes = b"\x89PNG the real picture".to_vec();
        let hash = blake3::hash(&bytes);
        let file = blob_file(&d, &hash).await;
        assert!(file_bytes(&d.store, &file).await.unwrap().is_none());

        let body = bytes.clone();
        let (origin, seen) = fake_server(move |_| http("200 OK", "image/png", &body)).await;
        let got = fetch_file_bytes(&d.store, &file, &[origin]).await.unwrap();
        assert_eq!(got, bytes);

        let heads = seen.lock().unwrap().clone();
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].starts_with(&format!("GET /download/files/{} ", hash.to_hex())),
            "{}",
            heads[0]
        );
        let lower = heads[0].to_ascii_lowercase();
        assert!(lower.contains("x-atomic-signature:"), "{lower}");
        assert!(lower.contains("x-atomic-agent:"), "{lower}");

        // Now local: no server needed.
        assert_eq!(
            file_bytes(&d.store, &file).await.unwrap().as_deref(),
            Some(&bytes[..])
        );
        let again = fetch_file_bytes(&d.store, &file, &[]).await.unwrap();
        assert_eq!(again, bytes);
    }

    #[tokio::test]
    async fn a_fetched_picture_must_match_its_hash_and_be_an_image() {
        let d = Device::new().await;
        let bytes = b"\x89PNG the real picture".to_vec();
        let hash = blake3::hash(&bytes);
        let file = blob_file(&d, &hash).await;

        let (origin, _) = fake_server(|_| http("200 OK", "image/png", b"\x89PNG forged")).await;
        let err = fetch_file_bytes(&d.store, &file, &[origin])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("do not match"), "{err}");
        assert!(file_bytes(&d.store, &file).await.unwrap().is_none());

        let body = bytes.clone();
        let (origin, _) = fake_server(move |_| http("200 OK", "text/html", &body)).await;
        let err = fetch_file_bytes(&d.store, &file, &[origin])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not an image"), "{err}");

        // Over the cap is refused before it is read.
        let (origin, _) = fake_server(|_| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_FILE_BYTES + 1
            )
            .into_bytes()
        })
        .await;
        let err = fetch_file_bytes(&d.store, &file, &[origin])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_fetch_names_the_http_status() {
        let d = Device::new().await;
        let hash = blake3::hash(b"x");
        let file = blob_file(&d, &hash).await;
        let (origin, _) = fake_server(|_| http("403 Forbidden", "text/plain", b"no")).await;
        let err = fetch_file_bytes(&d.store, &file, &[origin])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Status: 403"), "{err}");
    }

    /// No blob hash (an older File): the download URL is fetched, unverified
    /// but still bounded and checked for an image.
    #[tokio::test]
    async fn a_file_with_only_a_download_url_is_fetched_from_it() {
        let d = Device::new().await;
        let (origin, seen) = fake_server(|p| {
            assert_eq!(p, "/download/me.png");
            http("200 OK", "application/octet-stream", b"\x89PNG old file")
        })
        .await;
        let file = d.new_picture(&format!("{origin}/download/me.png")).await;
        let got = fetch_file_bytes(&d.store, &file, &[]).await.unwrap();
        assert_eq!(got, b"\x89PNG old file");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// The File itself is not on this device (it lives in the SaaS drive):
    /// the server is asked for it, then for its blob.
    #[tokio::test]
    async fn a_file_this_device_does_not_have_is_looked_up_on_the_server() {
        let d = Device::new().await;
        let bytes = b"\x89PNG far away".to_vec();
        let hash = blake3::hash(&bytes);
        let file = format!("did:ad:{}", "z".repeat(10));
        let (b, h) = (bytes.clone(), hash.to_hex().to_string());
        let (origin, seen) = fake_server(move |p| {
            if p.starts_with("/download/files/") {
                assert!(p.ends_with(&h));
                http("200 OK", "image/png", &b)
            } else {
                let json = format!(
                    r#"{{"@id":"x","{}":"atomic:blob:{h}","{}":"image/png"}}"#,
                    urls::BLOB,
                    urls::MIMETYPE
                );
                http("200 OK", "application/ad+json", json.as_bytes())
            }
        })
        .await;
        let got = fetch_file_bytes(&d.store, &file, &[origin]).await.unwrap();
        assert_eq!(got, bytes);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_picked_picture_becomes_the_icon_file_with_its_bytes_here() {
        let d = Device::new().await;
        let bytes = b"\x89PNG picked".to_vec();
        let file = upload_own_picture(
            &d.node,
            &NoPush,
            &d.drive,
            Some("https://s.test/"),
            "me.png",
            "image/PNG",
            &bytes,
        )
        .await
        .unwrap();
        set_own_profile(&d.node, &NoPush, "Pelican", "", Some(&file))
            .await
            .unwrap();
        let p = own_profile(&d.store, &AgentProfiles::none()).await.unwrap();
        assert_eq!(p["iconFile"], file.as_str());
        let hex = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(
            p["imageUrl"],
            format!("https://s.test/download/files/{hex}")
        );
        assert_eq!(
            file_bytes(&d.store, &file).await.unwrap().as_deref(),
            Some(&bytes[..])
        );
        let f = d.store.get_resource(&file.as_str().into()).await.unwrap();
        assert_eq!(f.get(urls::MIMETYPE).unwrap().to_string(), "image/png");
        assert_eq!(
            f.get(urls::FILESIZE).unwrap().to_string(),
            bytes.len().to_string()
        );
        assert!(d.node.outbox().has_pending(&file), "queued for sync");

        // Not an image, empty, too large: refused.
        for (mime, data) in [
            ("text/html", b"<p>".to_vec()),
            ("image/png", Vec::new()),
            ("image/png", vec![0; MAX_FILE_BYTES + 1]),
        ] {
            assert!(
                upload_own_picture(&d.node, &NoPush, &d.drive, None, "x", mime, &data)
                    .await
                    .is_err(),
                "{mime} {}",
                data.len()
            );
        }
    }
}
