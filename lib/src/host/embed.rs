//! What the embedded web renderer asks the store: the calls of the web app's
//! `NativeClientDb` (`browser/lib/src/client-db.native.ts`), answered from the
//! node's store. One request is a method name and its arguments as JSON; the
//! answer is JSON, with bytes as base64. See `planning/flutter-resource-webview.md`.
//!
//! Writes: the agent's secret stays here. The page can have two kinds of thing
//! signed: a commit that names this agent as its signer (`sign`), and the
//! genesis certificate that mints a new resource's DID (`signBytes`, only for
//! bytes that decode as a certificate of this agent). It hands a signed commit
//! back (`applyCommit`, the page's commit transport), which is applied like any
//! local edit, queued in the outbox and handed to the host's
//! [`LocalWritePusher`]. There is no raw signing, so a script inside the page
//! cannot get a signature over anything else.
//!
//! Reads: the page's store does not connect to a server, so an agent it shows
//! (a chat's author, "created by", a member list) that this device does not
//! hold would be "not found". Those are answered from the host's
//! [`AgentProfiles`] instead: the profile the connected server has, in memory
//! only, never written to the store (this device did not sign or verify it).

use super::{conversations::same_agent, profiles::AgentProfiles, LocalWritePusher};
use crate::{
    agents::ForAgent, runtime::AtomicNode, storelike::Query, Db, Resource, Storelike, Subject,
};
use serde_json::{json, Value as Json};
use std::collections::HashMap;
use std::sync::Arc;

fn err(e: crate::errors::AtomicError) -> String {
    e.to_string()
}

fn b64(bytes: &[u8]) -> String {
    crate::agents::encode_base64(bytes)
}

/// The origin subjects are addressed by in the page: a DID needs none, but a
/// resource served by URL does.
fn origin(store: &Db) -> String {
    store
        .get_base_domain()
        .unwrap_or_else(|| "http://localhost".to_string())
}

fn str_arg(args: &[Json], i: usize) -> Result<&str, String> {
    args.get(i)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("argument {i} must be a string"))
}

fn strings(args: &[Json], i: usize) -> Vec<String> {
    args.get(i)
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn subject_of(store: &Db, raw: &str) -> Subject {
    Subject::from_raw(raw, store.get_base_domain().as_deref())
}

/// A resource from the local store as JSON-AD under the subject it was asked
/// by, plus its Loro snapshot. Reads the stored row first, like the browser's
/// database does: decoding the whole CRDT history only to serialise it again
/// is the slow way.
async fn read_local(store: &Db, raw: &str) -> Json {
    let subject = subject_of(store, raw);
    let origin = origin(store);
    let resource: Option<Resource> = match store.get_resource_shallow(&subject) {
        Ok(r) => Some(r),
        Err(_) => store.get_resource(&subject).await.ok(),
    };
    let json_ad = resource.and_then(|r| r.to_json_ad(Some(&origin)).ok());
    let snapshot = json_ad
        .as_ref()
        .and_then(|_| store.get_loro_snapshot(&subject))
        .map(|b| b64(&b));
    json!({ "jsonAd": json_ad, "snapshot": snapshot })
}

/// Like [`read_local`], and an agent that is not in the local store is
/// answered with the profile from `profiles` (no snapshot: it is not a
/// resource of this device). Missing agents of one batch are looked up
/// together.
async fn read_many(store: &Db, profiles: &AgentProfiles, raws: &[String]) -> Vec<Json> {
    let mut rows: Vec<Json> = Vec::with_capacity(raws.len());
    for raw in raws {
        rows.push(read_local(store, raw).await);
    }
    // An agent the store only knows by its key is a stub without a name (the
    // store derives one for any agent subject): it needs the profile too.
    let nameless = |row: &Json| {
        row["jsonAd"]
            .as_str()
            .is_none_or(|ad| !ad.contains("\"https://atomicdata.dev/properties/name\""))
    };
    // This device's own agent is never asked for.
    let me = store
        .get_default_agent()
        .ok()
        .map(|a| a.subject.to_string());
    let missing: Vec<usize> = (0..raws.len())
        .filter(|&i| {
            nameless(&rows[i])
                && subject_of(store, &raws[i]).is_agent_did()
                && me.as_deref().is_none_or(|me| !same_agent(me, &raws[i]))
        })
        .collect();
    let found = futures::future::join_all(missing.iter().map(|&i| profiles.get(&raws[i]))).await;
    for (i, profile) in missing.into_iter().zip(found) {
        if let Some(json_ad) = profile {
            rows[i]["jsonAd"] = json!(json_ad);
            // Not a resource of this device: no snapshot to go with it.
            rows[i]["snapshot"] = Json::Null;
        }
    }
    rows
}

async fn query(store: &Db, opts: &Json) -> Result<Json, String> {
    let text = |k: &str| opts.get(k).and_then(Json::as_str).map(str::to_string);
    let base = store.get_base_domain();
    let property = text("property");
    let value = match text("value") {
        Some(raw) => Some(
            crate::collections::delocalize_filter_value(store, property.as_deref(), &raw).await,
        ),
        None => None,
    };

    let mut filters = Vec::new();
    for f in opts
        .get("filters")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let p = f.get("property").and_then(Json::as_str).map(str::to_string);
        let v = match f.get("value").and_then(Json::as_str) {
            Some(raw) => {
                Some(crate::collections::delocalize_filter_value(store, p.as_deref(), raw).await)
            }
            None => None,
        };
        filters.push(crate::storelike::PropVal {
            property: p,
            value: v,
            operator: crate::storelike::filter_operator_from_str(
                f.get("operator").and_then(Json::as_str),
            ),
        });
    }

    let aggregation = opts
        .get("aggregation")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| e.to_string()))
        .transpose()?;
    let expression_filters = opts
        .get("expressionFilters")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or_default();
    let flag = |k: &str| opts.get(k).and_then(Json::as_bool).unwrap_or(false);
    let number = |k: &str| opts.get(k).and_then(Json::as_u64).map(|n| n as usize);

    let q = Query {
        property,
        value,
        filters,
        expression_filters,
        aggregation,
        sort_by: text("sortBy"),
        sort_desc: flag("sortDesc"),
        limit: number("limit"),
        offset: number("offset").unwrap_or(0),
        start_val: None,
        end_val: None,
        include_external: false,
        include_nested: flag("includeResources"),
        exclude_trashed: !flag("includeTrashed"),
        for_agent: ForAgent::Sudo,
        drive: text("drive").map(|d| Subject::from_raw(&d, base.as_deref())),
    };
    let result = store.query(&q).await.map_err(err)?;
    let origin = origin(store);
    let resources: Vec<String> = result
        .resources
        .iter()
        .filter_map(|r| r.to_json_ad(Some(&origin)).ok())
        .collect();
    Ok(json!({
        "subjects": result.subjects.iter().map(|s| s.resolve(&origin)).collect::<Vec<_>>(),
        "resources": resources,
        "count": result.count,
        "aggregates": result.aggregates,
    }))
}

fn search(store: &Db, args: &[Json]) -> Result<Json, String> {
    let q = str_arg(args, 0)?;
    let opts = args.get(1).cloned().unwrap_or(Json::Null);
    let parents = match opts.get("parents") {
        Some(Json::String(s)) => Some(vec![s.clone()]),
        Some(Json::Array(a)) => Some(
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
    };
    let search_opts = crate::client::search::SearchOpts {
        limit: opts.get("limit").and_then(Json::as_u64).map(|n| n as u32),
        parents,
        include_trashed: opts
            .get("includeTrashed")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        ..Default::default()
    };
    let hits = crate::search::query(store, q, &search_opts).map_err(err)?;
    Ok(json!(hits
        .into_iter()
        .map(|h| h.subject.to_string())
        .collect::<Vec<_>>()))
}

/// Version vectors of the given subjects (`pure_id` strings, the keys of the
/// snapshot tree); subjects without a snapshot are left out.
fn version_vectors(store: &Db, subjects: Vec<String>) -> Json {
    use crate::db::trees::Tree;
    use crate::loro::AtomicLoroDoc;
    let mut out: HashMap<String, HashMap<String, i32>> = HashMap::new();
    for subject in subjects {
        if let Ok(Some(bytes)) = store.kv.get(Tree::LoroSnapshots, subject.as_bytes()) {
            if let Ok(vv) = AtomicLoroDoc::vv_map_from_snapshot(&bytes) {
                out.insert(subject, vv);
            }
        }
    }
    json!(out)
}

/// Signs `payload` if it is a commit by this device's agent, and nothing else.
fn sign_commit(store: &Db, payload: &str) -> Result<String, String> {
    let agent = store.get_default_agent().map_err(err)?;
    let commit: Json = serde_json::from_str(payload).map_err(|_| "only commits are signed")?;
    let is_commit = commit[crate::urls::IS_A]
        .as_array()
        .is_some_and(|classes| classes.iter().any(|c| c == crate::urls::COMMIT));
    let signer = commit[crate::urls::SIGNER].as_str();
    if !is_commit || signer != Some(agent.subject.to_string().as_str()) {
        return Err("only a commit by this device's agent is signed".into());
    }
    let key = agent
        .private_key
        .ok_or("this device holds no secret for its agent")?;
    crate::agents::sign_message(payload.as_bytes(), &key).map_err(err)
}

/// Signs a genesis certificate (base64 bytes) that names this device's agent
/// as its signer: how the page mints the DID of a resource it creates
/// (`Store.mintCertDid`, `Agent.privateDriveSubject`). The exact bytes are
/// signed, as the page encoded them; anything that is not such a certificate
/// is refused.
fn sign_genesis_cert(store: &Db, payload_b64: &str) -> Result<String, String> {
    let agent = store.get_default_agent().map_err(err)?;
    let bytes = crate::agents::decode_base64(payload_b64).map_err(err)?;
    let cert = crate::genesis::GenesisCert::decode(&bytes)
        .map_err(|_| "only a genesis certificate is signed as bytes")?;
    let own_key = crate::agents::decode_base64(&agent.public_key).map_err(err)?;
    if cert.signer_pubkey.as_slice() != own_key.as_slice() {
        return Err("only a genesis certificate of this device's agent is signed".into());
    }
    let key = agent
        .private_key
        .ok_or("this device holds no secret for its agent")?;
    crate::agents::sign_message(&bytes, &key).map_err(err)
}

/// A snapshot written together with outbox rows is the page's offline path
/// (`Resource.saveOffline`): an edit kept for the page's own database, which
/// here does not exist. It only happens when the page has no commit transport,
/// and then the edit is lost: say so in the log.
fn warn_unkept_local_edit(method: &str, outbox: Option<&Json>) {
    let subjects: Vec<&str> = outbox
        .and_then(|o| o.get("puts"))
        .and_then(Json::as_array)
        .map(|puts| {
            puts.iter()
                .filter_map(|p| p.get("subject").and_then(Json::as_str))
                .collect()
        })
        .unwrap_or_default();
    if !subjects.is_empty() {
        tracing::warn!(
            "[embed] {method} carries an offline edit of {subjects:?}, which is not kept: \
             the page saves through applyCommit, so it is running without a commit transport"
        );
    }
}

/// The page hands over a commit as its `Client.postCommit` body: signed, but
/// without an `@id` (a commit's id is derived from its signature, and the
/// signed bytes never carry it). The local store reads a commit as a resource,
/// so it gets the id a server would give it.
fn with_commit_id(commit_json: &str) -> Result<String, String> {
    let mut commit: Json = serde_json::from_str(commit_json).map_err(|e| e.to_string())?;
    let object = commit.as_object_mut().ok_or("a commit is a JSON object")?;
    if !object.contains_key("@id") {
        let signature = object
            .get(crate::urls::SIGNATURE)
            .and_then(Json::as_str)
            .ok_or("only a signed commit is applied")?;
        let id = crate::identifiers::commit_subject(signature);
        object.insert("@id".into(), json!(id));
    }
    Ok(commit.to_string())
}

/// The store side of the embedded renderer: answers the page's calls from
/// `node`, and hands every commit the page applies to `pusher`.
pub struct EmbedHost {
    node: AtomicNode,
    pusher: Arc<dyn LocalWritePusher>,
    profiles: AgentProfiles,
}

impl EmbedHost {
    pub fn new(
        node: AtomicNode,
        pusher: Arc<dyn LocalWritePusher>,
        profiles: AgentProfiles,
    ) -> Self {
        Self {
            node,
            pusher,
            profiles,
        }
    }

    /// One call from the page: `method` and its arguments (a JSON array),
    /// answered as JSON. Needs a tokio runtime (`applyCommit` pushes in the
    /// background).
    pub async fn call(&self, method: &str, args_json: &str) -> Result<String, String> {
        let args: Vec<Json> = serde_json::from_str(args_json).map_err(|e| e.to_string())?;
        let store = self.node.db();
        let answer: Json = match method {
            "init" => json!(true),
            "agent" => match store.get_default_agent() {
                Ok(agent) => json!(agent.subject.to_string()),
                Err(_) => Json::Null,
            },
            "getResource" => {
                let raw = vec![str_arg(&args, 0)?.to_string()];
                read_many(store, &self.profiles, &raw).await[0]["jsonAd"].clone()
            }
            "getResourcesWithSnapshots" => {
                json!(read_many(store, &self.profiles, &strings(&args, 0)).await)
            }
            "getLoroSnapshot" => json!(store
                .get_loro_snapshot(&subject_of(store, str_arg(&args, 0)?))
                .map(|b| b64(&b))),
            "query" => query(store, args.first().unwrap_or(&Json::Null)).await?,
            "search" => search(store, &args)?,
            "allSubjects" => json!(store
                .all_resources(true)
                .map(|r| r.get_subject().to_string())
                .collect::<Vec<_>>()),
            "getDriveSubjects" => json!(crate::sync::engine::collect_drive_subjects(
                store,
                &subject_of(store, str_arg(&args, 0)?)
            )
            .await
            .into_iter()
            .collect::<Vec<_>>()),
            "getVersionVectorsForDrive" => {
                let subjects: Vec<String> = crate::sync::engine::collect_drive_subjects(
                    store,
                    &subject_of(store, str_arg(&args, 0)?),
                )
                .await
                .into_iter()
                .collect();
                version_vectors(store, subjects)
            }
            "getVersionVectorsForSubjects" => version_vectors(store, strings(&args, 0)),
            // Nothing in the page syncs with a server, so nothing diffs versions.
            "getAllVersionVectors" => json!({}),
            "historyAttribution" => Json::Null,
            "getBlob" => Json::Null,
            "flush" => Json::Null,
            "outboxEntries" => json!([]),
            // The page's outbox bookkeeping: what it has yet to hand over. Its
            // edits reach `applyCommit` within the page's life, so none is kept.
            "outboxWrite" => Json::Null,
            // The page's local cache writes back what it just read, or what a
            // commit it gave `applyCommit` already wrote here: the real store
            // has it, so there is nothing to keep. An edit never travels this way.
            "putResourceWithSnapshot" => {
                warn_unkept_local_edit(method, args.get(3));
                Json::Null
            }
            "putResource" | "putResources" | "putBlob" | "applyPeerCommit" | "removeResource" => {
                Json::Null
            }
            "publicKey" => match store.get_default_agent() {
                Ok(agent) => json!(agent.public_key),
                Err(_) => Json::Null,
            },
            "sign" => json!(sign_commit(store, str_arg(&args, 0)?)?),
            "signBytes" => json!(sign_genesis_cert(store, str_arg(&args, 0)?)?),
            "applyCommit" => {
                let commit = with_commit_id(str_arg(&args, 0)?)?;
                let response = self
                    .node
                    .apply_commit(&commit, crate::runtime::IngestPolicy::LocalCache)
                    .await
                    .map_err(err)?;
                self.node
                    .outbox()
                    .mark_dirty(&response)
                    .await
                    .map_err(err)?;
                // Applied and queued: that is what the page waits for (its
                // save, and leaving the page, wait on this answer). Sending it
                // on to the server and peers can take a network round trip, so
                // it goes on without the page.
                let pusher = self.pusher.clone();
                tokio::spawn(async move {
                    pusher.push(&response).await;
                });
                Json::Null
            }
            other => {
                return Err(format!(
                    "{other}: not available in the embedded renderer yet"
                ))
            }
        };
        serde_json::to_string(&answer).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{test_support::Device, NoPush};
    use crate::urls;

    fn host(d: &Device) -> EmbedHost {
        EmbedHost::new(d.node.clone(), Arc::new(NoPush), AgentProfiles::none())
    }

    async fn ask(host: &EmbedHost, method: &str, args: Json) -> Json {
        serde_json::from_str(&host.call(method, &args.to_string()).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn the_page_can_read_a_resource_under_either_spelling() {
        let d = Device::new().await;
        let h = host(&d);
        let folder = d
            .store
            .create_resource(urls::FOLDER, &d.drive, "Embed folder", None)
            .await
            .unwrap();
        let other_spelling = if folder.starts_with("atomic:") {
            folder.replacen("atomic:", "did:ad:", 1)
        } else {
            folder.replacen("did:ad:", "atomic:", 1)
        };

        let rows = ask(
            &h,
            "getResourcesWithSnapshots",
            json!([[folder, other_spelling, "did:ad:not-here"]]),
        )
        .await;
        let rows = rows.as_array().unwrap();

        for row in &rows[..2] {
            assert!(row["jsonAd"].as_str().unwrap().contains("Embed folder"));
            assert!(!row["snapshot"].as_str().unwrap().is_empty());
        }
        // Answered under the name it was asked by.
        assert!(rows[1]["jsonAd"]
            .as_str()
            .unwrap()
            .contains(&other_spelling));
        assert!(rows[2]["jsonAd"].is_null());
    }

    /// Answers one agent's profile and counts the calls.
    struct Profiles(std::sync::atomic::AtomicUsize, Option<String>);

    #[async_trait::async_trait]
    impl crate::host::AgentProfileFetcher for Profiles {
        async fn fetch_agent_resource(&self, _agent: &str) -> Option<String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.1.clone()
        }
    }

    fn calls(p: &Profiles) -> usize {
        p.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn host_with(d: &Device, fetcher: Arc<Profiles>) -> EmbedHost {
        EmbedHost::new(
            d.node.clone(),
            Arc::new(NoPush),
            AgentProfiles::with_timing(
                fetcher,
                std::time::Duration::from_secs(2),
                std::time::Duration::from_secs(60),
            ),
        )
    }

    #[tokio::test]
    async fn an_agent_this_device_lacks_is_answered_from_the_server_once() {
        let d = Device::new().await;
        let reply = json!({ "@id": "https://server.test/x", urls::NAME: "Dora" }).to_string();
        let fetcher = Arc::new(Profiles(Default::default(), Some(reply)));
        let h = host_with(&d, fetcher.clone());
        let stranger = "atomic:agent:strangerkey";

        let rows = ask(&h, "getResourcesWithSnapshots", json!([[stranger]])).await;
        let json_ad = rows[0]["jsonAd"].as_str().unwrap();
        assert!(json_ad.contains("Dora"), "{json_ad}");
        assert!(json_ad.contains(stranger), "answered under the asked id");
        assert!(rows[0]["snapshot"].is_null());
        // getResource, and the other spelling's read, come from the cache.
        let one = ask(&h, "getResource", json!([stranger])).await;
        assert!(one.as_str().unwrap().contains("Dora"));
        assert_eq!(calls(&fetcher), 1);
        // Never stored as if it were ours.
        assert!(d
            .store
            .get_resource_shallow(&subject_of(&d.store, stranger))
            .is_err());
    }

    #[tokio::test]
    async fn an_agent_the_store_only_knows_by_its_key_still_gets_its_profile() {
        // The store derives a bare agent (key only, no name) for any agent
        // subject; the page needs the name from the server.
        let d = Device::new().await;
        let reply = json!({ "@id": "https://server.test/x", urls::NAME: "Dora" }).to_string();
        let fetcher = Arc::new(Profiles(Default::default(), Some(reply)));
        let h = host_with(&d, fetcher.clone());
        let stub = "atomic:agent:QmfpRIBn2JYEatT0MjSkMNoBJzstz19orwnT5oT2rcQ=";
        let rows = ask(&h, "getResourcesWithSnapshots", json!([[stub]])).await;
        let json_ad = rows[0]["jsonAd"].as_str().unwrap();
        assert!(json_ad.contains("Dora"), "{json_ad}");
        assert!(rows[0]["snapshot"].is_null());
        assert_eq!(calls(&fetcher), 1);
    }

    #[tokio::test]
    async fn an_unknown_agent_is_not_found_and_not_asked_again_for_a_minute() {
        let d = Device::new().await;
        let fetcher = Arc::new(Profiles(Default::default(), None));
        let h = host_with(&d, fetcher.clone());
        for _ in 0..3 {
            let rows = ask(
                &h,
                "getResourcesWithSnapshots",
                json!([["did:ad:agent:nobody"]]),
            )
            .await;
            assert!(rows[0]["jsonAd"].is_null());
        }
        assert_eq!(calls(&fetcher), 1);
    }

    #[tokio::test]
    async fn local_agents_and_other_subjects_never_ask_the_server() {
        let d = Device::new().await;
        let fetcher = Arc::new(Profiles(Default::default(), Some("{}".into())));
        let h = host_with(&d, fetcher.clone());
        let me = ask(&h, "agent", json!([])).await;
        let me = me.as_str().unwrap().to_string();
        let rows = ask(
            &h,
            "getResourcesWithSnapshots",
            json!([[me, "did:ad:not-here", "https://example.test/nope"]]),
        )
        .await;
        assert!(
            !rows[0]["jsonAd"].is_null(),
            "this device's own agent is local"
        );
        assert!(rows[1]["jsonAd"].is_null());
        assert!(rows[2]["jsonAd"].is_null());
        assert_eq!(calls(&fetcher), 0);
    }

    #[tokio::test]
    async fn the_page_can_list_the_children_of_a_folder_and_search_them() {
        let d = Device::new().await;
        let h = host(&d);
        let folder = d
            .store
            .create_resource(urls::FOLDER, &d.drive, "Embed parent", None)
            .await
            .unwrap();
        let child = d
            .store
            .create_resource(urls::FOLDER, &folder, "Quokkaembed child", None)
            .await
            .unwrap();

        let result = ask(
            &h,
            "query",
            json!([{ "property": urls::PARENT, "value": folder, "limit": 10 }]),
        )
        .await;
        let subjects: Vec<&str> = result["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Json::as_str)
            .collect();
        assert_eq!(subjects.len(), 1);
        assert!(subjects[0].ends_with(child.trim_start_matches("atomic:")));
        assert_eq!(result["count"], 1);

        let nested = ask(
            &h,
            "query",
            json!([{ "property": urls::PARENT, "value": folder, "includeResources": true }]),
        )
        .await;
        assert!(nested["resources"][0]
            .as_str()
            .unwrap()
            .contains("Quokkaembed child"));

        let hits = ask(
            &h,
            "search",
            json!(["quokkaembed", { "limit": 5, "parents": d.drive }]),
        )
        .await;
        assert!(hits
            .to_string()
            .contains(child.trim_start_matches("atomic:")));
    }

    #[tokio::test]
    async fn it_names_the_agent_and_says_it_is_ready() {
        let d = Device::new().await;
        let h = host(&d);
        assert_eq!(ask(&h, "init", json!([])).await, json!(true));
        assert!(ask(&h, "agent", json!([]))
            .await
            .as_str()
            .unwrap()
            .contains("agent"));
        assert!(h
            .call("noSuchMethod", "[]")
            .await
            .unwrap_err()
            .contains("not available"));
    }

    #[tokio::test]
    async fn only_a_commit_by_this_agent_gets_signed() {
        let d = Device::new().await;
        let h = host(&d);
        // No raw signing: bytes that are not a genesis certificate are refused.
        let refused = h.call("signBytes", "[\"eA\"]").await.unwrap_err();
        assert!(refused.contains("genesis certificate"), "{refused}");
        // Not a commit, or someone else's commit.
        assert!(h.call("sign", "[\"hello\"]").await.is_err());
        let agent = ask(&h, "agent", json!([])).await;
        let other = json!({
            urls::IS_A: [urls::COMMIT],
            urls::SIGNER: "did:ad:someone-else",
        });
        assert!(h
            .call("sign", &json!([other.to_string()]).to_string())
            .await
            .is_err());
        // This agent's own commit: signed, and the signature verifies.
        let mine = json!({
            urls::IS_A: [urls::COMMIT],
            urls::SIGNER: agent,
        })
        .to_string();
        let signature = ask(&h, "sign", json!([mine])).await;
        assert!(
            signature.as_str().is_some_and(|s| s.len() > 60),
            "{signature}"
        );
    }

    /// The page mints a new resource's DID by having its genesis certificate
    /// signed (`Store.mintCertDid`): this agent's certificate is signed, byte
    /// for byte, and one naming another key is not.
    #[tokio::test]
    async fn a_genesis_certificate_of_this_agent_gets_signed() {
        use crate::genesis::GenesisCert;
        let d = Device::new().await;
        let h = host(&d);
        let agent = d.store.get_default_agent().unwrap();
        let own: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let cert = |key: [u8; 32]| {
            let c = GenesisCert::new_v2(key, 1_780_000_000_000, [7; 16], None, "", "");
            crate::agents::encode_base64(&c.encode())
        };

        let signature = ask(&h, "signBytes", json!([cert(own)])).await;
        let signature = signature.as_str().unwrap();
        let mine = GenesisCert::new_v2(own, 1_780_000_000_000, [7; 16], None, "", "");
        mine.verify(signature)
            .expect("a valid signature over the cert");

        let refused = h
            .call("signBytes", &json!([cert([9; 32])]).to_string())
            .await
            .unwrap_err();
        assert!(refused.contains("this device's agent"), "{refused}");
    }

    /// Bytes in a commit's `loroUpdate` are standard, padded base64, as the
    /// page's `encodeB64` writes them.
    fn standard_base64(bytes: &[u8]) -> String {
        let url_safe = crate::agents::encode_base64(bytes)
            .replace('-', "+")
            .replace('_', "/");
        let pad = (4 - url_safe.len() % 4) % 4;
        format!("{url_safe}{}", "=".repeat(pad))
    }

    /// Counts what is handed on after `applyCommit`.
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl LocalWritePusher for Counting {
        async fn push(&self, _response: &crate::commit::CommitResponse) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The data loss this guards against: text typed into a document in the
    /// page was gone when the document was opened again. The page saves by
    /// signing a commit (`sign`) and handing it over (`applyCommit`, its commit
    /// transport); reopening reads `getResourcesWithSnapshots`. Here the commit
    /// is made the way the page makes it for a DocumentV2 edit: a Loro update
    /// on top of the stored state, `previousCommit`, signed through `sign`.
    #[tokio::test]
    async fn a_typed_edit_to_a_document_is_there_when_it_is_opened_again() {
        use crate::loro::AtomicLoroDoc;
        let d = Device::new().await;
        let pushed = Arc::new(Counting::default());
        let h = EmbedHost::new(d.node.clone(), pushed.clone(), AgentProfiles::none());
        let doc_subject = d
            .store
            .create_resource(urls::DOCUMENT_V2, &d.drive, "Typed doc", None)
            .await
            .unwrap();
        let subject = subject_of(&d.store, &doc_subject);

        // The page's view of the document, as it opened it.
        let opened = ask(&h, "getResourcesWithSnapshots", json!([[doc_subject]])).await;
        let snapshot =
            crate::agents::decode_base64(opened[0]["snapshot"].as_str().unwrap()).unwrap();
        let page_doc = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();
        page_doc.set_peer_id(0x5eed).unwrap();
        let before = page_doc.oplog_vv();
        // Typing: the editor writes into the document's text.
        page_doc
            .doc()
            .get_text("documentContent")
            .insert(0, "Quokkatyped on the phone")
            .unwrap();
        page_doc.commit_with_message("e-typing");
        let update = page_doc.export_updates_since(&before);
        assert!(!update.is_empty());

        // The commit, built and signed as the page does.
        let agent = ask(&h, "agent", json!([])).await;
        let previous = d
            .store
            .get_resource(&subject)
            .await
            .unwrap()
            .get(urls::LAST_COMMIT)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "did:ad:commit:earlier".to_string());
        let mut commit = json!({
            urls::IS_A: [urls::COMMIT],
            urls::SUBJECT: doc_subject,
            urls::SIGNER: agent,
            urls::CREATED_AT: crate::utils::now(),
            urls::PREVIOUS_COMMIT: previous,
            urls::LORO_UPDATE: standard_base64(&update),
        });
        let signature = ask(&h, "sign", json!([commit.to_string()])).await;
        commit[urls::SIGNATURE] = signature;

        assert_eq!(
            ask(&h, "applyCommit", json!([commit.to_string()])).await,
            Json::Null
        );

        // Opening it again: the typed text is in what the page reads.
        let reopened = ask(&h, "getResourcesWithSnapshots", json!([[doc_subject]])).await;
        assert!(reopened[0]["jsonAd"]
            .as_str()
            .unwrap()
            .contains("Typed doc"));
        let snapshot =
            crate::agents::decode_base64(reopened[0]["snapshot"].as_str().unwrap()).unwrap();
        let text = AtomicLoroDoc::from_snapshot(&snapshot)
            .unwrap()
            .extract_document_plain_text();
        assert!(text.contains("Quokkatyped on the phone"), "{text:?}");

        // It is queued to go to the server and peers, and handed on.
        assert!(
            d.node.outbox().has_pending(&subject.pure_id()),
            "the edit is queued for sync"
        );
        for _ in 0..100 {
            if pushed.0.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the applied commit was not handed to the pusher");
    }

    /// A resource made in the page ("New resource") arrives as a genesis
    /// commit, in the `Client.postCommit` body: no `@id`.
    #[tokio::test]
    async fn a_new_resource_from_the_page_is_stored() {
        let d = Device::new().await;
        let h = host(&d);
        // A genesis commit made elsewhere, as it would cross the wire.
        let maker = Db::init_redb(Some("https://localhost".into()))
            .await
            .unwrap();
        maker.populate().await.unwrap();
        let (_agent, drive) = maker.setup("Maker").await.unwrap();
        let mut draft = Resource::new("did:ad:placeholder".into());
        draft
            .set_unsafe(
                urls::NAME.into(),
                crate::Value::String("Made in the page".into()),
            )
            .unwrap();
        draft
            .set_unsafe(urls::PARENT.into(), crate::Value::AtomicUrl(drive.into()))
            .unwrap();
        let response = draft.save_as_genesis(&maker).await.unwrap();
        let subject = response.commit.subject.to_string();
        let body = crate::client::commit_to_wire_json(&response.commit, &maker)
            .await
            .unwrap();
        assert!(!body.contains("\"@id\""));

        assert_eq!(ask(&h, "applyCommit", json!([body])).await, Json::Null);

        let rows = ask(&h, "getResourcesWithSnapshots", json!([[subject]])).await;
        assert!(rows[0]["jsonAd"]
            .as_str()
            .unwrap()
            .contains("Made in the page"));
    }
}
