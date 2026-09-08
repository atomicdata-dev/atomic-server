//! Persistent import identity shared by JSON-AD and sandbox import proposals.
use crate::{agents::ForAgent, errors::AtomicResult, urls, Resource, Storelike, Subject, Value};

/// Match the immediate destination, not arbitrary descendants. Ambiguity is an
/// error: returning the first result would update an unrelated resource.
pub async fn find_existing(
    store: &impl Storelike,
    parent: &Subject,
    local_id: &str,
) -> AtomicResult<Option<String>> {
    find_in_scope(store, parent, local_id, false).await
}

/// JSON-AD batches use the import root as the local-reference namespace, even
/// when an explicit parent nests a resource beneath another imported resource.
pub async fn find_in_scope(
    store: &impl Storelike,
    parent: &Subject,
    local_id: &str,
    descendants: bool,
) -> AtomicResult<Option<String>> {
    let mut query = crate::storelike::Query::new_prop_val(urls::LOCAL_ID, local_id);
    query.for_agent = ForAgent::Sudo;
    let result = store.query(&query).await?;
    let mut matches = Vec::new();
    for resource in result.resources {
        if if descendants {
            resource.has_parent(store, parent.as_str()).await
        } else {
            resource
                .get(urls::PARENT)
                .ok()
                .is_some_and(|value| Subject::from(value.to_string()).pure_id() == parent.pure_id())
        } {
            matches.push(resource);
        }
    }
    resolve_matches(&matches)
}

/// Content reviewed by the user, excluding changing bookkeeping and the decision itself.
pub fn review_snapshot(resource: &Resource) -> AtomicResult<serde_json::Value> {
    let mut value: serde_json::Value = serde_json::from_str(&resource.to_json_ad(None)?)?;
    if let Some(map) = value.as_object_mut() {
        map.remove("@id");
        for key in [
            "subject",
            "loroUpdate",
            "lastCommit",
            "createdAt",
            "updatedAt",
            "createdBy",
            "modifiedAt",
            "modifiedBy",
            "genesis",
            "importResolution",
        ] {
            map.remove(&format!("https://atomicdata.dev/properties/{key}"));
        }
    }
    Ok(value)
}
fn resolution(resource: &Resource) -> Option<&serde_json::Value> {
    match resource.get(urls::IMPORT_RESOLUTION).ok()? {
        Value::Json(value) => Some(value),
        _ => None,
    }
}
pub fn resolve_matches(matches: &[Resource]) -> AtomicResult<Option<String>> {
    if matches.is_empty() {
        return Ok(None);
    }
    if matches.len() == 1 && resolution(&matches[0]).is_none() {
        return Ok(Some(matches[0].get_subject().to_string()));
    }
    let mut winners = Vec::new();
    for candidate in matches {
        let Some(marker) = resolution(candidate) else {
            continue;
        };
        let id = candidate.get_subject().pure_id();
        let Some(members) = marker.get("members").and_then(|v| v.as_object()) else {
            continue;
        };
        let Some(supersedes) = marker.get("supersedes").and_then(|v| v.as_array()) else {
            continue;
        };
        if marker.get("version") != Some(&serde_json::json!(1))
            || marker.get("canonical").and_then(|v| v.as_str()) != Some(id.as_str())
            || members.len() != matches.len()
        {
            continue;
        }
        let mut valid = true;
        for other in matches {
            let other_id = other.get_subject().pure_id();
            let Some(reviewed) = members.get(&other_id) else {
                valid = false;
                break;
            };
            if other_id == id {
                continue;
            }
            if reviewed != &review_snapshot(other)?
                || resolution(other)
                    .is_some_and(|m| !m.get("id").is_some_and(|id| supersedes.contains(id)))
            {
                valid = false;
                break;
            }
        }
        if valid {
            winners.push(candidate.get_subject().to_string());
        }
    }
    if winners.len() == 1 {
        return Ok(winners.pop());
    }
    Err("Ambiguous import identity: review all copies again before importing".into())
}

/// Called inside the identity lock. A signed review may resolve an ambiguous
/// group only when every reviewed copy is still current. No original is deleted.
pub async fn validate_candidate(
    store: &impl Storelike,
    old: Option<&Resource>,
    new: &Resource,
) -> AtomicResult<Option<String>> {
    let Some((parent, local_id)) = identity(new) else {
        return Ok(None);
    };
    let mut query = crate::storelike::Query::new_prop_val(urls::LOCAL_ID, &local_id);
    query.for_agent = ForAgent::Sudo;
    let mut matches: Vec<Resource> = store
        .query(&query)
        .await?
        .resources
        .into_iter()
        .filter(|r| {
            identity(r).is_some_and(|(p, id)| p.pure_id() == parent.pure_id() && id == local_id)
        })
        .collect();
    let changed = resolution(new) != old.and_then(resolution);
    if changed {
        let marker = resolution(new)
            .ok_or("Removing an import resolution requires a new reviewed decision")?;
        let members = marker
            .get("members")
            .and_then(|v| v.as_object())
            .ok_or("Resolution needs reviewed copies")?;
        if matches.len() < 2
            || matches.len() > 100
            || members.len() != matches.len()
            || marker
                .get("id")
                .and_then(|v| v.as_str())
                .is_none_or(|id| id.is_empty())
        {
            return Err("Resolution must review every existing copy (two to 100)".into());
        }
        for r in &matches {
            if members.get(&r.get_subject().pure_id()) != Some(&review_snapshot(r)?) {
                return Err("Import resolution is stale; review every copy again".into());
            }
            if r.get(urls::IS_A).ok().map(ToString::to_string)
                != new.get(urls::IS_A).ok().map(ToString::to_string)
            {
                return Err("Import resolution requires matching classes".into());
            }
        }
        let mut expected = review_snapshot(old.ok_or("A primary record must already exist")?)?;
        if let Some(choices) = marker.get("choices") {
            for (property, source) in choices
                .as_object()
                .ok_or("Resolution choices must be an object")?
            {
                if property.starts_with("https://atomicdata.dev/properties/")
                    && property != urls::NAME
                    && property != urls::DESCRIPTION
                    || property == "@id"
                {
                    return Err("This field is protected from consolidation".into());
                }
                let member = source
                    .as_str()
                    .and_then(|s| members.get(s))
                    .ok_or("Choose a reviewed copy")?;
                if let Some(value) = member.get(property) {
                    expected[property] = value.clone();
                } else {
                    expected.as_object_mut().unwrap().remove(property);
                }
            }
        }
        if expected != review_snapshot(new)? {
            return Err("Consolidated values must match the reviewed field choices".into());
        }
    }
    let subject = new.get_subject().pure_id();
    if let Some(existing) = matches
        .iter_mut()
        .find(|r| r.get_subject().pure_id() == subject)
    {
        *existing = new.clone();
    }
    // A new third claim must not be smuggled into a reviewed group.
    else if !matches.is_empty() {
        return Err("Import identity already exists; preview again".into());
    } else {
        return Ok(None);
    }
    resolve_matches(&matches)
}

pub fn identity(resource: &Resource) -> Option<(Subject, String)> {
    // Commit envelopes carry copies of changed values; they are not imports.
    if resource.get_subject().is_commit_did() {
        return None;
    }
    let Value::String(id) = resource.get(urls::LOCAL_ID).ok()? else {
        return None;
    };
    let parent = Subject::from(resource.get(urls::PARENT).ok()?.to_string());
    Some((parent, id.clone()))
}

/// The source snapshot is signed with the mutation. Check it while the subject
/// lock is held so a stale preview cannot overwrite intervening local edits.
pub fn validate_baseline(old: Option<&Resource>, new: &Resource) -> AtomicResult<()> {
    let Some(Value::Json(next)) = new.get(urls::IMPORT_BASELINE).ok() else {
        return Ok(());
    };
    let previous = old.and_then(|r| r.get(urls::IMPORT_BASELINE).ok());
    if matches!(previous, Some(Value::Json(value)) if value == next) {
        return Ok(());
    }
    let values = next
        .get("values")
        .and_then(|v| v.as_object())
        .ok_or("Import baseline needs source values")?;
    if values.contains_key(urls::IMPORT_BASELINE)
        || values.contains_key(urls::IMPORT_RESOLUTION)
        || values.contains_key(urls::IMPORT_REFERENCE_REVIEW)
        || values.contains_key(urls::LOCAL_ID)
        || values.contains_key(urls::PARENT)
        || values.contains_key(urls::IS_A)
    {
        return Err("Import source values cannot contain identity or baseline fields".into());
    }
    let previous_values = match previous {
        Some(Value::Json(value)) => value.get("values"),
        _ => None,
    };
    if next.get("previous") != Some(previous_values.unwrap_or(&serde_json::json!({}))) {
        return Err("Import preview is stale; preview this source again before applying".into());
    }
    let current: serde_json::Value = match old {
        Some(r) => serde_json::from_str(&r.to_json_ad(None)?)?,
        None => serde_json::json!({}),
    };
    let proposed: serde_json::Value = serde_json::from_str(&new.to_json_ad(None)?)?;
    for (property, desired) in values {
        let before = current.get(property);
        let after = proposed.get(property);
        if let Some(review) = next.get("resolution").and_then(|v| v.get(property)) {
            let observed = if review.get("present").and_then(|v| v.as_bool()) == Some(true) {
                review.get("value")
            } else {
                None
            };
            if observed != before {
                return Err("Import resolution is stale; review the current value again".into());
            }
            match review.get("choice").and_then(|v| v.as_str()) {
                Some("local") if after == before => {}
                Some("source") if after == Some(desired) => {}
                _ => return Err("Import resolution does not match the reviewed choice".into()),
            }
            continue;
        }
        if old.is_none() {
            if after != Some(desired) {
                return Err("Imported value did not preserve its source datatype".into());
            }
        } else if previous_values.is_none() {
            if before != Some(desired) || after != before {
                return Err("Existing import has no baseline; local values must be reviewed before adoption".into());
            }
        } else if after != before {
            if before != previous_values.and_then(|v| v.get(property)) || after != Some(desired) {
                return Err(
                    "Import conflicts with a local edit; preview again and resolve the conflict"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// Signed per-record compare-and-set review. Normal edits can retain the receipt.
pub fn validate_reference_review(old: Option<&Resource>, new: &Resource) -> AtomicResult<()> {
    let Some(next) = new.get(urls::IMPORT_REFERENCE_REVIEW).ok() else {
        return Ok(());
    };
    let Value::Json(review) = next else {
        return Err("Link review must be JSON".into());
    };
    if matches!(old.and_then(|r| r.get(urls::IMPORT_REFERENCE_REVIEW).ok()), Some(Value::Json(previous)) if previous == review)
    {
        return Ok(());
    }
    if review
        .get("id")
        .and_then(|v| v.as_str())
        .is_none_or(str::is_empty)
    {
        return Err("Link review needs an ID".into());
    }
    let changes = review
        .get("changes")
        .and_then(|v| v.as_array())
        .ok_or("Link review needs changes")?;
    if changes.is_empty() || changes.len() > 100 {
        return Err("Review between one and 100 link fields".into());
    }
    let old = old.ok_or("Link review requires an existing record")?;
    let mut properties = std::collections::HashSet::new();
    for change in changes {
        let p = change
            .get("property")
            .and_then(|v| v.as_str())
            .ok_or("Link review needs a property")?;
        if p.starts_with("https://atomicdata.dev/properties/") || !properties.insert(p) {
            return Err("Protected or duplicate link field".into());
        }
        let before = old.get(p)?;
        let after = new.get(p)?;
        if !matches!(
            (before, after),
            (Value::AtomicUrl(_), Value::AtomicUrl(_))
                | (Value::ResourceArray(_), Value::ResourceArray(_))
        ) {
            return Err("Only typed links can be rewritten".into());
        }
        let current: serde_json::Value = serde_json::from_str(&old.to_json_ad(None)?)?;
        let proposed: serde_json::Value = serde_json::from_str(&new.to_json_ad(None)?)?;
        if change.get("before") != current.get(p) {
            return Err("Link review is stale; review the current links again".into());
        }
        if change.get("after") != proposed.get(p) {
            return Err("Link update does not match the reviewed value".into());
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "db"))]
mod tests {
    use super::*;
    use serde_json::json;
    fn row(subject: &str, parent: &Subject, name: &str) -> Resource {
        let mut r = Resource::new(subject.into());
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent.clone()))
            .unwrap();
        r.set_unsafe(urls::LOCAL_ID.into(), Value::String("provider:one".into()))
            .unwrap();
        r.set_unsafe(urls::NAME.into(), Value::String(name.into()))
            .unwrap();
        r
    }
    #[tokio::test]
    async fn offline_duplicates_remain_visible_after_sync_in_both_orders() {
        use crate::sync::{
            engine::import_sync_push,
            protocol::{DecodedSyncPush, SyncPushEntry},
        };
        let a = crate::test_utils::init_store().await;
        let parent = crate::test_utils::create_test_drive(&a).await.unwrap();
        let b = crate::test_utils::init_store().await;
        let drive = a.get_resource(&parent).await.unwrap();
        b.add_resource_opts(&drive, false, true, true)
            .await
            .unwrap();
        let mut first = row("https://localhost/offline-a", &parent, "Local A");
        let mut second = row("https://localhost/offline-b", &parent, "Local B");
        first.save_as_genesis(&a).await.unwrap();
        second.save_as_genesis(&b).await.unwrap();
        let copies = [first, second];
        for (reverse, live) in [(false, false), (true, false), (false, true), (true, true)] {
            let receiver = crate::test_utils::init_store().await;
            receiver
                .add_resource_opts(&drive, false, true, true)
                .await
                .unwrap();
            for index in if reverse { [1, 0] } else { [0, 1] } {
                let r = &copies[index];
                let push = DecodedSyncPush {
                    drive: parent.to_string(),
                    last: true,
                    entries: vec![SyncPushEntry {
                        subject: r.get_subject().to_string(),
                        loro_bytes: r.build_state_doc().unwrap().export_snapshot(),
                    }],
                };
                for _ in 0..2 {
                    // A replay must not hide either copy.
                    if live {
                        crate::sync::ws_apply::apply_state_update(
                            &receiver,
                            &push.entries[0].subject,
                            &push.entries[0].loro_bytes,
                        )
                        .await
                        .unwrap();
                    } else {
                        let (count, _) = import_sync_push(&push, &receiver, &ForAgent::Sudo, false)
                            .await
                            .unwrap();
                        assert_eq!(count, 1);
                    }
                    let found = receiver.get_resource(r.get_subject()).await.unwrap();
                    assert_eq!(
                        found.get(urls::NAME).unwrap().to_string(),
                        r.get(urls::NAME).unwrap().to_string()
                    );
                }
            }
            assert!(find_existing(&receiver, &parent, "provider:one")
                .await
                .unwrap_err()
                .to_string()
                .contains("Ambiguous"));
            let mut third = row("https://localhost/offline-third", &parent, "Must reject");
            assert!(third.save_as_genesis(&receiver).await.is_err());
            let mut primary = receiver
                .get_resource(copies[0].get_subject())
                .await
                .unwrap();
            let mut members = serde_json::Map::new();
            for copy in &copies {
                let current = receiver.get_resource(copy.get_subject()).await.unwrap();
                members.insert(
                    copy.get_subject().pure_id(),
                    review_snapshot(&current).unwrap(),
                );
            }
            let mut marker = json!({"version":1,"id":"review-one","canonical":primary.get_subject().pure_id(),"members":members,"supersedes":[]});
            // An altered reviewed value must be rejected without changing either copy.
            marker["members"][copies[1].get_subject().pure_id()][urls::NAME] =
                json!("Not reviewed");
            primary
                .set_unsafe(urls::IMPORT_RESOLUTION.into(), Value::Json(marker.clone()))
                .unwrap();
            assert!(primary
                .save_locally(&receiver)
                .await
                .unwrap_err()
                .to_string()
                .contains("stale"));
            primary = receiver
                .get_resource(copies[0].get_subject())
                .await
                .unwrap();
            marker["members"][copies[1].get_subject().pure_id()][urls::NAME] = json!("Local B");
            // Consolidation must exactly match an explicit reviewed choice.
            marker["choices"] = json!({urls::NAME: copies[1].get_subject().pure_id()});
            primary
                .set_unsafe(urls::IMPORT_RESOLUTION.into(), Value::Json(marker.clone()))
                .unwrap();
            assert!(primary
                .save_locally(&receiver)
                .await
                .unwrap_err()
                .to_string()
                .contains("reviewed field choices"));
            primary = receiver
                .get_resource(copies[0].get_subject())
                .await
                .unwrap();
            primary
                .set_unsafe(urls::NAME.into(), Value::String("Local B".into()))
                .unwrap();
            primary
                .set_unsafe(urls::IMPORT_RESOLUTION.into(), Value::Json(marker))
                .unwrap();
            primary.save_locally(&receiver).await.unwrap();
            assert_eq!(
                receiver
                    .get_resource(primary.get_subject())
                    .await
                    .unwrap()
                    .get(urls::NAME)
                    .unwrap()
                    .to_string(),
                "Local B"
            );
            assert_eq!(
                find_existing(&receiver, &parent, "provider:one")
                    .await
                    .unwrap()
                    .unwrap(),
                primary.get_subject().to_string()
            );
            assert_eq!(
                receiver
                    .get_resource(copies[1].get_subject())
                    .await
                    .unwrap()
                    .get(urls::NAME)
                    .unwrap()
                    .to_string(),
                "Local B"
            );
            // Replaying the original snapshot cannot undo the signed decision.
            let push = DecodedSyncPush {
                drive: parent.to_string(),
                last: true,
                entries: vec![SyncPushEntry {
                    subject: copies[1].get_subject().to_string(),
                    loro_bytes: copies[1].build_state_doc().unwrap().export_snapshot(),
                }],
            };
            import_sync_push(&push, &receiver, &ForAgent::Sudo, false)
                .await
                .unwrap();
            assert!(find_existing(&receiver, &parent, "provider:one")
                .await
                .unwrap()
                .is_some());
            // A genuinely new offline edit is not replay: it reopens review.
            let mut offline = copies[1].clone();
            offline
                .set_unsafe(urls::NAME.into(), Value::String("New offline value".into()))
                .unwrap();
            offline.save_locally(&b).await.unwrap();
            let offline = b.get_resource(copies[1].get_subject()).await.unwrap();
            let edited = DecodedSyncPush {
                drive: parent.to_string(),
                last: true,
                entries: vec![SyncPushEntry {
                    subject: offline.get_subject().to_string(),
                    loro_bytes: offline.build_state_doc().unwrap().export_snapshot(),
                }],
            };
            import_sync_push(&edited, &receiver, &ForAgent::Sudo, false)
                .await
                .unwrap();
            assert!(find_existing(&receiver, &parent, "provider:one")
                .await
                .unwrap_err()
                .to_string()
                .contains("Ambiguous"));
        }
    }

    #[tokio::test]
    async fn reference_review_rejects_stale_signed_writes() {
        let store = crate::test_utils::init_store().await;
        let parent = crate::test_utils::create_test_drive(&store).await.unwrap();
        let p = "https://example.com/project";
        let mut initial = Resource::new("https://localhost/reference-review".into());
        initial
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent))
            .unwrap();
        initial
            .set_unsafe(p.into(), Value::AtomicUrl("https://example.com/old".into()))
            .unwrap();
        initial.save_locally(&store).await.unwrap();
        let subject = initial.get_subject().clone();
        let mut stale = store.get_resource(&subject).await.unwrap();
        let mut approved = store.get_resource(&subject).await.unwrap();
        for (r, id, target) in [
            (&mut approved, "first", "https://example.com/new"),
            (&mut stale, "stale", "https://example.com/other"),
        ] {
            r.set_unsafe(p.into(), Value::AtomicUrl(target.into()))
                .unwrap();
            r.set_unsafe(urls::IMPORT_REFERENCE_REVIEW.into(), Value::Json(json!({"id":id,"changes":[{"property":p,"before":"https://example.com/old","after":target}]}))).unwrap();
        }
        approved.save_locally(&store).await.unwrap();
        assert!(stale.save_locally(&store).await.is_err());
        assert_eq!(
            store
                .get_resource(&subject)
                .await
                .unwrap()
                .get(p)
                .unwrap()
                .to_string(),
            "https://example.com/new"
        );
        // A normal subsequent edit can retain the review receipt.
        let mut local = store.get_resource(&subject).await.unwrap();
        local
            .set_unsafe(
                p.into(),
                Value::AtomicUrl("https://example.com/local".into()),
            )
            .unwrap();
        local.save_locally(&store).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_identity_claims_have_one_winner() {
        let store = crate::test_utils::init_store().await;
        let parent = crate::test_utils::create_test_drive(&store).await.unwrap();
        let mut first = row("https://localhost/import-a", &parent, "A");
        let mut second = row("https://localhost/import-b", &parent, "B");
        let (a, b) = tokio::join!(first.save_locally(&store), second.save_locally(&store));
        assert_eq!(
            usize::from(a.is_ok()) + usize::from(b.is_ok()),
            1,
            "{a:?} {b:?}"
        );
        assert!(find_existing(&store, &parent, "provider:one")
            .await
            .unwrap()
            .is_some());
        let other_parent = crate::test_utils::create_test_drive(&store).await.unwrap();
        row("https://localhost/import-c", &other_parent, "C")
            .save_locally(&store)
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn reviewed_resolution_preserves_local_choice_and_rejects_stale_review() {
        let store = crate::test_utils::init_store().await;
        let parent = crate::test_utils::create_test_drive(&store).await.unwrap();
        let mut initial = row("https://localhost/resolution", &parent, "Source");
        initial
            .set_unsafe(
                urls::IMPORT_BASELINE.into(),
                Value::Json(json!({"values":{urls::NAME:"Source"},"previous":{}})),
            )
            .unwrap();
        initial.save_locally(&store).await.unwrap();
        let subject = initial.get_subject().clone();
        let mut local = store.get_resource(&subject).await.unwrap();
        local
            .set_unsafe(urls::NAME.into(), Value::String("Local".into()))
            .unwrap();
        local.save_locally(&store).await.unwrap();
        let mut resolution = store.get_resource(&subject).await.unwrap();
        resolution.set_unsafe(urls::IMPORT_BASELINE.into(), Value::Json(json!({"values":{urls::NAME:"Remote"},"previous":{urls::NAME:"Source"},"resolution":{urls::NAME:{"present":true,"value":"Local","choice":"local"}}}))).unwrap();
        resolution.save_locally(&store).await.unwrap();
        let mut stale = store.get_resource(&subject).await.unwrap();
        stale
            .set_unsafe(urls::NAME.into(), Value::String("Next remote".into()))
            .unwrap();
        stale.set_unsafe(urls::IMPORT_BASELINE.into(), Value::Json(json!({"values":{urls::NAME:"Next remote"},"previous":{urls::NAME:"Remote"},"resolution":{urls::NAME:{"present":true,"value":"Older local","choice":"source"}}}))).unwrap();
        assert!(stale
            .save_locally(&store)
            .await
            .unwrap_err()
            .to_string()
            .contains("stale"));
        assert_eq!(
            store
                .get_resource(&subject)
                .await
                .unwrap()
                .get(urls::NAME)
                .unwrap()
                .to_string(),
            "Local"
        );
    }
    #[tokio::test]
    async fn stale_baselines_and_local_edits_reject_at_commit() {
        let store = crate::test_utils::init_store().await;
        let parent = crate::test_utils::create_test_drive(&store).await.unwrap();
        let mut first = row("https://localhost/import-baseline", &parent, "A");
        first
            .set_unsafe(
                urls::IMPORT_BASELINE.into(),
                Value::Json(json!({"values":{urls::NAME:"A"},"previous":{}})),
            )
            .unwrap();
        first.save_locally(&store).await.unwrap();
        let subject = first.get_subject().clone();
        let mut approved = store.get_resource(&subject).await.unwrap();
        let mut stale = store.get_resource(&subject).await.unwrap();
        for (resource, name) in [(&mut approved, "B"), (&mut stale, "C")] {
            resource
                .set_unsafe(urls::NAME.into(), Value::String(name.into()))
                .unwrap();
            resource
                .set_unsafe(
                    urls::IMPORT_BASELINE.into(),
                    Value::Json(json!({"values":{urls::NAME:name},"previous":{urls::NAME:"A"}})),
                )
                .unwrap();
        }
        approved.save_locally(&store).await.unwrap();
        let stale_result = stale.save_locally(&store).await;
        let after_stale = store.get_resource(&subject).await.unwrap();
        assert_eq!(
            after_stale.get(urls::NAME).unwrap().to_string(),
            "B",
            "stale outcome: {:?}; baseline: {:?}",
            stale_result.as_ref().err(),
            after_stale.get(urls::IMPORT_BASELINE)
        );
        let mut duplicate = store.get_resource(&subject).await.unwrap();
        duplicate.set_unsafe(urls::IMPORT_BASELINE.into(), Value::Json(json!({"values":{urls::NAME:"B"},"previous":{urls::NAME:"A"},"approval":"second-approval"}))).unwrap();
        assert!(duplicate
            .save_locally(&store)
            .await
            .unwrap_err()
            .to_string()
            .contains("stale"));
        let mut local = store.get_resource(&subject).await.unwrap();
        local
            .set_unsafe(urls::NAME.into(), Value::String("Local".into()))
            .unwrap();
        local.save_locally(&store).await.unwrap();
        let mut update = store.get_resource(&subject).await.unwrap();
        update
            .set_unsafe(urls::NAME.into(), Value::String("Remote".into()))
            .unwrap();
        update
            .set_unsafe(
                urls::IMPORT_BASELINE.into(),
                Value::Json(json!({"values":{urls::NAME:"Remote"},"previous":{urls::NAME:"B"}})),
            )
            .unwrap();
        assert!(update
            .save_locally(&store)
            .await
            .unwrap_err()
            .to_string()
            .contains("local edit"));
    }
}
