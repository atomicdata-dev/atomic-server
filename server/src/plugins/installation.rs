//! Resolve existing resources into an installation without moving or cloning them.
//!
//! An identity belongs to its existing resource subject. Entry points inherit the
//! nearest identity, but only after their owning drive has been verified. Legacy
//! resources without an identity remain explicit; revoked identities never become
//! legacy or inherit a more powerful ancestor's signer.

use atomic_lib::{
    db::app_agent::{AppAgentKey, AppAgentState},
    urls, Db, Resource, Storelike, Subject, Value,
};

pub struct Installation {
    pub signing_as: Option<AppAgentKey>,
}

/// What an Installation's agent may reach, as its resource lists it.
///
/// Each list is a limit on top of the agent's own rights (the hierarchy), never
/// a right of its own: activating the Installation puts the agent on the listed
/// subtrees (`plugin.rs`), and the host refuses anything outside them even if
/// the agent was given more by hand. `None` is "this scope does
/// not limit", which is every Installation from before scopes existed.
/// `full-drive-access` is the widest scope: the drive, for reads and writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scopes {
    /// Subtrees (the resource and everything below it) that may be read.
    pub read: Option<Vec<String>>,
    /// Subtrees that may be written.
    pub write: Option<Vec<String>>,
    /// Interfaces that may be called through `calls.call`.
    pub calls: Option<Vec<String>>,
}

/// A JSON list of strings (or an object's keys) in either encoding a client
/// may have stored it in.
fn json_names(resource: &Resource, property: &str) -> Option<Vec<String>> {
    let json = match resource.get(property).ok()? {
        Value::Json(json) => json.clone(),
        Value::String(s) => serde_json::from_str(s).ok()?,
        _ => return None,
    };
    match json {
        serde_json::Value::Array(items) => Some(
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        serde_json::Value::Object(map) => Some(map.keys().cloned().collect()),
        _ => None,
    }
}

impl Scopes {
    /// The scopes of an Installation of `drive`.
    pub fn of(installation: &Resource, drive: &str) -> Self {
        let subtrees = |property: &str| {
            installation
                .get(property)
                .ok()
                .map(|v| v.to_subjects(None).unwrap_or_default())
        };
        let mut scopes = Self {
            read: subtrees(urls::READ_SCOPE),
            write: subtrees(urls::WRITE_SCOPE),
            calls: json_names(installation, urls::CALL_SCOPE),
        };
        let wide = json_names(installation, urls::GRANTS)
            .is_some_and(|names| names.iter().any(|n| n == "full-drive-access"));
        if wide {
            for list in [&mut scopes.read, &mut scopes.write] {
                list.get_or_insert_with(Vec::new).push(drive.to_string());
            }
        }
        scopes
    }

    pub async fn allows_read(&self, db: &Db, resource: &Resource) -> bool {
        within(db, resource, self.read.as_deref()).await
    }

    pub async fn allows_write(&self, db: &Db, resource: &Resource) -> bool {
        within(db, resource, self.write.as_deref()).await
    }

    pub fn allows_call(&self, interface: &str) -> bool {
        self.calls
            .as_ref()
            .is_none_or(|calls| calls.iter().any(|c| c == interface))
    }
}

/// Whether `resource` is one of `roots` or below one, by its parents. No roots
/// means no limit.
pub async fn within(db: &Db, resource: &Resource, roots: Option<&[String]>) -> bool {
    let Some(roots) = roots else {
        return true;
    };
    let roots: Vec<String> = roots
        .iter()
        .map(|r| Subject::from(r.as_str()).pure_id())
        .collect();
    let mut current = resource.clone();
    for _ in 0..64 {
        if roots.contains(&current.get_subject().pure_id()) {
            return true;
        }
        match current.get_parent(db).await {
            Ok(parent) => current = parent,
            Err(_) => return false,
        }
    }
    false
}

/// Whether this resource is an Installation that is not running.
///
/// Read from the resource rather than from any cached state, so pausing takes
/// effect on the next run with no registry to keep in step. `revoked` needs no
/// case here: revoking retires the identity, which the walk below already
/// refuses. Anything that is not an Installation (a legacy `Plugin`, an entry
/// point, a drive) is not suspendable and reads as running.
pub fn suspended_status(resource: &Resource) -> Option<String> {
    let is_installation = resource
        .get(urls::IS_A)
        .ok()
        .map(|is_a| is_a.to_reference_index_strings().unwrap_or_default())
        .is_some_and(|classes| classes.iter().any(|c| c == urls::INSTALLATION));
    if !is_installation {
        return None;
    }
    // Anything but `active` is suspended, including a status that is missing or
    // in an encoding this does not recognise. A plugin that stopped when it
    // should not have is visible and harmless; one that kept running through a
    // pause is the bug this guards. `revoked` lands here too, ahead of the
    // identity tombstone below, which is best-effort.
    let status = match resource.get(urls::INSTALLATION_STATUS) {
        Ok(Value::String(status)) => status.clone(),
        Ok(other) => other.to_string(),
        Err(_) => "a draft".to_string(),
    };
    (status != "active").then_some(status)
}

/// Whether this resource is an Installation that is not running.
pub fn is_suspended(resource: &Resource) -> bool {
    suspended_status(resource).is_some()
}

pub async fn resolve(db: &Db, drive: &str, entrypoint: &str) -> Result<Installation, String> {
    let expected = Subject::from(drive).pure_id();
    let mut current = db
        .get_resource(&entrypoint.into())
        .await
        .map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut signing_as = None;
    let mut identities = None;
    loop {
        if seen.len() >= 64 {
            return Err("plugin parent hierarchy is too deep".into());
        }
        if !seen.insert(current.get_subject().pure_id()) {
            return Err("plugin parent hierarchy contains a cycle".into());
        }
        if let Some(status) = suspended_status(&current) {
            return Err(format!(
                "this installation is {status}, not active, so it does not run"
            ));
        }
        if signing_as.is_none() {
            let key = AppAgentKey::new(drive, &current.get_subject().to_string());
            match db.get_app_agent_state(&key).map_err(|e| e.to_string())? {
                AppAgentState::Revoked => {
                    return Err(
                        "installation identity was revoked; reconnect before running".into(),
                    )
                }
                AppAgentState::Active(_) => signing_as = Some(key),
                AppAgentState::Legacy => {
                    if let Some(agent) =
                        app_identity_without_key(db, drive, &current, &mut identities).await
                    {
                        return Err(format!(
                            "{} writes as its own agent {agent}, but this node holds no key \
                             for it; connect the app's identity on this node before running \
                             it here",
                            current.get_subject()
                        ));
                    }
                }
            }
        }
        if let Some(owner) = current.get_drive() {
            if owner.pure_id() != expected {
                return Err("the plugin does not belong to this drive".into());
            }
        }
        if current.get_subject().pure_id() == expected {
            return Ok(Installation { signing_as });
        }
        current = current
            .get_parent(db)
            .await
            .map_err(|_| "the plugin has no owning drive".to_string())?;
    }
}

/// The app agent this resource was issued, when this node cannot sign as it.
///
/// Called only once the key lookup came back `Legacy`. An app's agent
/// resource syncs with the drive. Its key, posted once to `POST /app-agent`,
/// stays on the node it was posted to. On any other node the missing key
/// reads as `Legacy`, and without this check a run falls back to the server's
/// own agent. The app's writes are then attributed to the server, and the
/// app's own rights no longer bound them (ontola/atomic-plugins#41).
///
/// "Issued an app agent" is read from synced data only: an agent DID in the
/// resource's `write` list whose agent resource sits in the drive's
/// app-identities folder, which is where `createApp` puts every app agent.
/// `identities` caches that folder's subject across one resolve walk.
async fn app_identity_without_key(
    db: &Db,
    drive: &str,
    resource: &Resource,
    identities: &mut Option<Option<String>>,
) -> Option<String> {
    let writers: Vec<String> = resource
        .get(urls::WRITE)
        .ok()
        .and_then(|value| value.to_subjects(None).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|writer| Subject::from(writer.as_str()).is_agent_did())
        .collect();
    if writers.is_empty() {
        return None;
    }
    if identities.is_none() {
        *identities = Some(app_identities_folder(db, drive).await);
    }
    let folder = identities.as_ref()?.as_ref()?;
    for writer in writers {
        let Ok(agent) = db.get_resource(&writer.as_str().into()).await else {
            continue;
        };
        let parent = agent.get(urls::PARENT).ok().map(|p| p.to_string());
        if parent.as_deref() == Some(folder.as_str()) {
            return Some(writer);
        }
    }
    None
}

/// The drive's app-identities folder, found through the drive-schema property
/// `createApp` points at it with.
async fn app_identities_folder(db: &Db, drive: &str) -> Option<String> {
    let property = super::scheduler::drive_terms(db, drive)
        .await?
        .properties
        .remove("app-identities")?;
    let drive_resource = db.get_resource(&drive.into()).await.ok()?;
    drive_resource.get(&property).ok().map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::{agents::Agent, db::app_agent::AppAgent, urls, Value};

    #[test]
    fn full_drive_access_is_the_widest_scope_and_no_scope_limits_nothing() {
        let installation = |props: Vec<(&str, Value)>| {
            let mut resource = Resource::new("did:ad:installation".into());
            for (property, value) in props {
                resource.set_unsafe(property.into(), value).unwrap();
            }
            Scopes::of(&resource, "did:ad:drive")
        };
        assert_eq!(installation(vec![]), Scopes::default());
        assert!(Scopes::default().allows_call("atomic:any/thing@1"));

        let wide = installation(vec![(
            urls::GRANTS,
            Value::Json(serde_json::json!(["storage", "full-drive-access"])),
        )]);
        assert_eq!(wide.read, Some(vec!["did:ad:drive".to_string()]));
        assert_eq!(wide.write, Some(vec!["did:ad:drive".to_string()]));
        assert_eq!(wide.calls, None);

        let narrow = installation(vec![
            (
                urls::READ_SCOPE,
                Value::ResourceArray(vec!["did:ad:docs".into()]),
            ),
            (
                urls::CALL_SCOPE,
                Value::Json(serde_json::json!(["a:b/c@1"])),
            ),
        ]);
        assert_eq!(narrow.read, Some(vec!["did:ad:docs".to_string()]));
        assert_eq!(narrow.write, None);
        assert!(narrow.allows_call("a:b/c@1") && !narrow.allows_call("a:b/d@1"));
    }

    #[actix_rt::test]
    async fn resolves_existing_subjects_without_migrating_data_and_refuses_foreign_drives() {
        let mut f = crate::plugins::test_fixture::fixture("installation_binding").await;
        crate::plugins::test_fixture::write_plugin(&mut f, "binding test").await;
        let db = &f.appstate.store;
        assert!(resolve(db, &f.drive, &f.plugin)
            .await
            .unwrap()
            .signing_as
            .is_none());
        let child = crate::plugins::test_fixture::genesis(
            db,
            vec![(urls::PARENT, Value::AtomicUrl(f.plugin.as_str().into()))],
        )
        .await;
        let key = AppAgentKey::new(&f.drive, &f.plugin);
        let agent = Agent::new(None).unwrap();
        db.set_app_agent(
            &key,
            &AppAgent::new(agent.subject.to_string(), agent.build_secret().unwrap(), 0),
        )
        .unwrap();
        assert_eq!(
            resolve(db, &f.drive, &child).await.unwrap().signing_as,
            Some(key.clone())
        );
        // A key stored under a forged drive claim must not bypass ownership.
        db.set_app_agent(
            &AppAgentKey::new("did:ad:wrong", &child),
            &AppAgent::new(agent.subject.to_string(), agent.build_secret().unwrap(), 0),
        )
        .unwrap();
        assert!(resolve(db, "did:ad:wrong", &child).await.is_err());
        db.delete_app_agent(&key).unwrap();
        assert!(resolve(db, &f.drive, &child).await.is_err());
        assert_eq!(
            db.get_resource(&child.as_str().into())
                .await
                .unwrap()
                .get(urls::PARENT)
                .unwrap()
                .to_string(),
            f.plugin
        );
        db.set_app_agent(
            &key,
            &AppAgent::new(agent.subject.to_string(), agent.build_secret().unwrap(), 0),
        )
        .unwrap();
        assert_eq!(
            resolve(db, &f.drive, &child).await.unwrap().signing_as,
            Some(key)
        );
    }
}
