//! The store, as the planner and the applier see it.
//!
//! Planning and applying are deliberately written against narrow traits so
//! they can be tested against fixtures. This is the one implementation that
//! touches real data, and it is where the rights check lives.

use std::collections::HashMap;

use atomic_lib::{
    agents::ForAgent, datatype::DataType, db::app_agent::AppAgentKey, hierarchy::check_write, urls,
    Db, Resource, Storelike, Subject, Value,
};
use serde_json::Value as Json;

use crate::plugins::{
    apply::{ApplyHost, CreateRequest},
    plan::PlanHost,
};

/// Compatibility accessor for callers that only need the installation signer.
/// Ownership and lifecycle validation live in the shared installation resolver.
pub async fn app_signing_for(
    db: &Db,
    drive: &str,
    plugin: &str,
) -> Result<Option<AppAgentKey>, String> {
    Ok(super::installation::resolve(db, drive, plugin)
        .await?
        .signing_as)
}

pub async fn check_effective_read(
    db: &Db,
    resource: &Resource,
    account: &ForAgent,
    app: Option<&AppAgentKey>,
) -> Result<(), String> {
    atomic_lib::hierarchy::check_read(db, resource, account)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(key) = app {
        let info = db
            .get_app_agent_info(key)
            .map_err(|e| e.to_string())?
            .ok_or("app identity is missing")?;
        atomic_lib::hierarchy::check_read(db, resource, &ForAgent::AgentSubject(info.agent.into()))
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub struct StoreApplyHost {
    pub store: Db,
    pub for_agent: ForAgent,
    /// The app whose key signs these writes, when it has one.
    ///
    /// Without it the server's own agent signs, and the history then says the
    /// server made a change that an app decided on. The signer is the author —
    /// a commit carries one identity — so this is the only place the two can
    /// be made to agree.
    pub signing_as: Option<AppAgentKey>,
}

impl StoreApplyHost {
    /// All execution paths resolve the same installation and retain the actor's
    /// rights as an independent bound on effects.
    pub async fn for_installation(
        store: &Db,
        drive: &str,
        plugin: &str,
        for_agent: ForAgent,
    ) -> Result<Self, String> {
        Ok(Self {
            store: store.clone(),
            for_agent,
            signing_as: super::installation::resolve(store, drive, plugin)
                .await?
                .signing_as,
        })
    }

    /// A selected installation must still have a key at effect time. Only an
    /// explicitly legacy host may use the default signer.
    fn app_agent(&self) -> Result<Option<atomic_lib::agents::Agent>, String> {
        let Some(key) = &self.signing_as else {
            return Ok(None);
        };

        self.store
            .with_app_agent(key, |agent| agent.clone())
            .map_err(|e| format!("could not read {}'s key: {e}", key.app))?
            .map(Some)
            .ok_or_else(|| "installation identity is missing or revoked".to_string())
    }

    async fn commit(&self, resource: &mut Resource, what: &str) -> Result<(), String> {
        let result = match self.app_agent()? {
            Some(agent) => resource.save_as(&agent, &self.store).await,
            None => resource.save(&self.store).await,
        };

        result.map(|_| ()).map_err(|e| format!("{what}: {e}"))
    }

    /// Refuses unless `for_agent` may write here.
    async fn may_write(&self, subject: &str) -> Result<(), String> {
        let resource = self
            .store
            .get_resource(&subject.into())
            .await
            .map_err(|e| format!("{subject} could not be read: {e}"))?;

        check_write(&self.store, &resource, &self.for_agent)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(agent) = self.app_agent()? {
            check_write(
                &self.store,
                &resource,
                &ForAgent::AgentSubject(agent.subject),
            )
            .await
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    async fn value_for(&self, property: &str, value: Json) -> Result<Value, String> {
        let full = self
            .store
            .get_property(property)
            .await
            .map_err(|e| format!("{property} is not a property: {e}"))?;

        json_to_value(value, &full.data_type).map_err(|e| format!("{}: {e}", full.shortname))
    }
}

#[async_trait::async_trait]
impl PlanHost for StoreApplyHost {
    fn create_subject(&mut self, parent: &str) -> String {
        // A resource under a DID drive gets its identity from a genesis
        // certificate, which cannot be guessed before it is signed. So the
        // plan carries a placeholder and the applier reports back what the
        // store actually minted — showing a plausible-looking URL that will
        // never exist would be worse than showing an obvious placeholder.
        if is_did(parent) {
            return format!("_new:{}", ulid::Ulid::new().to_string().to_lowercase());
        }

        format!(
            "{}/{}",
            parent.trim_end_matches('/'),
            ulid::Ulid::new().to_string().to_lowercase(),
        )
    }

    async fn get_property(&mut self, subject: &str) -> Option<(String, String)> {
        let resource = self.store.get_resource(&subject.into()).await.ok()?;
        check_effective_read(
            &self.store,
            &resource,
            &self.for_agent,
            self.signing_as.as_ref(),
        )
        .await
        .ok()?;
        let property = self.store.get_property(subject).await.ok()?;

        Some((property.data_type.to_string(), property.shortname))
    }

    async fn read_resource(&mut self, subject: &str) -> Option<HashMap<String, Json>> {
        // A subject that could not be fetched is indistinguishable from one
        // that was never created, and both mean the same thing for planning:
        // there is nothing here to change.
        let resource = self.store.get_resource(&subject.into()).await.ok()?;
        check_effective_read(
            &self.store,
            &resource,
            &self.for_agent,
            self.signing_as.as_ref(),
        )
        .await
        .ok()?;

        // Through JSON-AD, so the planner compares against the same shape the
        // plugin was given when it read the resource.
        let json = resource.to_json_ad(None).ok()?;
        let mut map: HashMap<String, Json> = serde_json::from_str(&json).ok()?;
        map.remove("@id");

        Some(map)
    }
}

#[async_trait::async_trait]
impl ApplyHost for StoreApplyHost {
    async fn create(&mut self, request: CreateRequest) -> Result<String, String> {
        self.may_write(&request.parent).await?;

        let mut resource = Resource::new(self.create_subject(&request.parent));

        resource
            .set_unsafe(
                urls::PARENT.into(),
                Value::AtomicUrl(Subject::from_raw(&request.parent, None)),
            )
            .map_err(|e| e.to_string())?;

        if !request.is_a.is_empty() {
            resource
                .set_unsafe(
                    urls::IS_A.into(),
                    Value::ResourceArray(
                        request
                            .is_a
                            .iter()
                            .map(|class| {
                                atomic_lib::values::SubResource::Subject(Subject::from_raw(
                                    class, None,
                                ))
                            })
                            .collect(),
                    ),
                )
                .map_err(|e| e.to_string())?;
        }

        for (property, value) in request.prop_vals {
            let value = self
                .value_for(&property, stamp_import_approval(&property, value))
                .await?;

            resource
                .set_unsafe(property, value)
                .map_err(|e| e.to_string())?;
        }

        // Signed by the app here too. Under a DID drive the signature *is* the
        // subject, so signing as the server would mint the app's own data
        // under the server's name rather than merely mislabelling its author.
        match (is_did(&request.parent), self.app_agent()?) {
            (true, Some(agent)) => {
                resource
                    .save_as_genesis_signed_by(&agent, &self.store)
                    .await
            }
            (true, None) => resource.save_as_genesis(&self.store).await,
            (false, Some(agent)) => resource.save_as(&agent, &self.store).await,
            (false, None) => resource.save(&self.store).await,
        }
        .map_err(|e| format!("could not create a resource under {}: {e}", request.parent))?;

        // Read the subject after saving: genesis mints it from the signature,
        // so it is not knowable before.
        Ok(resource.get_subject().to_string())
    }

    async fn set(&mut self, subject: &str, prop_vals: HashMap<String, Json>) -> Result<(), String> {
        self.may_write(subject).await?;

        let mut resource = self
            .store
            .get_resource(&subject.into())
            .await
            .map_err(|e| format!("{subject} could not be read: {e}"))?;

        for (property, value) in prop_vals {
            let value = self
                .value_for(&property, stamp_import_approval(&property, value))
                .await?;

            resource
                .set_unsafe(property, value)
                .map_err(|e| e.to_string())?;
        }

        self.commit(&mut resource, &format!("could not write {subject}"))
            .await?;

        Ok(())
    }

    async fn remove(&mut self, subject: &str, properties: Vec<String>) -> Result<(), String> {
        self.may_write(subject).await?;

        let mut resource = self
            .store
            .get_resource(&subject.into())
            .await
            .map_err(|e| format!("{subject} could not be read: {e}"))?;

        for property in properties {
            resource
                .remove_propval(&property)
                .map_err(|e| e.to_string())?;
        }

        self.commit(&mut resource, &format!("could not write {subject}"))
            .await?;

        Ok(())
    }

    async fn destroy(&mut self, subject: &str) -> Result<(), String> {
        self.may_write(subject).await?;

        let mut resource = self
            .store
            .get_resource(&subject.into())
            .await
            .map_err(|e| format!("{subject} could not be read: {e}"))?;

        match self.app_agent()? {
            Some(agent) => resource.destroy_as(&agent, &self.store).await,
            None => resource.destroy(&self.store).await,
        }
        .map_err(|e| format!("could not destroy {subject}: {e}"))?;

        Ok(())
    }
}

/// A JSON value from a verdict, as the datatype its property declares.
///
/// The planner already refused anything that does not fit, so a failure here
/// means the two disagree — which is exactly the drift the shared fixture
/// corpus exists to catch, and worth an error rather than a coercion.
fn json_to_value(value: Json, datatype: &DataType) -> Result<Value, String> {
    match (datatype, value) {
        (DataType::Json | DataType::LocalizedText, value) => Ok(Value::Json(value)),
        (DataType::Integer, Json::Number(n)) => n
            .as_i64()
            .map(Value::Integer)
            .ok_or_else(|| format!("{n} is not a whole number")),
        (DataType::Timestamp, Json::Number(n)) => n
            .as_i64()
            .map(Value::Timestamp)
            .ok_or_else(|| format!("{n} is not a timestamp")),
        (DataType::Float, Json::Number(n)) => n
            .as_f64()
            .map(Value::Float)
            .ok_or_else(|| format!("{n} is not a number")),
        (DataType::Boolean, Json::Bool(b)) => Ok(Value::Boolean(b)),
        (DataType::ResourceArray, Json::Array(items)) => Ok(Value::ResourceArray(
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(|subject| {
                            atomic_lib::values::SubResource::Subject(Subject::from_raw(
                                subject, None,
                            ))
                        })
                        .ok_or_else(|| format!("{item} is not a subject"))
                })
                .collect::<Result<Vec<_>, String>>()?,
        )),
        (datatype, Json::String(text)) => Value::new(&text, datatype).map_err(|e| e.to_string()),
        (datatype, value) => Err(format!("{value} is not a {datatype}")),
    }
}

/// Whether resources under this parent are identified by genesis certificate
/// rather than by path.
fn is_did(subject: &str) -> bool {
    subject.starts_with("did:")
}

/// Mark each approved import write, even when two previews have identical data.
fn stamp_import_approval(property: &str, mut value: Json) -> Json {
    if property == urls::IMPORT_BASELINE {
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "approval".into(),
                Json::String(atomic_lib::utils::random_string(32)),
            );
        }
    }
    value
}

#[cfg(test)]
mod installation_tests {
    use super::*;
    use atomic_lib::{agents::Agent, db::app_agent::AppAgent};

    #[actix_rt::test]
    async fn revoked_installation_never_falls_back_to_server_signing() {
        let mut fixture = crate::plugins::test_fixture::fixture("revoked_installation").await;
        crate::plugins::test_fixture::write_plugin(&mut fixture, "revocation test").await;
        let db = &fixture.appstate.store;
        let key = AppAgentKey::new(&fixture.drive, &fixture.plugin);
        let agent = Agent::new(None).unwrap();
        db.set_app_agent(
            &key,
            &AppAgent::new(agent.subject.to_string(), agent.build_secret().unwrap(), 0),
        )
        .unwrap();
        let selected = app_signing_for(db, &fixture.drive, &fixture.plugin)
            .await
            .unwrap();
        assert_eq!(selected, Some(key.clone()));
        let host = StoreApplyHost {
            store: db.clone(),
            for_agent: ForAgent::AgentSubject(agent.subject),
            signing_as: selected,
        };
        db.delete_app_agent(&key).unwrap();
        assert!(
            host.app_agent().is_err(),
            "an already-selected installation must fail closed after revocation"
        );
        assert!(
            app_signing_for(db, &fixture.drive, &fixture.plugin)
                .await
                .is_err(),
            "a future run must not treat revoked as legacy"
        );
    }
}

#[cfg(test)]
mod destroy_identity_tests {
    use super::*;
    use atomic_lib::{agents::Agent, db::app_agent::AppAgent, storelike::Query};

    #[actix_rt::test]
    async fn destroy_uses_the_selected_installation_signer() {
        let mut f = crate::plugins::test_fixture::fixture("destroy_signer").await;
        crate::plugins::test_fixture::write_plugin(&mut f, "unused").await;
        let db = &f.appstate.store;
        let app = Agent::new(None).unwrap();
        let key = AppAgentKey::new(&f.drive, &f.plugin);
        db.set_app_agent(
            &key,
            &AppAgent::new(app.subject.to_string(), app.build_secret().unwrap(), 0),
        )
        .unwrap();
        let owner = db.get_default_agent().unwrap().subject;
        let mut root = db.get_resource(&f.plugin.as_str().into()).await.unwrap();
        root.set_unsafe(
            urls::WRITE.into(),
            Value::ResourceArray(vec![app.subject.clone().into(), owner.clone().into()]),
        )
        .unwrap();
        root.save(db).await.unwrap();
        let mut host = StoreApplyHost::for_installation(
            db,
            &f.drive,
            &f.plugin,
            ForAgent::AgentSubject(owner),
        )
        .await
        .unwrap();
        let subject = host
            .create(CreateRequest {
                parent: f.plugin,
                is_a: vec![],
                prop_vals: HashMap::new(),
            })
            .await
            .unwrap();
        host.destroy(&subject).await.unwrap();
        let commits = db
            .query(&Query::new_prop_val(urls::SUBJECT, &subject))
            .await
            .unwrap();
        let destroy = commits
            .resources
            .iter()
            .find(|r| r.get(urls::DESTROY).is_ok_and(|v| v.to_string() == "true"))
            .expect("destroy commit");
        assert_eq!(
            destroy.get(urls::SIGNER).unwrap().to_string(),
            app.subject.to_string()
        );
    }
}
