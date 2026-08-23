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

/// Reads for the planner, writes for the applier.
///
/// `for_agent` is whoever the run is acting for. The commit itself is signed
/// by the server's own agent — it is the only key the server holds — so
/// without this check a plugin would be a way to write anywhere on the server
/// regardless of who set it up.
/// The app a plugin belongs to, if that app has a key.
///
/// A plugin's parent is its app — an entry point and a handler both sit under
/// one. Bounded rather than exhaustive, like every other parent walk here: a
/// cycle would otherwise hang a scheduled run, and nothing legitimate nests an
/// app's own plugins deeper than this.
pub async fn app_signing_for(db: &Db, drive: &str, plugin: &str) -> Option<AppAgentKey> {
    let mut subject = plugin.to_string();

    for _ in 0..3 {
        let key = AppAgentKey::new(drive, &subject);

        if db.get_app_agent_info(&key).ok().flatten().is_some() {
            return Some(key);
        }

        let resource = db.get_resource(&subject.as_str().into()).await.ok()?;
        subject = resource.get(urls::PARENT).ok()?.to_string();
    }

    None
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
    /// Writes, signed by the app when it has a key of its own.
    ///
    /// Falling back to the store's default agent is what every write did
    /// before app keys existed; an app created since always has one, so the
    /// fallback covers only apps that predate this.
    /// The app's signing agent, when this host is acting for one.
    fn app_agent(&self) -> Result<Option<atomic_lib::agents::Agent>, String> {
        let Some(key) = &self.signing_as else {
            return Ok(None);
        };

        self.store
            .with_app_agent(key, |agent| agent.clone())
            .map_err(|e| format!("could not read {}'s key: {e}", key.app))
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
            .map(|_| ())
            .map_err(|e| format!("not allowed to write to {subject}: {e}"))
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
        let property = self.store.get_property(subject).await.ok()?;

        Some((property.data_type.to_string(), property.shortname))
    }

    async fn read_resource(&mut self, subject: &str) -> Option<HashMap<String, Json>> {
        // A subject that could not be fetched is indistinguishable from one
        // that was never created, and both mean the same thing for planning:
        // there is nothing here to change.
        let resource = self.store.get_resource(&subject.into()).await.ok()?;

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
            let value = self.value_for(&property, value).await?;

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
            let value = self.value_for(&property, value).await?;

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

        resource
            .destroy(&self.store)
            .await
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
