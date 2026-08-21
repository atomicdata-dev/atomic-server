//! The store, as the planner and the applier see it.
//!
//! Planning and applying are deliberately written against narrow traits so
//! they can be tested against fixtures. This is the one implementation that
//! touches real data, and it is where the rights check lives.

use std::collections::HashMap;

use atomic_lib::{
    agents::ForAgent, datatype::DataType, hierarchy::check_write, urls, Db, Resource, Storelike,
    Subject, Value,
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
pub struct StoreApplyHost {
    pub store: Db,
    pub for_agent: ForAgent,
}

impl StoreApplyHost {
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

        let subject = self.create_subject(&request.parent);
        let mut resource = Resource::new(subject.clone());

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

        resource
            .save(&self.store)
            .await
            .map_err(|e| format!("could not create {subject}: {e}"))?;

        Ok(subject)
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

        resource
            .save(&self.store)
            .await
            .map_err(|e| format!("could not write {subject}: {e}"))?;

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

        resource
            .save(&self.store)
            .await
            .map_err(|e| format!("could not write {subject}: {e}"))?;

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
