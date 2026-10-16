//! Helper library for server modules (class extenders) on the Atomic host ABI,
//! world `server-module` (`atomic-host/wit/host.wit`).

#[doc(hidden)]
pub mod bindings {
    wit_bindgen::generate!({
        path: "../atomic-host/wit",
        world: "server-module",
        pub_export_macro: true,
        default_bindings_module: "atomic_plugin::bindings",
    });
}

use std::collections::{HashMap, HashSet};

pub use bindings::atomic::host::{calls, net};
use bindings::atomic::host::{
    context,
    store::{self, Intent, Outcome},
    types::{Problem, PropVal, Severity, Value},
};
pub use bindings::exports::atomic::host::hooks::{CommitInfo, Guest};

const IS_A: &str = "https://atomicdata.dev/properties/isA";

#[cfg(not(target_arch = "wasm32"))]
pub mod packaging;

// Re-export contents of packaging module directly if it exists
#[cfg(not(target_arch = "wasm32"))]
pub use packaging::packaging_impl;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub struct Resource {
    pub subject: String,
    pub props: serde_json::Map<String, JsonValue>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    #[serde(rename = "https://atomicdata.dev/properties/subject")]
    pub subject: String,
    /// The date it was created, as a unix timestamp
    #[serde(rename = "https://atomicdata.dev/properties/createdAt")]
    pub created_at: i64,
    /// The URL of the one signing this Commit
    #[serde(rename = "https://atomicdata.dev/properties/signer")]
    pub signer: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    #[serde(rename = "https://atomicdata.dev/properties/set")]
    pub set: Option<std::collections::HashMap<String, JsonValue>>,
    #[serde(rename = "https://atomicdata.dev/properties/remove")]
    /// The set of property URLs that need to be removed
    pub remove: Option<Vec<String>>,
    /// If set to true, deletes the entire resource
    #[serde(rename = "https://atomicdata.dev/properties/destroy")]
    pub destroy: Option<bool>,
    /// Base64 encoded signature of the JSON serialized Commit
    #[serde(rename = "https://atomicdata.dev/properties/signature")]
    pub signature: Option<String>,
    /// List of Properties and Arrays to be appended to them
    #[serde(rename = "https://atomicdata.dev/properties/push")]
    pub push: Option<std::collections::HashMap<String, JsonValue>>,
    /// The previously applied commit to this Resource.
    #[serde(rename = "https://atomicdata.dev/properties/previousCommit")]
    pub previous_commit: Option<String>,
    /// The URL of the Commit
    pub url: Option<String>,
}

/// Use this for creating Commits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta.
    /// Not the URL of the Commit itself.
    /// https://atomicdata.dev/properties/subject
    pub subject: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    /// https://atomicdata.dev/properties/set
    set: std::collections::HashMap<String, JsonValue>,
    /// The set of PropVals that need to be appended to resource arrays.
    push: std::collections::HashMap<String, Vec<String>>,
    /// The set of property URLs that need to be removed
    /// https://atomicdata.dev/properties/remove
    remove: HashSet<String>,
    /// If set to true, deletes the entire resource
    /// https://atomicdata.dev/properties/destroy
    destroy: bool,
    previous_commit: Option<String>,
}

impl CommitBuilder {
    pub fn new(subject: String) -> Self {
        Self {
            subject,
            set: HashMap::new(),
            push: HashMap::new(),
            remove: HashSet::new(),
            destroy: false,
            previous_commit: None,
        }
    }

    /// Set Property / Value combinations that will either be created or overwritten.
    pub fn set(&mut self, prop: String, val: JsonValue) -> &Self {
        self.set.insert(prop, val);

        self
    }

    /// Set Property URLs which values to be removed
    pub fn remove(&mut self, prop: String) -> &Self {
        self.remove.insert(prop);

        self
    }

    /// Whether the resource needs to be removed fully
    pub fn destroy(&mut self, destroy: bool) {
        self.destroy = destroy;
    }

    /// Appends a Resource subject to a ResourceArray.
    pub fn push(&mut self, property: &str, value: String) -> &Self {
        let Some(vec) = self.push.get_mut(property) else {
            self.push.insert(property.to_string(), vec![value]);
            return self;
        };

        vec.push(value.clone());
        self
    }
}

/// High-level trait for implementing a server module that extends classes.
pub trait ClassExtender {
    /// The classes this module extends.
    fn class_url() -> Vec<String>;

    /// Called when a resource of the class is read. Change it in place and
    /// return it, or return `None` to leave it as it is. The default leaves it.
    /// An error fails the read.
    fn on_resource_get(_resource: &mut Resource) -> Result<Option<&Resource>, String> {
        Ok(None)
    }

    /// Called before a Commit that targets the class is persisted. If you return an error, the commit will be rejected.
    fn before_commit(_commit: &Commit, _snapshot: &Resource, _is_new: bool) -> Result<(), String> {
        Ok(())
    }

    /// Called after a Commit that targets the class has been applied. Returning an error will not cancel the commit.
    fn after_commit(_commit: &Commit, _resource: &Resource, _is_new: bool) -> Result<(), String> {
        Ok(())
    }
}

#[doc(hidden)]
pub struct PluginWrapper<T>(std::marker::PhantomData<T>);

fn commit_of(info: &CommitInfo) -> Result<Commit, String> {
    serde_json::from_str(&info.commit_json).map_err(|e| e.to_string())
}

fn error(message: String) -> bindings::atomic::host::types::Error {
    bindings::atomic::host::types::Error {
        code: "internal".into(),
        message,
    }
}

impl<T: ClassExtender> Guest for PluginWrapper<T> {
    fn classes() -> Vec<String> {
        T::class_url()
    }

    fn before_commit(
        info: CommitInfo,
        after: bindings::atomic::host::types::Resource,
    ) -> Vec<Problem> {
        let verdict = commit_of(&info)
            .and_then(|commit| T::before_commit(&commit, &after.into(), info.is_new));
        match verdict {
            Ok(()) => Vec::new(),
            Err(message) => vec![Problem {
                severity: Severity::Error,
                message,
                subject: Some(info.subject),
                property: None,
            }],
        }
    }

    fn after_commit(
        info: CommitInfo,
        after: bindings::atomic::host::types::Resource,
    ) -> Result<(), bindings::atomic::host::types::Error> {
        commit_of(&info)
            .and_then(|commit| T::after_commit(&commit, &after.into(), info.is_new))
            .map_err(error)
    }

    fn on_get(
        resource: bindings::atomic::host::types::Resource,
        _agent: String,
    ) -> Result<Option<bindings::atomic::host::types::Resource>, bindings::atomic::host::types::Error>
    {
        let mut resource: Resource = resource.into();
        let answer = T::on_resource_get(&mut resource).map_err(error)?;
        Ok(answer.map(Resource::to_wit))
    }
}

#[macro_export]
macro_rules! export_plugin {
    ($plugin_type:ty) => {
        type Plugin = $crate::PluginWrapper<$plugin_type>;
        $crate::bindings::export!(Plugin with_types_in $crate::bindings);
    };
}

fn failure(error: bindings::atomic::host::types::Error) -> String {
    format!("{}: {}", error.code, error.message)
}

/// Gets a resource from the store by subject, as the module's agent: it sees
/// what that agent may read and nothing else.
pub fn get_resource(subject: String) -> Result<Resource, String> {
    store::get(&subject).map(Resource::from).map_err(failure)
}

/// Queries the store for resources whose `property` equals `value` (a page of
/// at most 100), as the module's agent.
pub fn query(property: String, value: String) -> Result<Vec<Resource>, String> {
    let page = store::query(&store::QuerySpec {
        class: None,
        parent: None,
        filters: vec![store::Filter {
            property,
            op: store::FilterOp::Eq,
            value: Some(Value::String(value)),
        }],
        sort_by: None,
        sort_desc: false,
        limit: None,
        cursor: None,
        with_resources: true,
    })
    .map_err(failure)?;
    Ok(page.resources.into_iter().map(Resource::from).collect())
}

/// Gets the config of the plugin deserialized to the given type.
/// The user can edit this config at any time.
pub fn get_config<'a, T>() -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str::<T>(&context::get().config)
        .map_err(|e| format!("Failed to deserialize config: {}", e))
}

/// The subject of the agent the module acts as, if it has one.
pub fn get_plugin_agent() -> Option<String> {
    context::get().agent
}

/// Writes what the builder describes as one transaction, signed by the
/// module's agent. An error if it was not written (the agent may not write
/// there, or the change is invalid).
pub fn commit(commit: &CommitBuilder) -> Result<(), String> {
    let subject = commit.subject.clone();
    let mut intents = Vec::new();
    if commit.destroy {
        intents.push(Intent::Destroy(subject));
    } else {
        let mut set: Vec<PropVal> = commit
            .set
            .iter()
            .map(|(property, value)| PropVal {
                property: property.clone(),
                value: json_to_value(value),
            })
            .collect();
        if !commit.push.is_empty() {
            let current = store::get(&subject).map_err(failure)?;
            for (property, items) in &commit.push {
                let mut all = match current.propvals.iter().find(|pv| &pv.property == property) {
                    Some(PropVal {
                        value: Value::ResourceArray(existing),
                        ..
                    }) => existing.clone(),
                    _ => Vec::new(),
                };
                all.extend(items.iter().cloned());
                set.push(PropVal {
                    property: property.clone(),
                    value: Value::ResourceArray(all),
                });
            }
        }
        if !set.is_empty() {
            intents.push(Intent::Set((subject.clone(), set)));
        }
        if !commit.remove.is_empty() {
            intents.push(Intent::Remove((
                subject,
                commit.remove.iter().cloned().collect(),
            )));
        }
    }
    if intents.is_empty() {
        return Ok(());
    }

    let applied = store::apply(&intents).map_err(failure)?;
    match applied.outcome {
        Outcome::Committed => Ok(()),
        outcome => Err(format!(
            "Failed to commit ({outcome:?}): {}",
            applied
                .problems
                .iter()
                .map(|p| p.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )),
    }
}

/// Makes an HTTP request through the host.
///
/// A module has no sockets of its own; this is the only way out. A request
/// names an operation the manifest declares (`operations`): the host knows its
/// origin and method, the module supplies the path, query, headers and body,
/// and the host checks that the address is on the public internet.
///
/// # Credentials
///
/// Put `secret:<name>` in a **header value** and the host substitutes the
/// secret before sending. The module never sees it. A handle anywhere else is
/// an error, not a substitution. Redirects are not followed.
pub fn fetch(request: net::Request) -> Result<net::Response, String> {
    net::fetch(&request).map_err(failure)
}

fn json_to_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(b) => Value::Boolean(*b),
        JsonValue::Number(n) => match n.as_i64() {
            Some(i) => Value::Integer(i),
            None => Value::Float(n.as_f64().unwrap_or_default()),
        },
        JsonValue::String(s) => Value::String(s.clone()),
        other => Value::Json(other.to_string()),
    }
}

fn value_to_json(value: Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Boolean(b) => JsonValue::Bool(b),
        Value::Integer(i) => i.into(),
        Value::Float(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, Into::into),
        Value::String(s) | Value::Link(s) => JsonValue::String(s),
        Value::ResourceArray(items) => items.into(),
        Value::Json(text) => serde_json::from_str(&text).unwrap_or(JsonValue::String(text)),
    }
}

impl From<bindings::atomic::host::types::Resource> for Resource {
    fn from(resource: bindings::atomic::host::types::Resource) -> Self {
        Self {
            subject: resource.subject,
            props: resource
                .propvals
                .into_iter()
                .map(|pv| (pv.property, value_to_json(pv.value)))
                .collect(),
        }
    }
}

impl Resource {
    fn to_wit(&self) -> bindings::atomic::host::types::Resource {
        bindings::atomic::host::types::Resource {
            subject: self.subject.clone(),
            classes: Vec::new(),
            propvals: self
                .props
                .iter()
                .map(|(property, value)| PropVal {
                    property: property.clone(),
                    value: json_to_value(value),
                })
                .collect(),
        }
    }

    pub fn to_json(&self) -> Result<String, String> {
        let mut props = self.props.clone();
        props.insert("@id".to_string(), JsonValue::String(self.subject.clone()));
        serde_json::to_string(&props).map_err(|e| format!("Serialize error: {e}"))
    }

    pub fn is_a(&self, class: &str) -> bool {
        let Some(is_a) = self.props.get(IS_A) else {
            return false;
        };

        let Some(is_a_subjects) = is_a.as_array() else {
            return false;
        };

        is_a_subjects
            .iter()
            .any(|subject| subject.as_str() == Some(class))
    }
}
