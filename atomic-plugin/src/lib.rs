#[doc(hidden)]
pub mod bindings;

use std::collections::{HashMap, HashSet};

#[doc(hidden)]
pub use bindings::*;

// Types re-exports
pub use bindings::atomic::class_extender::host;
pub use bindings::atomic::class_extender::types::{
    CommitContext, GetContext, HttpHeader, HttpRequest, HttpResponse, ResourceJson,
    ResourceResponse,
};

pub use bindings::Guest;

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

/// High-level trait for implementing a Class Extender plugin.
pub trait ClassExtender {
    fn class_url() -> Vec<String>;

    /// Called when a resource is fetched from the server. You can modify the resource in place.
    fn on_resource_get(resource: &mut Resource) -> Result<Option<&Resource>, String> {
        Ok(Some(resource))
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

impl<T: ClassExtender> Guest for PluginWrapper<T> {
    fn class_url() -> Vec<String> {
        T::class_url()
    }

    fn on_resource_get(ctx: GetContext) -> Result<Option<ResourceResponse>, String> {
        let mut resource = Resource::try_from(ctx.snapshot)?;

        let Some(result) = T::on_resource_get(&mut resource)? else {
            return Ok(None);
        };

        let updated_payload = result.to_json()?;

        Ok(Some(ResourceResponse {
            primary: ResourceJson {
                subject: resource.subject,
                json_ad: updated_payload,
            },
            referenced: Vec::new(),
        }))
    }

    fn before_commit(ctx: CommitContext) -> Result<(), String> {
        let commit: Commit = serde_json::from_str(&ctx.commit_json).map_err(|e| e.to_string())?;
        let snapshot: Resource = Resource::try_from(ctx.snapshot)?;

        T::before_commit(&commit, &snapshot, ctx.is_new)
    }

    fn after_commit(ctx: CommitContext) -> Result<(), String> {
        let commit: Commit = serde_json::from_str(&ctx.commit_json).map_err(|e| e.to_string())?;
        let snapshot: Resource = Resource::try_from(ctx.snapshot)?;

        T::after_commit(&commit, &snapshot, ctx.is_new)
    }
}

#[macro_export]
macro_rules! export_plugin {
    ($plugin_type:ty) => {
        struct Shim;
        impl $crate::Guest for Shim {
            fn class_url() -> Vec<String> {
                <$crate::PluginWrapper<$plugin_type> as $crate::Guest>::class_url()
            }
            fn on_resource_get(ctx: $crate::GetContext) -> Result<Option<$crate::ResourceResponse>, String> {
                <$crate::PluginWrapper<$plugin_type> as $crate::Guest>::on_resource_get(ctx)
            }
            fn before_commit(ctx: $crate::CommitContext) -> Result<(), String> {
                <$crate::PluginWrapper<$plugin_type> as $crate::Guest>::before_commit(ctx)
            }
            fn after_commit(ctx: $crate::CommitContext) -> Result<(), String> {
                <$crate::PluginWrapper<$plugin_type> as $crate::Guest>::after_commit(ctx)
            }
        }

       $crate::__export_world_class_extender_cabi!(Shim with_types_in $crate::bindings);
    };
}

/// Gets a resource from the store by subject, the plugin's agent is used to authorize the request.
pub fn get_resource(subject: String) -> Result<Resource, String> {
    host::get_resource(&subject, None)
        .map(|json| Resource::try_from(json).map_err(|e| e.to_string()))?
}

/// Queries the store for resources that match the given property and value, the plugin's agent is used to authorize the request.
pub fn query(property: String, value: String) -> Result<Vec<Resource>, String> {
    host::query(&property, &value, None).map(|json| {
        json.into_iter()
            .map(|json| Resource::try_from(json).map_err(|e| e.to_string()))
            .collect::<Result<Vec<Resource>, String>>()
    })?
}

/// Gets the config of the plugin deserialized to the given type.
/// The user can edit this config at any time.
pub fn get_config<'a, T>() -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let config_str = host::get_config();
    serde_json::from_str::<T>(&config_str)
        .map_err(|e| format!("Failed to deserialize config: {}", e))
}

/// Creates a commit and signs it using the plugin's agent.
pub fn commit(commit: &CommitBuilder) -> Result<(), String> {
    let commit_str =
        serde_json::to_string(commit).map_err(|e| format!("Failed to serialize commit: {}", e))?;
    host::commit(&commit_str).map_err(|e| format!("Failed to commit: {}", e))
}

/// Makes an HTTP request through the host.
///
/// A plugin has no sockets of its own; this is the only way out, and the host
/// decides whether it opens. The manifest must declare the origin, and the URL
/// must resolve to somewhere on the public internet.
///
/// # Credentials
///
/// Put `secret:<name>` in a **header value** and the host substitutes the
/// secret before sending. The plugin never sees it — printing the header shows
/// `secret:notion`, not the token.
///
/// ```no_run
/// # use atomic_plugin::{fetch, HttpHeader, HttpRequest};
/// let response = fetch(HttpRequest {
///     method: "GET".to_string(),
///     url: "https://api.notion.com/v1/users/me".to_string(),
///     headers: vec![HttpHeader {
///         name: "Authorization".to_string(),
///         value: "Bearer secret:notion".to_string(),
///     }],
///     body: None,
/// })?;
/// # Ok::<(), String>(())
/// ```
///
/// A handle in the URL or the body is an error, not a substitution: a
/// credential in a URL is written to access logs as a matter of course.
/// Redirects are not followed, so a 3xx comes back for the plugin to handle.
pub fn fetch(request: HttpRequest) -> Result<HttpResponse, String> {
    host::fetch(&request)
}

impl TryFrom<ResourceJson> for Resource {
    type Error = String;

    fn try_from(resource_json: ResourceJson) -> Result<Self, Self::Error> {
        let json_value: JsonValue = serde_json::from_str(&resource_json.json_ad)
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        let Some(obj) = json_value.as_object() else {
            return Err("Resource is not a JSON object".into());
        };

        let mut props = obj.clone();
        props.remove("@id");

        Ok(Self {
            subject: resource_json.subject,
            props,
        })
    }
}

impl Resource {
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
