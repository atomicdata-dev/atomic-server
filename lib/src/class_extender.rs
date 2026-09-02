use std::sync::Arc;

use crate::{
    agents::ForAgent, errors::AtomicResult, storelike::ResourceResponse, urls, Commit, Db, Resource,
};

pub use crate::plugins::BoxFuture;

pub struct GetExtenderContext<'a> {
    pub store: &'a Db,
    pub url: &'a url::Url,
    pub db_resource: &'a mut Resource,
    pub for_agent: &'a ForAgent,
}

pub struct CommitExtenderContext<'a> {
    pub store: &'a Db,
    pub commit: &'a Commit,
    pub resource: &'a Resource,
    pub is_new: bool,
    /// The property URLs changed by this commit's Loro update.
    pub changed_props: &'a std::collections::HashSet<String>,
}

pub type ResourceGetHandler = Arc<
    dyn for<'a> Fn(GetExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<ResourceResponse>>
        + Send
        + Sync,
>;
pub type CommitHandler =
    Arc<dyn for<'a> Fn(CommitExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<()>> + Send + Sync>;

/// The form of a subject that two references to the *same* resource always
/// share.
///
/// Class matching is a string comparison, and a DID subject has more than one
/// spelling. `did:ad:abc` and `did:ad:abc?drive=did:ad:xyz` name one class, but
/// `Display` keeps the query string, so comparing raw strings silently answers
/// "different class" — and a plugin that declared the bare DID never runs, with
/// nothing logged to say why. `pure_id` drops the query and fragment, which is
/// exactly the difference that does not change identity.
///
/// Note what this deliberately does NOT accept: the address-bar form
/// (`http://host/did:ad:abc`). That is a server-specific URL for the resource,
/// not its identity, and treating it as equal here would mean a plugin's
/// declared class silently depended on which origin served it. It is a common
/// enough mistake to be worth naming, so it is warned about at load time
/// instead — see [`ClassExtender::warn_about_unmatchable_classes`].
fn normalize_class(raw: &str) -> String {
    crate::Subject::from_raw(raw.trim(), None).pure_id()
}

#[derive(Clone, Debug)]
pub enum ClassExtenderScope {
    Global,
    Drive(String),
}

#[derive(Clone)]
pub struct ClassExtender {
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub on_resource_get: Option<ResourceGetHandler>,
    pub before_commit: Option<CommitHandler>,
    pub after_commit: Option<CommitHandler>,
    pub scope: ClassExtenderScope,
    pub subject: Option<String>,
}

pub struct ClassExtenderBuilder {
    id: Option<String>,
    classes: Vec<String>,
    on_resource_get: Option<ResourceGetHandler>,
    before_commit: Option<CommitHandler>,
    after_commit: Option<CommitHandler>,
    scope: ClassExtenderScope,
    subject: Option<String>,
}

impl ClassExtenderBuilder {
    pub fn new() -> Self {
        Self {
            id: None,
            classes: Vec::new(),
            on_resource_get: None,
            before_commit: None,
            after_commit: None,
            scope: ClassExtenderScope::Global,
            subject: None,
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Classes are normalized here rather than at comparison time, so a plugin
    /// declaring `did:ad:abc?drive=…` and one declaring `did:ad:abc` are the
    /// same extender as far as everything downstream is concerned.
    pub fn classes(mut self, classes: Vec<String>) -> Self {
        self.classes = classes.iter().map(|c| normalize_class(c)).collect();
        self
    }

    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.classes.push(normalize_class(&class.into()));
        self
    }

    pub fn on_resource_get(mut self, handler: ResourceGetHandler) -> Self {
        self.on_resource_get = Some(handler);
        self
    }

    pub fn on_resource_get_fn<F>(mut self, handler: F) -> Self
    where
        F: for<'a> Fn(GetExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<ResourceResponse>>
            + Send
            + Sync
            + 'static,
    {
        self.on_resource_get = Some(ClassExtender::wrap_get_handler(handler));
        self
    }

    pub fn before_commit(mut self, handler: CommitHandler) -> Self {
        self.before_commit = Some(handler);
        self
    }

    pub fn before_commit_fn<F>(mut self, handler: F) -> Self
    where
        F: for<'a> Fn(CommitExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<()>>
            + Send
            + Sync
            + 'static,
    {
        self.before_commit = Some(ClassExtender::wrap_commit_handler(handler));
        self
    }

    pub fn after_commit(mut self, handler: CommitHandler) -> Self {
        self.after_commit = Some(handler);
        self
    }

    pub fn after_commit_fn<F>(mut self, handler: F) -> Self
    where
        F: for<'a> Fn(CommitExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<()>>
            + Send
            + Sync
            + 'static,
    {
        self.after_commit = Some(ClassExtender::wrap_commit_handler(handler));
        self
    }

    pub fn scope(mut self, scope: ClassExtenderScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn build(self) -> ClassExtender {
        ClassExtender {
            id: self.id,
            classes: self.classes,
            on_resource_get: self.on_resource_get,
            before_commit: self.before_commit,
            after_commit: self.after_commit,
            scope: self.scope,
            subject: self.subject,
        }
    }
}

impl Default for ClassExtenderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassExtender {
    pub fn builder() -> ClassExtenderBuilder {
        ClassExtenderBuilder::new()
    }

    pub fn resource_has_extender(&self, resource: &Resource) -> AtomicResult<bool> {
        let Ok(is_a) = resource.get(urls::IS_A) else {
            return Ok(false);
        };

        let resource_classes = is_a.to_subjects(None)?;
        let matched = resource_classes
            .iter()
            .any(|c| self.classes.contains(&normalize_class(c)));

        if !matched && !self.classes.is_empty() {
            // The single most common reason a plugin "does nothing": it loaded,
            // it registered, and its class never matched anything. Without this
            // that is indistinguishable from a hook that ran and chose not to
            // act.
            tracing::debug!(
                extender = self.id.as_deref().unwrap_or("<unnamed>"),
                declares = ?self.classes,
                resource_is_a = ?resource_classes,
                "class extender skipped: no class in common"
            );
        }

        Ok(matched)
    }

    /// Warn about declared classes that cannot ever match.
    ///
    /// A class is identified by its subject. The address-bar URL for a DID
    /// resource (`http://host/did:ad:abc`) is not that subject, so declaring it
    /// produces an extender that loads cleanly and never fires. Called once
    /// when an extender is registered, because "never fires" is otherwise only
    /// discoverable by reading this source.
    pub fn warn_about_unmatchable_classes(&self) {
        for class in &self.classes {
            if let Some((_origin, tail)) = class.split_once("/did:") {
                tracing::warn!(
                    extender = self.id.as_deref().unwrap_or("<unnamed>"),
                    declared = %class,
                    "class extender declares a class by URL, not by subject — it will never \
                     match. Use the bare DID instead: did:{}",
                    tail
                );
            }
        }
    }

    pub fn wrap_get_handler<F>(handler: F) -> ResourceGetHandler
    where
        F: for<'a> Fn(GetExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<ResourceResponse>>
            + Send
            + Sync
            + 'static,
    {
        Arc::new(handler)
    }

    pub fn wrap_commit_handler<F>(handler: F) -> CommitHandler
    where
        F: for<'a> Fn(CommitExtenderContext<'a>) -> BoxFuture<'a, AtomicResult<()>>
            + Send
            + Sync
            + 'static,
    {
        Arc::new(handler)
    }

    /// Checks if the resource is within the scope of the extender.
    /// To prevent unnecessary database lookups, the cached root can be supplied.
    /// Returns a tuple of (is_in_scope, cached_root).
    pub async fn check_scope(
        &self,
        resource: &Resource,
        store: &Db,
        cached_root: Option<String>,
    ) -> AtomicResult<(bool, Option<String>)> {
        match &self.scope {
            ClassExtenderScope::Drive(scope) => {
                // If the resource is the scope itself we can just return true.
                let subject = resource.get_subject().clone();
                if normalize_class(&subject.to_string()) == normalize_class(scope) {
                    return Ok((true, Some(subject.to_string())));
                }

                // Find the root parent of the resource or use the cached root.
                let rs = if let Some(rs) = &cached_root {
                    rs.clone()
                } else {
                    let parents = resource.get_parent_tree(store).await?;
                    let Some(root) = parents.last() else {
                        return Ok((false, None));
                    };

                    root.get_subject().to_string()
                };

                // Normalized for the same reason as the class match: the root
                // this resolves to and the drive the plugin was scoped to are
                // the same drive spelled two ways more often than not.
                if normalize_class(&rs) != normalize_class(scope) {
                    tracing::debug!(
                        extender = self.id.as_deref().unwrap_or("<unnamed>"),
                        scoped_to = %scope,
                        resource_root = %rs,
                        "class extender skipped: resource is in a different drive"
                    );
                    return Ok((false, Some(rs)));
                }

                Ok((true, Some(rs)))
            }
            ClassExtenderScope::Global => Ok((true, cached_root)),
        }
    }

    /// Checks if the given resource is the plugin itself.
    /// This can be used to prevent the plugin from extending itself as this could enable malicious behavior.
    pub fn can_extend(&self, resource: &Resource) -> bool {
        if self.subject.is_none() {
            // The extender is not a plugin so it can extend any resource
            return true;
        };

        let Ok(is_a) = resource.get(urls::IS_A) else {
            return true;
        };

        let Ok(is_a_subjects) = is_a.to_subjects(None) else {
            return true;
        };

        // Check if the resource is a plugin, if so return false.
        !is_a_subjects.contains(&urls::PLUGIN.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    const CLASS: &str = "did:ad:guDVPzQKpsfcS5Vpbgdh0cj19CFapvKuQ5NVyYfjcspo0ZMpua9UzgC8WkDZa1_Z";

    fn extender_declaring(class: &str) -> ClassExtender {
        ClassExtender::builder()
            .id("test".to_string())
            .classes(vec![class.to_string()])
            .build()
    }

    fn resource_of_class(raw_is_a: &str) -> Resource {
        let mut resource = Resource::new("did:ad:someresource".to_string());
        resource
            .set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![crate::Subject::from_raw(raw_is_a, None).into()]),
            )
            .unwrap();
        resource
    }

    #[test]
    fn a_bare_did_matches_itself() {
        assert!(extender_declaring(CLASS)
            .resource_has_extender(&resource_of_class(CLASS))
            .unwrap());
    }

    #[test]
    fn a_drive_hint_does_not_change_which_class_this_is() {
        // The resource carries the hint, the plugin declared the bare DID.
        // Comparing `Display` output made these different strings, so the hook
        // never ran and nothing said why.
        let hinted = format!("{CLASS}?drive=did:ad:somedrive");

        assert!(extender_declaring(CLASS)
            .resource_has_extender(&resource_of_class(&hinted))
            .unwrap());

        // And the other way round, since either side may carry it.
        assert!(extender_declaring(&hinted)
            .resource_has_extender(&resource_of_class(CLASS))
            .unwrap());
    }

    #[test]
    fn surrounding_whitespace_is_not_a_different_class() {
        assert!(extender_declaring(&format!("  {CLASS}  "))
            .resource_has_extender(&resource_of_class(CLASS))
            .unwrap());
    }

    #[test]
    fn an_address_bar_url_is_still_not_the_class() {
        // Deliberate: that URL is how one server serves the resource, not what
        // the resource is. Accepting it would make a plugin's declared class
        // depend on the origin it was written against. `add_class_extender`
        // warns about this shape instead.
        assert!(!extender_declaring(CLASS)
            .resource_has_extender(&resource_of_class(&format!(
                "http://localhost:24797/{CLASS}"
            )))
            .unwrap());
    }

    #[test]
    fn a_different_class_still_does_not_match() {
        assert!(!extender_declaring(CLASS)
            .resource_has_extender(&resource_of_class("did:ad:someotherclassentirely"))
            .unwrap());
    }

    #[test]
    fn a_resource_without_is_a_matches_nothing() {
        let bare = Resource::new("did:ad:someresource".to_string());
        assert!(!extender_declaring(CLASS)
            .resource_has_extender(&bare)
            .unwrap());
    }

    /// An extender shapes the response with `set`, which also records a Loro
    /// op on the doc the response is serialized from. That op is never
    /// persisted, so a client seeding its doc from the response would build
    /// every later delta on an op this store does not have, and
    /// `apply_commit` would park it as pending. The served `loroUpdate` must
    /// therefore be the persisted snapshot — with the dynamic propval still
    /// in the JSON-AD.
    #[tokio::test]
    async fn extended_get_serves_the_persisted_snapshot() {
        use crate::{agents::ForAgent, storelike::ResourceResponse, Storelike};
        use base64::Engine;

        let store = crate::test_utils::init_store().await;
        let dynamic_prop = urls::NAME;

        let mut resource = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        resource
            .set(
                urls::SHORTNAME.into(),
                Value::Slug("extended".into()),
                &store,
            )
            .await
            .unwrap();
        resource
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown("stored".into()),
                &store,
            )
            .await
            .unwrap();
        resource.save_locally(&store).await.unwrap();
        let subject = resource.get_subject().clone();

        store
            .add_class_extender(
                ClassExtender::builder()
                    .id("leaky")
                    .classes(vec![urls::CLASS.to_string()])
                    .on_resource_get_fn(move |context| {
                        Box::pin(async move {
                            context
                                .db_resource
                                .set(
                                    dynamic_prop.into(),
                                    Value::String("computed on read".into()),
                                    context.store,
                                )
                                .await?;
                            Ok(ResourceResponse::Resource(context.db_resource.to_owned()))
                        })
                    })
                    .build(),
            )
            .unwrap();

        let served = store
            .get_resource_extended(&subject, false, &ForAgent::Sudo)
            .await
            .unwrap()
            .to_single();
        let json: serde_json::Value =
            serde_json::from_str(&served.to_json_ad(None).unwrap()).unwrap();
        assert_eq!(
            json[dynamic_prop], "computed on read",
            "the dynamic propval must still reach the client"
        );

        let served_snapshot = base64::engine::general_purpose::STANDARD
            .decode(json[urls::LORO_UPDATE].as_str().unwrap())
            .unwrap();
        let persisted = store
            .get_resource(&subject)
            .await
            .unwrap()
            .build_state_doc()
            .unwrap();
        let persisted_vv = persisted.oplog_vv_map();
        persisted.import_update(&served_snapshot).unwrap();
        assert_eq!(
            persisted_vv,
            persisted.oplog_vv_map(),
            "the served loroUpdate carried Loro ops the store has not persisted"
        );
    }
}
