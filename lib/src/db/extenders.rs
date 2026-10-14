//! Class extenders and endpoints for [`Db`].

use super::*;

impl Db {
    pub fn add_class_extender(&self, class_extender: ClassExtender) -> AtomicResult<()> {
        // At registration, not at match time: a class that can never match is a
        // property of the extender, so say it once on load rather than on every
        // commit that failed to match it.
        class_extender.warn_about_unmatchable_classes();

        let mut extenders = self
            .class_extenders
            .write()
            .map_err(|e| format!("Failed to write to class extenders: {}", e))?;

        if let Some(id) = &class_extender.id {
            extenders.retain(|e| e.id.as_ref() != Some(id));
        }

        extenders.push(class_extender);
        Ok(())
    }

    /// Runs one extender's `after_commit` for a commit that is already
    /// persisted. The caller logs an error and moves on to the next extender;
    /// see the AFTER APPLY COMMIT HANDLERS block in `apply_commit`.
    pub(super) async fn run_after_commit_extender(
        &self,
        extender: &ClassExtender,
        resource: &Resource,
        commit_response: &CommitResponse,
        root_subject: &mut Option<String>,
    ) -> AtomicResult<()> {
        let Some(handler) = extender.after_commit.as_ref() else {
            return Ok(());
        };
        if !extender.resource_has_extender(resource)? || !extender.can_extend(resource) {
            return Ok(());
        }

        let (is_in_scope, cached_root) = extender
            .check_scope(resource, self, root_subject.take())
            .await?;
        *root_subject = cached_root;
        if !is_in_scope {
            return Ok(());
        }

        (handler)(crate::class_extender::CommitExtenderContext {
            store: self,
            commit: &commit_response.commit,
            resource,
            is_new: commit_response.resource_old.is_none(),
            changed_props: &commit_response.changed_props,
        })
        .await
    }

    pub fn get_class_extenders_on_drive(&self, drive_subject: &str) -> Vec<ClassExtender> {
        let Ok(extenders) = self.class_extenders.read() else {
            return Vec::new();
        };

        extenders
            .iter()
            .filter(
                |e| matches!(&e.scope, ClassExtenderScope::Drive(scope) if scope == drive_subject),
            )
            .cloned()
            .collect()
    }

    /// Whether an extender of this id is registered right now.
    pub fn has_class_extender(&self, id: &str) -> bool {
        let Ok(extenders) = self.class_extenders.read() else {
            return false;
        };
        extenders.iter().any(|e| e.id.as_deref() == Some(id))
    }

    pub fn remove_class_extender(&self, id: &str) -> AtomicResult<()> {
        let mut extenders = self
            .class_extenders
            .write()
            .map_err(|e| format!("Failed to write to class extenders: {}", e))?;
        extenders.retain(|e| e.id.as_deref() != Some(id));
        Ok(())
    }

    pub fn add_endpoint(&mut self, endpoint: Endpoint) -> AtomicResult<()> {
        self.endpoints.push(endpoint);
        Ok(())
    }

    pub fn get_endpoints(&self) -> &Vec<Endpoint> {
        &self.endpoints
    }

    pub(super) fn is_endpoint(&self, url: &url::Url) -> bool {
        self.endpoints.iter().any(|e| e.path == url.path())
    }

    #[tracing::instrument(skip_all)]
    pub(super) async fn call_endpoint(
        &self,
        subject: &str,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        // For internal endpoint resolution, we use the store's base domain if set.
        let origin = self
            .get_base_domain()
            .unwrap_or_else(|| "http://localhost".to_string());
        let resolved = Subject::from(subject).resolve(&origin);
        let url = url::Url::parse(&resolved)?;

        // Check if the subject matches one of the endpoints
        for endpoint in self.endpoints.iter() {
            if url.path() == endpoint.path {
                // An endpoint whose required query keys are absent returns itself,
                // which clients render as a form to fill in. Handling it here (and
                // not in each handler) keeps handlers to the case they exist for:
                // the request that actually carries what they need.
                let missing_required = endpoint.form_when_missing.iter().any(|key| {
                    !url.query_pairs()
                        .any(|(k, v)| k == key.as_str() && !v.is_empty())
                });

                // Not all Endpoints have a handle function.
                // If there is none, return the endpoint plainly.
                let response = if missing_required {
                    endpoint.to_resource_response(self, subject).await?
                } else if let Some(handle) = endpoint.handle.as_ref() {
                    // Call the handle function for the endpoint, if it exists.
                    let context: HandleGetContext = HandleGetContext {
                        subject: url,
                        store: self,
                        for_agent,
                    };
                    (handle)(context).await.map_err(|mut e| {
                        e.message = format!(
                            "Error handling {} Endpoint: {}",
                            endpoint.shortname, e.message
                        );
                        e
                    })?
                } else {
                    endpoint.to_resource_response(self, subject).await?
                };

                // Extended resources must always return the requested subject as their own subject,
                // EXCEPT when the handler returned a resource with its own canonical subject
                // (e.g. the /did proxy endpoint returns DID resources that must keep their DID as @id).
                match response {
                    ResourceResponse::Resource(mut resource) => {
                        if !matches!(resource.get_subject(), Subject::Did { .. }) {
                            resource.set_subject(subject.into());
                        }
                        return Ok(resource.into());
                    }
                    ResourceResponse::ResourceWithReferenced(mut resource, references) => {
                        if !matches!(resource.get_subject(), Subject::Did { .. }) {
                            resource.set_subject(subject.into());
                        }
                        return Ok(ResourceResponse::ResourceWithReferenced(
                            resource, references,
                        ));
                    }
                    ResourceResponse::Redirect(target) => {
                        return Ok(ResourceResponse::Redirect(target));
                    }
                }
            }
        }

        Err(format!("No endpoint found for {}", subject).into())
    }
}
