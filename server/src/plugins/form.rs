/*!
# Form
Class extender that adds an ephemeral, server-computed submission summary
(`form-submission-summary`) to Form resources when they are fetched over HTTP.
The data-browser's Summary tab forces a server fetch to read it; it is never
persisted and never part of the Form's Loro state.
*/

use atomic_lib::{
    class_extender::{BoxFuture, ClassExtender, GetExtenderContext},
    errors::AtomicResult,
    storelike::ResourceResponse,
    urls, Value,
};

use crate::forms;

/// Runs after the GET path's read-rights check, and the inner row query runs
/// as the same agent, so no extra authorization is needed here. Aggregation
/// errors serve the Form without the summary — a broken target table must not
/// make the Form itself unfetchable.
pub fn construct_form<'a>(
    context: GetExtenderContext<'a>,
) -> BoxFuture<'a, AtomicResult<ResourceResponse>> {
    Box::pin(async move {
        let GetExtenderContext {
            store,
            db_resource: resource,
            for_agent,
            ..
        } = context;

        match forms::build_form_summary(store, resource, for_agent).await {
            Ok(summary) => {
                resource
                    .set(
                        urls::FORM_SUBMISSION_SUMMARY.into(),
                        Value::Json(summary),
                        store,
                    )
                    .await?;
            }
            Err(e) => {
                tracing::warn!(
                    subject = %resource.get_subject(),
                    "Failed to build form submission summary: {e}"
                );
            }
        }

        Ok(ResourceResponse::Resource(resource.to_owned()))
    })
}

pub fn build_form_extender() -> ClassExtender {
    ClassExtender::builder()
        .id("form")
        .classes(vec![urls::FORM.to_string()])
        .on_resource_get(ClassExtender::wrap_get_handler(construct_form))
        .build()
}
