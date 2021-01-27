use std::sync::MutexGuard;

use atomic_lib::errors::AtomicResult;
use tera::Context as TeraCtx;

use crate::{appstate::AppState, render::propvals::propvals_to_html_vec};

/// Renders the HTML view for a given resource.
/// If there's a (set of) Classes for the Resource, check if they have a custom View.
/// If not, fall back to the default View
pub fn render_resource(
  resource: &atomic_lib::Resource,
  context: &MutexGuard<AppState>,
) -> AtomicResult<String> {
  // If the Resource has an `is-a` attribute...
  if let Ok(classes_val) = resource.get(atomic_lib::urls::IS_A) {
      // And it can be vectorized...
      if let Ok(classes_vec) = classes_val.to_vec() {
          for class in classes_vec {
              // Check if there's a custom renderer available
              match class.as_ref() {
                  atomic_lib::urls::COLLECTION => {
                      return Ok(crate::views::collection::render_collection(
                          &resource, &context,
                      )?)
                  }
                  atomic_lib::urls::CLASS => {
                      return Ok(crate::views::class::render_class(
                          &resource, &context,
                      )?)
                  }
                  _ => {}
              }
          }
      }
  }
  default_view(resource, context)
}

/// The default view for resources
fn default_view(
  resource: &atomic_lib::Resource,
  context: &MutexGuard<AppState>,
) -> AtomicResult<String> {
  let mut tera_context = TeraCtx::new();
  // If not, fall back to the default renderer
  let propvals = propvals_to_html_vec(
      &resource.get_propvals(),
      &context.store,
      resource.get_subject().clone(),
  )?;
  tera_context.insert("resource", &propvals);
  Ok(context.tera.render("resource.html", &tera_context)?)
}
