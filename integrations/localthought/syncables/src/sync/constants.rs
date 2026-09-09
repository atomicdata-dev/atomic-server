//! Binding configured constants into a resource model's path templates —
//! what scopes a sync to one issue tracker (`owner`/`repo`) instead of
//! every tracker the credential can reach, per
//! [issue #6](https://github.com/localthought/syncables-rs/issues/6).
//!
//! A GitHub token can read every repository its owner can reach; narrowing
//! that down has to be part of the sync's configuration, not a filter
//! applied after the fact — fetching every tracker and discarding most of
//! it is both slow and a data-handling problem.

use std::collections::{BTreeMap, HashSet};

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use crate::error::{Error, Result};
use crate::openapi::types::OpenApiDocument;

use super::resource_model::{path_variables, ResourceModel};

/// Characters percent-encoded when a value is substituted into a URL path
/// segment — everything outside what's safe unescaped in a path segment,
/// mirroring the `url` crate's `PATH_SEGMENT_ENCODE_SET` (not pulled in as
/// a dependency for one constant).
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%');

/// Every parameter name declared by some operation in the document — path
/// or query, on any method — the set a constant is allowed to name.
fn declared_parameter_names(document: &OpenApiDocument) -> HashSet<&str> {
    document
        .paths
        .values()
        .flat_map(|item| {
            [
                item.get.as_ref(),
                item.put.as_ref(),
                item.post.as_ref(),
                item.patch.as_ref(),
                item.delete.as_ref(),
            ]
        })
        .flatten()
        .flat_map(|operation| operation.parameters.iter().flatten())
        .map(|parameter| parameter.name.as_str())
        .collect()
}

/// A path variable is resolvable if a constant supplies it, or a parent
/// record's context provider does.
fn is_resolvable(model: &ResourceModel, constants: &BTreeMap<String, String>, param: &str) -> bool {
    constants.contains_key(param) || model.provider_for(param).is_some()
}

/// Validates `constants` against `document` and `model`, before any request
/// is made:
///
/// - every constant must name a parameter the document actually declares
///   ([`Error::UnknownConstant`]) — a typo'd key would otherwise silently
///   sync nothing, or scope the sync far wider than intended;
/// - every path variable a managed collection needs — in its list URL, or
///   in its own item URL beyond what its identity binding already supplies
///   — must be resolvable by a constant or a parent record's provider
///   ([`Error::UnboundContextParam`]).
pub fn validate_constants(
    document: &OpenApiDocument,
    model: &ResourceModel,
    constants: &BTreeMap<String, String>,
) -> Result<()> {
    let declared = declared_parameter_names(document);
    for key in constants.keys() {
        if !declared.contains(key.as_str()) {
            return Err(Error::UnknownConstant(key.clone()));
        }
    }

    for collection in &model.collections {
        for param in &collection.context_params {
            if !is_resolvable(model, constants, param) {
                return Err(Error::UnboundContextParam(param.clone()));
            }
        }
        for param in path_variables(&collection.item_url) {
            if collection.identity_params.contains(&param) {
                continue;
            }
            if !is_resolvable(model, constants, &param) {
                return Err(Error::UnboundContextParam(param));
            }
        }
    }
    Ok(())
}

/// Substitutes every `{param}` in `template` with its percent-encoded value
/// from `values`.
///
/// Errors with [`Error::UnboundContextParam`] if `template` names a
/// variable `values` has no entry for — [`validate_constants`] is meant to
/// have already ruled this out for every template the resource model
/// declares, so this only fires on a template built outside that check.
pub fn bind_url(template: &str, values: &BTreeMap<String, String>) -> Result<String> {
    let mut bound = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        bound.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}') else {
            bound.push_str(&rest[start..]);
            return Ok(bound);
        };
        let name = &rest[start + 1..start + end];
        let value = values
            .get(name)
            .ok_or_else(|| Error::UnboundContextParam(name.to_string()))?;
        bound.push_str(&utf8_percent_encode(value, PATH_SEGMENT).to_string());
        rest = &rest[start + end + 1..];
    }
    bound.push_str(rest);
    Ok(bound)
}
