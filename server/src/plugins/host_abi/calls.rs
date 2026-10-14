//! `atomic:host/calls`: apps calling apps, through the host.
//!
//! An app never reaches another app. It names an interface and a function, and
//! the host finds the provider installed in the same drive, checks the
//! arguments against the provider's declared schema, runs the provider in its
//! own instance under its own Installation's rights, checks the result against
//! its schema, and returns it.

use super::{
    bindings::atomic::host::calls::{self, AppExport, Effect, Handle},
    code, error,
    registry::HostAbiRegistry,
    run::{call_export, AbiState},
    HostError,
};
use crate::plugins::manifest::{Export, ExportEffect};

fn to_wit(export: &Export) -> AppExport {
    AppExport {
        interface: export.interface.clone(),
        function: export.function.clone(),
        description: export.description.clone(),
        input_schema: serde_json::to_string(&export.input_schema).unwrap_or_default(),
        output_schema: serde_json::to_string(&export.output_schema).unwrap_or_default(),
        effect: match export.effect {
            ExportEffect::Read => Effect::Read,
            ExportEffect::Write => Effect::Write,
            ExportEffect::External => Effect::External,
            ExportEffect::Interactive => Effect::Interactive,
        },
    }
}

/// What the preferred provider of `interface` offers.
pub fn describe(
    registry: &HostAbiRegistry,
    drive: &str,
    interface: &str,
) -> Result<Vec<AppExport>, HostError> {
    let provider = registry
        .providers(drive, interface)
        .into_iter()
        .next()
        .ok_or_else(|| {
            error(
                code::NOT_FOUND,
                format!("no installed app in this drive provides {interface}"),
            )
        })?;
    Ok(provider
        .manifest
        .exports_of(interface)
        .map(to_wit)
        .collect())
}

impl calls::Host for AbiState {
    async fn providers(&mut self, interface: String) -> Vec<String> {
        self.host
            .registry
            .providers(&self.host.app.drive, &interface)
            .into_iter()
            .map(|app| app.installation.clone())
            .collect()
    }

    async fn describe(&mut self, interface: String) -> Result<Vec<AppExport>, HostError> {
        describe(&self.host.registry, &self.host.app.drive, &interface)
    }

    async fn call(
        &mut self,
        interface: String,
        function: String,
        args: String,
        handles: Vec<Handle>,
    ) -> Result<String, HostError> {
        // TODO(host-abi step 2): handles are scoped capabilities the callee may
        // use for this call only. Until grants have scopes there is nothing to
        // intersect them with, so they are accepted and ignored: the callee
        // runs with its own Installation's rights and nothing of the caller's.
        if !handles.is_empty() {
            tracing::debug!(
                count = handles.len(),
                "host ABI: ignoring handles passed to calls.call"
            );
        }
        call_export(
            &self.host.registry,
            &self.host.db,
            &self.host.app.drive,
            &interface,
            &function,
            &args,
            None,
            self.host.depth + 1,
        )
        .await
    }
}
