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
            .providers(&self.host.drive, &interface)
            .into_iter()
            .map(|app| app.installation.clone())
            .collect()
    }

    async fn describe(&mut self, interface: String) -> Result<Vec<AppExport>, HostError> {
        describe(&self.host.registry, &self.host.drive, &interface)
    }

    async fn call(
        &mut self,
        interface: String,
        function: String,
        args: String,
        handles: Vec<Handle>,
    ) -> Result<String, HostError> {
        // TODO(host-abi): handles are scoped capabilities the callee may use for
        // this call only. They are accepted and ignored: the callee runs with
        // its own Installation's scopes and nothing of the calling app's, still
        // bounded by whoever made the entry call.
        if !handles.is_empty() {
            tracing::debug!(
                count = handles.len(),
                "host ABI: ignoring handles passed to calls.call"
            );
        }
        // What a call causes is bounded by what the calling app declared, not
        // only by who asked: an app calls only the interfaces its manifest
        // lists in `uses`.
        let declared = self
            .host
            .manifest
            .as_ref()
            .is_some_and(|m| m.uses.contains(&interface));
        if !declared {
            return Err(error(
                code::FORBIDDEN,
                format!("this app does not declare that it uses {interface} (manifest `uses`)"),
            ));
        }
        if !self.host.core.grant().allows_call(&interface) {
            return Err(error(
                code::FORBIDDEN,
                format!("{interface} is outside the call scope of this installation"),
            ));
        }
        call_export(
            &self.host.registry,
            &self.host.db,
            &self.host.drive,
            &interface,
            &function,
            &args,
            self.host.core.grant().caller().clone(),
            self.host.depth + 1,
            self.host.budget.clone(),
        )
        .await
    }
}
