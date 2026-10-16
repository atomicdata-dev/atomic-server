//! Example server module on the Atomic host ABI (world `server-module`).
//!
//! Extends folders:
//! - `before-commit` refuses a folder named `refuse-me` and warns on `warn-me`;
//! - `on-get` replaces the description with a note about the read: who asked,
//!   who the module is, and what the module's agent could do when its config
//!   asks it to try (`probeRead`: a subject to `store.get`, `probeWrite`: a
//!   subject to rename with `store.apply`, `probeCall`: an `{interface,
//!   function, args}` to call with `calls.call`). The probes report error codes
//!   and outcomes, so a test can see what the module's rights were.
//!
//! The probes must not name a folder: reading one runs this hook again.

wit_bindgen::generate!({
    path: "../../atomic-host/wit",
    world: "server-module",
});

use atomic::host::{
    calls, context,
    store::{self, Intent, Outcome},
    types::{Error, Problem, PropVal, Resource, Severity, Value},
};
use exports::atomic::host::hooks::{CommitInfo, Guest};

const FOLDER: &str = "https://atomicdata.dev/classes/Folder";
const NAME: &str = "https://atomicdata.dev/properties/name";
const DESCRIPTION: &str = "https://atomicdata.dev/properties/description";

struct Module;

fn name_of(resource: &Resource) -> Option<&str> {
    resource.propvals.iter().find_map(|pv| match &pv.value {
        Value::String(name) if pv.property == NAME => Some(name.as_str()),
        _ => None,
    })
}

fn problem(severity: Severity, message: &str) -> Problem {
    Problem {
        severity,
        message: message.to_string(),
        subject: None,
        property: Some(NAME.to_string()),
    }
}

impl Guest for Module {
    fn classes() -> Vec<String> {
        vec![FOLDER.to_string()]
    }

    fn before_commit(_commit: CommitInfo, after: Resource) -> Vec<Problem> {
        match name_of(&after) {
            Some("refuse-me") => vec![problem(Severity::Error, "this module refuses refuse-me")],
            Some("warn-me") => vec![problem(
                Severity::Warning,
                "this module warns about warn-me",
            )],
            _ => Vec::new(),
        }
    }

    fn after_commit(_commit: CommitInfo, _after: Resource) -> Result<(), Error> {
        Ok(())
    }

    fn on_get(mut resource: Resource, agent: String) -> Result<Option<Resource>, Error> {
        let me = context::get();
        let config: serde_json::Value = serde_json::from_str(&me.config).unwrap_or_default();
        let mut notes = vec![
            format!("asked by {agent}"),
            format!("module {}", me.agent.unwrap_or_else(|| "none".into())),
        ];
        if let Some(subject) = config["probeRead"].as_str() {
            let outcome = match store::get(subject) {
                Ok(_) => "ok".to_string(),
                Err(e) => e.code,
            };
            notes.push(format!("read {outcome}"));
        }
        if let Some(subject) = config["probeWrite"].as_str() {
            let rename = Intent::Set((
                subject.to_string(),
                vec![PropVal {
                    property: NAME.to_string(),
                    value: Value::String("overwritten".to_string()),
                }],
            ));
            let outcome = match store::apply(&[rename]) {
                Ok(applied) => match applied.outcome {
                    Outcome::Committed => "committed",
                    Outcome::Proposed => "proposed",
                    Outcome::Refused => "refused",
                }
                .to_string(),
                Err(e) => e.code,
            };
            notes.push(format!("write {outcome}"));
        }
        if let Some(call) = config.get("probeCall") {
            let text = |key: &str| call[key].as_str().unwrap_or_default().to_string();
            let outcome = match calls::call(
                &text("interface"),
                &text("function"),
                &call["args"].to_string(),
                &[],
            ) {
                Ok(result) => format!("ok {result}"),
                Err(e) => e.code,
            };
            notes.push(format!("call {outcome}"));
        }
        resource.propvals.retain(|pv| pv.property != DESCRIPTION);
        resource.propvals.push(PropVal {
            property: DESCRIPTION.to_string(),
            value: Value::String(notes.join("; ")),
        });
        Ok(Some(resource))
    }
}

export!(Module);
