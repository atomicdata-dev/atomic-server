//! Example app on the Atomic host ABI.
//!
//! Exports `atomic:example/counter@1` `increment`: reads a resource with
//! `store.get`, writes its count plus one with `store.apply`, and returns the
//! new count. The host decides whether the write is committed (the app's agent
//! may write there) or only proposed; the app reports what happened.

wit_bindgen::generate!({
    path: "../../atomic-host/wit",
    world: "sandboxed-app",
});

use atomic::host::{
    events::Event,
    store::{self, Intent, Outcome},
    types::{Error, PropVal, Value},
};
use exports::atomic::host::app::Guest;

struct Counter;

fn fail(code: &str, message: impl Into<String>) -> Error {
    Error {
        code: code.to_string(),
        message: message.into(),
    }
}

fn increment(args: &str) -> Result<String, Error> {
    let args: serde_json::Value =
        serde_json::from_str(args).map_err(|e| fail("invalid-argument", e.to_string()))?;
    let subject = args["subject"]
        .as_str()
        .ok_or_else(|| fail("invalid-argument", "subject is required"))?;
    let property = args["property"]
        .as_str()
        .ok_or_else(|| fail("invalid-argument", "property is required"))?;

    let resource = store::get(subject)?;
    let current = match resource.propvals.iter().find(|pv| pv.property == property) {
        Some(PropVal {
            value: Value::Integer(count),
            ..
        }) => *count,
        Some(_) => {
            return Err(fail(
                "invalid-argument",
                format!("{property} is not an integer"),
            ))
        }
        None => 0,
    };
    let next = current + 1;

    let applied = store::apply(&[Intent::Set((
        subject.to_string(),
        vec![PropVal {
            property: property.to_string(),
            value: Value::Integer(next),
        }],
    ))])?;
    if applied.outcome != Outcome::Committed {
        return Err(fail(
            "not-committed",
            format!("{:?}: {:?}", applied.outcome, applied.problems),
        ));
    }

    Ok(serde_json::json!({ "count": next }).to_string())
}

impl Guest for Counter {
    fn on_event(_event: Event) -> Result<(), Error> {
        Ok(())
    }

    fn invoke(interface: String, function: String, args: String) -> Result<String, Error> {
        match (interface.as_str(), function.as_str()) {
            ("atomic:example/counter@1", "increment") => increment(&args),
            _ => Err(fail(
                "not-found",
                format!("no export {interface} {function}"),
            )),
        }
    }
}

export!(Counter);
