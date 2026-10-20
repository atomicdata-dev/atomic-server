//! Example app on the Atomic host ABI.
//!
//! Exports `atomic:example/caller@1`:
//!
//! - `bump-twice` calls `atomic:example/counter@1` `increment` twice through
//!   `calls.call`. The caller never touches the counter's data and has no
//!   rights over it: the counter app does the write, with its own grant.
//! - `recurse` calls itself until `n` reaches `limit`, to show that the host
//!   bounds how deep apps may call each other.

wit_bindgen::generate!({
    path: "../../atomic-host/wit",
    world: "sandboxed-app",
});

use atomic::host::{calls, events::Event, types::Error};
use exports::atomic::host::app::Guest;

struct Caller;

const COUNTER: &str = "atomic:example/counter@1";
const CALLER: &str = "atomic:example/caller@1";

fn fail(code: &str, message: impl Into<String>) -> Error {
    Error {
        code: code.to_string(),
        message: message.into(),
    }
}

fn parse(args: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(args).map_err(|e| fail("invalid-argument", e.to_string()))
}

fn bump_twice(args: &str) -> Result<String, Error> {
    // The counter validates these; the caller only forwards them.
    let args = parse(args)?;
    let forwarded = serde_json::json!({
        "subject": args["subject"],
        "property": args["property"],
    })
    .to_string();

    let mut count = 0;
    for _ in 0..2 {
        let result = calls::call(COUNTER, "increment", &forwarded, &[])?;
        let result: serde_json::Value =
            serde_json::from_str(&result).map_err(|e| fail("internal", e.to_string()))?;
        count = result["count"]
            .as_i64()
            .ok_or_else(|| fail("internal", "the counter returned no count"))?;
    }

    Ok(serde_json::json!({ "count": count }).to_string())
}

fn recurse(args: &str) -> Result<String, Error> {
    let args = parse(args)?;
    let n = args["n"].as_i64().unwrap_or(0);
    let limit = args["limit"].as_i64().unwrap_or(0);
    if n >= limit {
        return Ok(serde_json::json!({ "depth": n }).to_string());
    }
    calls::call(
        CALLER,
        "recurse",
        &serde_json::json!({ "n": n + 1, "limit": limit }).to_string(),
        &[],
    )
}

impl Guest for Caller {
    fn on_event(_event: Event) -> Result<(), Error> {
        Ok(())
    }

    fn invoke(interface: String, function: String, args: String) -> Result<String, Error> {
        match (interface.as_str(), function.as_str()) {
            (CALLER, "bump-twice") => bump_twice(&args),
            (CALLER, "recurse") => recurse(&args),
            _ => Err(fail(
                "not-found",
                format!("no export {interface} {function}"),
            )),
        }
    }
}

export!(Caller);
