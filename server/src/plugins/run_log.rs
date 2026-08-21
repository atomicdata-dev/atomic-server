//! The record an unattended run leaves behind.
//!
//! The Rust half of `plugin-log.ts`. It matters more here than in the browser:
//! a run the server applied on its own is one nobody watched, so the log is
//! the only account of what happened. If it cannot be written, the run does
//! not get to write either — see [`super::scheduler`].

use std::collections::HashMap;

use serde_json::{json, Value as Json};

use crate::plugins::{
    apply::{ApplyHost, ApplyReport, CreateRequest},
    plan::{Problem, RunPlan},
    scheduler::DriveTerms,
};

/// blocked, applied, partial or failed — the same four the browser writes.
pub fn run_status(plan: &RunPlan, report: Option<&ApplyReport>) -> &'static str {
    let Some(report) = report else {
        return "blocked";
    };

    if plan.blocked {
        return "blocked";
    }

    if report.failed == 0 {
        return "applied";
    }

    if report.applied > 0 {
        "partial"
    } else {
        "failed"
    }
}

/// Writes one run record under the plugin and returns its subject.
pub async fn record_run(
    host: &mut impl ApplyHost,
    terms: &DriveTerms,
    plugin: &str,
    trigger: &str,
    at: i64,
    plan: &RunPlan,
    report: Option<&ApplyReport>,
) -> Result<String, String> {
    let status = run_status(plan, report);

    let mut prop_vals: HashMap<String, Json> = HashMap::new();
    prop_vals.insert(
        atomic_lib::urls::NAME.to_string(),
        json!(format!("{trigger} run — {status}")),
    );

    let mut put = |shortname: &str, value: Json| -> Result<(), String> {
        let property = terms
            .property(shortname)
            .ok_or_else(|| format!("this drive has no {shortname} property"))?;
        prop_vals.insert(property.to_string(), value);

        Ok(())
    };

    put("trigger", json!(trigger))?;
    put("started-at", json!(at))?;
    put("run-status", json!(status))?;
    put("run-problems", problems_of(plan))?;
    put(
        "run-outcomes",
        serde_json::to_value(report.map(|r| &r.outcomes)).map_err(|e| e.to_string())?,
    )?;

    // Only after something was actually applied: persisting a cursor for a run
    // that wrote nothing would tell the next run to skip work never done.
    if let (Some(report), Some(cursor)) = (report, plan.cursor.as_ref()) {
        if report.applied > 0 {
            put("run-cursor", json!(cursor))?;
        }
    }

    let class = terms
        .class("plugin-run")
        .ok_or("this drive has no plugin-run class")?;

    host.create(CreateRequest {
        parent: plugin.to_string(),
        is_a: vec![class.to_string()],
        prop_vals,
    })
    .await
}

/// Problems worth keeping: everything the plan carried, plus everything
/// attached to a change, each tagged with the subject it concerns so the log
/// reads without the plan beside it.
fn problems_of(plan: &RunPlan) -> Json {
    let attached = plan.changes.iter().flat_map(|change| {
        change.problems.iter().map(|problem| Problem {
            subject: problem
                .subject
                .clone()
                .or_else(|| Some(change.subject.clone())),
            ..problem.clone()
        })
    });

    let all: Vec<Problem> = plan.problems.iter().cloned().chain(attached).collect();

    serde_json::to_value(all).unwrap_or_else(|_| json!([]))
}
