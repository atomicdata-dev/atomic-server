//! Writing an approved plan, server-side.
//!
//! The mirror of `plugin-apply.ts`. The browser applies what a person just
//! reviewed on screen; this applies what a person reviewed once and then
//! granted — a scheduled run whose changes get written without anyone
//! watching. Same plan, same ordering rules, same refusals.
//!
//! One deliberate difference: this one is sequential. The browser's
//! concurrency exists because every write is a round trip, and an import of
//! two thousand rows spent almost all of its time waiting. Here the store is
//! in-process, so there is nothing to overlap and a single order is easier to
//! reason about when something fails halfway.

use std::collections::{HashMap, HashSet};

use serde_json::Value as Json;

use crate::plugins::plan::{Op, PlannedChange, RunPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeStatus {
    Applied,
    Skipped,
    Failed,
    NotAttempted,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeOutcome {
    pub op: String,
    /// The subject as planned.
    pub planned: String,
    /// The subject that exists now. Differs from `planned` for creates.
    pub subject: String,
    pub local_id: Option<String>,
    pub status: ChangeStatus,
    pub error: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyReport {
    pub outcomes: Vec<ChangeOutcome>,
    pub applied: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Planned subject to the real one, for creates.
    pub subjects: HashMap<String, String>,
    /// True when a failure stopped the run before every change was attempted.
    pub stopped_early: bool,
}

pub struct CreateRequest {
    pub parent: String,
    pub is_a: Vec<String>,
    pub prop_vals: HashMap<String, Json>,
}

/// What applying needs from a store. Narrow, for the same reason `PlanHost` is.
#[async_trait::async_trait]
pub trait ApplyHost: Send {
    /// Creates the resource and returns the subject it actually got.
    async fn create(&mut self, request: CreateRequest) -> Result<String, String>;
    async fn set(&mut self, subject: &str, prop_vals: HashMap<String, Json>) -> Result<(), String>;
    async fn remove(&mut self, subject: &str, properties: Vec<String>) -> Result<(), String>;
    async fn destroy(&mut self, subject: &str) -> Result<(), String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyOptions {
    /// Keep going after a change fails. Off by default: a failed create means
    /// everything that links to it would point at nothing, and half a linked
    /// graph is harder to reason about than a run that stopped.
    pub continue_on_error: bool,
}

/// Applies a plan and reports what happened to every change.
///
/// Refuses a blocked plan outright. Applying one would mean writing changes
/// the planner already knows are wrong, and a partially-applied bad import is
/// the expensive kind of mistake.
pub async fn apply_plan(
    plan: &RunPlan,
    host: &mut impl ApplyHost,
    options: ApplyOptions,
) -> Result<ApplyReport, String> {
    if plan.blocked {
        return Err(
            "refusing to apply a blocked plan: resolve its errors or drop the offending changes first"
                .to_string(),
        );
    }

    let ordered = creates_first(&plan.changes);
    let planned_subjects: HashSet<String> = plan
        .changes
        .iter()
        .filter(|c| c.op == Op::Create)
        .map(|c| c.subject.clone())
        .collect();

    let mut subjects: HashMap<String, String> = HashMap::new();
    let mut outcomes = Vec::with_capacity(ordered.len());
    let mut stopped = false;

    for change in ordered {
        if stopped {
            outcomes.push(outcome(
                change,
                &change.subject,
                ChangeStatus::NotAttempted,
                None,
            ));

            continue;
        }

        match apply_change(change, host, &subjects, &planned_subjects).await {
            Ok((subject, status)) => {
                if subject != change.subject {
                    subjects.insert(change.subject.clone(), subject.clone());
                }

                outcomes.push(outcome(change, &subject, status, None));
            }
            Err(e) => {
                outcomes.push(outcome(
                    change,
                    &change.subject,
                    ChangeStatus::Failed,
                    Some(e),
                ));

                if !options.continue_on_error {
                    stopped = true;
                }
            }
        }
    }

    Ok(ApplyReport {
        applied: outcomes
            .iter()
            .filter(|o| o.status == ChangeStatus::Applied)
            .count(),
        skipped: outcomes
            .iter()
            .filter(|o| o.status == ChangeStatus::Skipped)
            .count(),
        failed: outcomes
            .iter()
            .filter(|o| o.status == ChangeStatus::Failed)
            .count(),
        stopped_early: outcomes
            .iter()
            .any(|o| o.status == ChangeStatus::NotAttempted),
        outcomes,
        subjects,
    })
}

async fn apply_change(
    change: &PlannedChange,
    host: &mut impl ApplyHost,
    subjects: &HashMap<String, String>,
    planned_subjects: &HashSet<String>,
) -> Result<(String, ChangeStatus), String> {
    let subject = subjects
        .get(&change.subject)
        .cloned()
        .unwrap_or_else(|| change.subject.clone());

    let values = writable_values(change);
    let dangling = unresolved_references(
        &values,
        change.parent.as_deref(),
        planned_subjects,
        subjects,
    );

    if !dangling.is_empty() {
        return Err(format!(
            "refers to {}, which this run did not create — writing it would link to nothing",
            dangling.join(", "),
        ));
    }

    match change.op {
        Op::Create => {
            let parent = change
                .parent
                .clone()
                .ok_or("a create with no parent cannot be written")?;

            let created = host
                .create(CreateRequest {
                    parent: subjects.get(&parent).cloned().unwrap_or(parent),
                    is_a: change.is_a.clone(),
                    prop_vals: rewrite(values, subjects),
                })
                .await?;

            Ok((created, ChangeStatus::Applied))
        }
        Op::Set => {
            if change.properties.is_empty() {
                return Ok((subject, ChangeStatus::Skipped));
            }

            host.set(&subject, rewrite(values, subjects)).await?;

            Ok((subject, ChangeStatus::Applied))
        }
        Op::Remove => {
            if change.properties.is_empty() {
                return Ok((subject, ChangeStatus::Skipped));
            }

            let properties = change
                .properties
                .iter()
                .map(|p| p.property.clone())
                .collect();

            host.remove(&subject, properties).await?;

            Ok((subject, ChangeStatus::Applied))
        }
        Op::Destroy => {
            host.destroy(&subject).await?;

            Ok((subject, ChangeStatus::Applied))
        }
    }
}

/// Orders creates ahead of everything else, and each create after every create
/// it refers to.
///
/// Following only `parent` was not enough: an imported contact whose employer
/// points at an Organization created by the same run is not that
/// Organization's child, so it could be written first — and then the link was
/// written as the planner's placeholder subject, which never exists. That is
/// silent data corruption, and it is exactly what a linked import produces.
///
/// The plan keeps intent order so the preview reads the way the run was
/// written; only applying needs dependency order.
fn creates_first(changes: &[PlannedChange]) -> Vec<&PlannedChange> {
    let creates: Vec<&PlannedChange> = changes.iter().filter(|c| c.op == Op::Create).collect();
    let by_subject: HashMap<&str, &PlannedChange> =
        creates.iter().map(|c| (c.subject.as_str(), *c)).collect();

    let mut ordered: Vec<&PlannedChange> = Vec::with_capacity(changes.len());
    let mut placed: HashSet<String> = HashSet::new();

    for create in &creates {
        place(
            create,
            &by_subject,
            &mut placed,
            &mut HashSet::new(),
            &mut ordered,
        );
    }

    ordered.extend(changes.iter().filter(|c| c.op != Op::Create));
    ordered
}

fn place<'a>(
    change: &'a PlannedChange,
    by_subject: &HashMap<&str, &'a PlannedChange>,
    placed: &mut HashSet<String>,
    seen: &mut HashSet<String>,
    ordered: &mut Vec<&'a PlannedChange>,
) {
    if placed.contains(&change.subject) || seen.contains(&change.subject) {
        return;
    }

    seen.insert(change.subject.clone());

    for dependency in referenced_creates(change, by_subject) {
        place(dependency, by_subject, placed, seen, ordered);
    }

    placed.insert(change.subject.clone());
    ordered.push(change);
}

/// Creates this change refers to, by parent or by any property value.
fn referenced_creates<'a>(
    change: &PlannedChange,
    by_subject: &HashMap<&str, &'a PlannedChange>,
) -> Vec<&'a PlannedChange> {
    let mut found = Vec::new();

    let visit = |value: &Json, found: &mut Vec<&'a PlannedChange>| {
        for subject in subjects_in(value) {
            if let Some(hit) = by_subject.get(subject.as_str()) {
                if hit.subject != change.subject {
                    found.push(*hit);
                }
            }
        }
    };

    if let Some(parent) = &change.parent {
        visit(&Json::String(parent.clone()), &mut found);
    }

    for property in &change.properties {
        if let Some(to) = &property.to {
            visit(to, &mut found);
        }
    }

    found
}

/// Planned subjects that no longer have a real one.
///
/// Reachable when two creates refer to each other: no order can satisfy both,
/// so one of them would write a link to a resource that does not exist.
/// Reported rather than written — a dangling link that looks like data is
/// worse than a change that refused.
fn unresolved_references(
    values: &HashMap<String, Json>,
    parent: Option<&str>,
    planned_subjects: &HashSet<String>,
    subjects: &HashMap<String, String>,
) -> Vec<String> {
    let mut dangling: Vec<String> = Vec::new();

    let check = |value: &Json, dangling: &mut Vec<String>| {
        for subject in subjects_in(value) {
            if planned_subjects.contains(&subject)
                && !subjects.contains_key(&subject)
                && !dangling.contains(&subject)
            {
                dangling.push(subject);
            }
        }
    };

    if let Some(parent) = parent {
        check(&Json::String(parent.to_string()), &mut dangling);
    }

    for value in values.values() {
        check(value, &mut dangling);
    }

    dangling
}

/// Every string anywhere in a value. A reference can sit inside an array or a
/// nested object, and one written as a placeholder is as broken as one written
/// at the top level.
fn subjects_in(value: &Json) -> Vec<String> {
    match value {
        Json::String(text) => vec![text.clone()],
        Json::Array(items) => items.iter().flat_map(subjects_in).collect(),
        Json::Object(map) => map.values().flat_map(subjects_in).collect(),
        _ => Vec::new(),
    }
}

fn writable_values(change: &PlannedChange) -> HashMap<String, Json> {
    change
        .properties
        .iter()
        .filter_map(|p| p.to.clone().map(|to| (p.property.clone(), to)))
        .collect()
}

/// Points values at the subjects creates actually got.
fn rewrite(
    values: HashMap<String, Json>,
    subjects: &HashMap<String, String>,
) -> HashMap<String, Json> {
    if subjects.is_empty() {
        return values;
    }

    values
        .into_iter()
        .map(|(key, value)| (key, swap(value, subjects)))
        .collect()
}

fn swap(value: Json, subjects: &HashMap<String, String>) -> Json {
    match value {
        Json::String(text) => Json::String(subjects.get(&text).cloned().unwrap_or(text)),
        Json::Array(items) => Json::Array(items.into_iter().map(|i| swap(i, subjects)).collect()),
        Json::Object(map) => Json::Object(
            map.into_iter()
                .map(|(k, v)| (k, swap(v, subjects)))
                .collect(),
        ),
        other => other,
    }
}

fn outcome(
    change: &PlannedChange,
    subject: &str,
    status: ChangeStatus,
    error: Option<String>,
) -> ChangeOutcome {
    ChangeOutcome {
        op: format!("{:?}", change.op).to_lowercase(),
        planned: change.subject.clone(),
        subject: subject.to_string(),
        local_id: change.local_id.clone(),
        status,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::plan::PlannedProperty;
    use serde_json::json;

    /// Records what it was asked to write, and mints a subject unlike the
    /// planned one — a store that hands back the subject it was given would
    /// hide every rewriting bug in here.
    #[derive(Default)]
    struct FakeHost {
        creates: Vec<CreateRequest>,
        sets: Vec<(String, HashMap<String, Json>)>,
        removes: Vec<(String, Vec<String>)>,
        destroys: Vec<String>,
        minted: usize,
        fail_on: Option<String>,
    }

    #[async_trait::async_trait]
    impl ApplyHost for FakeHost {
        async fn create(&mut self, request: CreateRequest) -> Result<String, String> {
            if self.fail_on.as_deref() == Some(request.parent.as_str()) {
                return Err("the store said no".to_string());
            }

            self.minted += 1;
            self.creates.push(request);

            Ok(format!("did:ad:real-{}", self.minted))
        }

        async fn set(
            &mut self,
            subject: &str,
            prop_vals: HashMap<String, Json>,
        ) -> Result<(), String> {
            if self.fail_on.as_deref() == Some(subject) {
                return Err("the store said no".to_string());
            }

            self.sets.push((subject.to_string(), prop_vals));

            Ok(())
        }

        async fn remove(&mut self, subject: &str, properties: Vec<String>) -> Result<(), String> {
            self.removes.push((subject.to_string(), properties));

            Ok(())
        }

        async fn destroy(&mut self, subject: &str) -> Result<(), String> {
            self.destroys.push(subject.to_string());

            Ok(())
        }
    }

    fn plan(changes: Vec<PlannedChange>) -> RunPlan {
        RunPlan {
            changes,
            ..Default::default()
        }
    }

    fn create(subject: &str, properties: Vec<PlannedProperty>) -> PlannedChange {
        PlannedChange {
            op: Op::Create,
            subject: subject.to_string(),
            local_id: subject.rsplit('/').next().map(str::to_string),
            parent: Some("https://x/drive".to_string()),
            is_a: vec!["https://x/Thing".to_string()],
            properties,
            problems: Vec::new(),
        }
    }

    fn change(op: Op, subject: &str, properties: Vec<PlannedProperty>) -> PlannedChange {
        PlannedChange {
            op,
            subject: subject.to_string(),
            local_id: None,
            parent: None,
            is_a: Vec::new(),
            properties,
            problems: Vec::new(),
        }
    }

    fn property(url: &str, to: Option<Json>) -> PlannedProperty {
        PlannedProperty {
            property: url.to_string(),
            shortname: None,
            from: None,
            to,
        }
    }

    #[tokio::test]
    async fn refuses_a_blocked_plan_instead_of_writing_part_of_it() {
        let mut host = FakeHost::default();
        let blocked = RunPlan {
            changes: vec![create("local:a", vec![])],
            blocked: true,
            ..Default::default()
        };

        assert!(apply_plan(&blocked, &mut host, ApplyOptions::default())
            .await
            .is_err());
        assert!(host.creates.is_empty());
    }

    #[tokio::test]
    async fn reports_the_subject_a_create_actually_got() {
        let mut host = FakeHost::default();

        let report = apply_plan(
            &plan(vec![create("https://x/planned", vec![])]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.applied, 1);
        assert_eq!(report.outcomes[0].subject, "did:ad:real-1");
        assert_eq!(report.outcomes[0].planned, "https://x/planned");
        assert_eq!(
            report.subjects.get("https://x/planned").map(String::as_str),
            Some("did:ad:real-1"),
        );
    }

    #[tokio::test]
    async fn points_later_references_at_the_subject_the_store_minted() {
        let mut host = FakeHost::default();

        apply_plan(
            &plan(vec![
                create("https://x/planned", vec![]),
                change(
                    Op::Set,
                    "https://x/other",
                    vec![property("https://x/link", Some(json!("https://x/planned")))],
                ),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            host.sets[0].1.get("https://x/link"),
            Some(&json!("did:ad:real-1")),
        );
    }

    #[tokio::test]
    async fn creates_the_target_before_the_resource_that_links_to_it() {
        let mut host = FakeHost::default();

        // The linking resource comes first in the plan, and is not a child of
        // the one it points at — so only following the reference gets this
        // right.
        let report = apply_plan(
            &plan(vec![
                create(
                    "https://x/contact",
                    vec![property("https://x/employer", Some(json!("https://x/org")))],
                ),
                create("https://x/org", vec![]),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.failed, 0);
        assert_eq!(
            host.creates[1].prop_vals.get("https://x/employer"),
            Some(&json!("did:ad:real-1")),
            "the link points at the org, which was created first",
        );
    }

    #[tokio::test]
    async fn follows_links_nested_in_arrays() {
        let mut host = FakeHost::default();

        apply_plan(
            &plan(vec![
                create(
                    "https://x/list",
                    vec![property(
                        "https://x/members",
                        Some(json!(["https://x/member", "https://x/outside"])),
                    )],
                ),
                create("https://x/member", vec![]),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            host.creates[1].prop_vals.get("https://x/members"),
            Some(&json!(["did:ad:real-1", "https://x/outside"])),
        );
    }

    #[tokio::test]
    async fn refuses_to_write_a_link_to_a_create_that_never_happened() {
        let mut host = FakeHost::default();

        // Two creates pointing at each other: no order satisfies both, so one
        // of them must refuse rather than write a placeholder subject.
        let report = apply_plan(
            &plan(vec![
                create(
                    "https://x/a",
                    vec![property("https://x/link", Some(json!("https://x/b")))],
                ),
                create(
                    "https://x/b",
                    vec![property("https://x/link", Some(json!("https://x/a")))],
                ),
            ]),
            &mut host,
            ApplyOptions {
                continue_on_error: true,
            },
        )
        .await
        .unwrap();

        // Neither is written: whichever goes first has nothing to link to,
        // and the second then has nothing to link to either.
        assert_eq!(report.failed, 2);
        assert!(host.creates.is_empty());
        assert!(report.outcomes.iter().all(|o| o
            .error
            .as_deref()
            .is_some_and(|e| e.contains("link to nothing"))));
    }

    #[tokio::test]
    async fn sends_only_properties_that_have_a_value() {
        let mut host = FakeHost::default();

        apply_plan(
            &plan(vec![change(
                Op::Set,
                "https://x/a",
                vec![
                    property("https://x/kept", Some(json!("yes"))),
                    property("https://x/dropped", None),
                ],
            )]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        let written = &host.sets[0].1;
        assert_eq!(written.len(), 1);
        assert!(written.contains_key("https://x/kept"));
    }

    #[tokio::test]
    async fn removes_and_destroys() {
        let mut host = FakeHost::default();

        apply_plan(
            &plan(vec![
                change(
                    Op::Remove,
                    "https://x/a",
                    vec![property("https://x/gone", None)],
                ),
                change(Op::Destroy, "https://x/b", vec![]),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            host.removes,
            vec![(
                "https://x/a".to_string(),
                vec!["https://x/gone".to_string()]
            )],
        );
        assert_eq!(host.destroys, vec!["https://x/b".to_string()]);
    }

    #[tokio::test]
    async fn skips_a_change_with_nothing_to_write() {
        let mut host = FakeHost::default();

        let report = apply_plan(
            &plan(vec![change(Op::Set, "https://x/a", vec![])]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.skipped, 1);
        assert_eq!(report.applied, 0);
        assert!(host.sets.is_empty());
    }

    #[tokio::test]
    async fn stops_so_dependents_do_not_link_to_something_that_failed() {
        let mut host = FakeHost {
            fail_on: Some("https://x/drive".to_string()),
            ..Default::default()
        };

        let report = apply_plan(
            &plan(vec![
                create("https://x/a", vec![]),
                change(
                    Op::Set,
                    "https://x/b",
                    vec![property("https://x/link", Some(json!("https://x/a")))],
                ),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.failed, 1);
        assert!(report.stopped_early);
        assert!(host.sets.is_empty());
        assert_eq!(report.outcomes[1].status, ChangeStatus::NotAttempted);
    }

    #[tokio::test]
    async fn records_why_a_change_failed() {
        let mut host = FakeHost {
            fail_on: Some("https://x/a".to_string()),
            ..Default::default()
        };

        let report = apply_plan(
            &plan(vec![change(
                Op::Set,
                "https://x/a",
                vec![property("https://x/p", Some(json!("v")))],
            )]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            report.outcomes[0].error.as_deref(),
            Some("the store said no"),
        );
    }

    #[tokio::test]
    async fn keeps_going_when_told_to() {
        let mut host = FakeHost {
            fail_on: Some("https://x/a".to_string()),
            ..Default::default()
        };

        let report = apply_plan(
            &plan(vec![
                change(
                    Op::Set,
                    "https://x/a",
                    vec![property("https://x/p", Some(json!("v")))],
                ),
                change(
                    Op::Set,
                    "https://x/b",
                    vec![property("https://x/p", Some(json!("v")))],
                ),
            ]),
            &mut host,
            ApplyOptions {
                continue_on_error: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.failed, 1);
        assert_eq!(report.applied, 1);
        assert!(!report.stopped_early);
    }

    #[tokio::test]
    async fn does_not_claim_it_stopped_early_when_the_last_change_failed() {
        let mut host = FakeHost {
            fail_on: Some("https://x/b".to_string()),
            ..Default::default()
        };

        let report = apply_plan(
            &plan(vec![
                change(
                    Op::Set,
                    "https://x/a",
                    vec![property("https://x/p", Some(json!("v")))],
                ),
                change(
                    Op::Set,
                    "https://x/b",
                    vec![property("https://x/p", Some(json!("v")))],
                ),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.failed, 1);
        assert!(!report.stopped_early);
    }

    #[tokio::test]
    async fn reports_every_change_exactly_once() {
        let mut host = FakeHost::default();

        let report = apply_plan(
            &plan(vec![
                create("https://x/a", vec![]),
                create("https://x/b", vec![]),
                change(Op::Destroy, "https://x/c", vec![]),
            ]),
            &mut host,
            ApplyOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.outcomes.len(), 3);
        assert_eq!(report.applied, 3);
    }
}
