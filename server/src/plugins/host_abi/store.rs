//! `atomic:host/store`: reads, queries and `apply`.
//!
//! Every read goes through [`HostCore`]'s grant (the caller and the
//! Installation's agent must both be able to read). Every write is planned by
//! [`plan_verdict`] and applied by [`apply_plan`] through [`StoreApplyHost`],
//! signed by the Installation's agent.

use atomic_lib::{urls, Db, Storelike};

use super::{
    bindings::atomic::host::{
        store::{self, Applied, Intent, Outcome, Page, QuerySpec},
        types::{Problem, Resource as WitResource, Severity},
    },
    classify, code,
    convert::{self, check_spec, intents_to_verdict, to_query, to_wit_resource},
    error,
    run::AbiState,
    HostError,
};
use crate::plugins::{
    apply::{apply_plan, ApplyOptions},
    plan::{plan_verdict, Op, RunPlan, Severity as PlanSeverity},
    store_host::StoreApplyHost,
};

/// Most subjects one `get-many` reads; the same as a frame's `getMany`
/// (`MAX_GET_MANY` in `hostStore.ts`).
pub(super) const MAX_GET_MANY: usize = 100;
/// Most intents in one `apply`.
const MAX_INTENTS: usize = 500;

/// Classes an app may never write through the ABI: its own installation and
/// code are changed by people, not by the apps they installed.
const PROTECTED_CLASSES: [&str; 3] = [urls::INSTALLATION, urls::PLUGIN, urls::RELEASE];

fn problem(message: impl Into<String>, subject: Option<String>) -> Problem {
    Problem {
        severity: Severity::Error,
        message: message.into(),
        subject,
        property: None,
    }
}

fn plan_problems(plan: &RunPlan) -> Vec<Problem> {
    plan.problems
        .iter()
        .chain(plan.changes.iter().flat_map(|c| c.problems.iter()))
        .map(|p| Problem {
            severity: match p.severity {
                PlanSeverity::Error => Severity::Error,
                PlanSeverity::Warning => Severity::Warning,
            },
            message: p.message.clone(),
            subject: p.subject.clone(),
            property: None,
        })
        .collect()
}

/// Where each planned change lands: the resource written, or for a create the
/// parent that must allow it. A create under a resource made by the same apply
/// has no parent to check yet, and is covered by the create above it.
fn write_targets(plan: &RunPlan) -> Vec<String> {
    let created: std::collections::HashSet<&String> = plan
        .changes
        .iter()
        .filter(|c| c.op == Op::Create)
        .map(|c| &c.subject)
        .collect();
    plan.changes
        .iter()
        .filter_map(|change| match change.op {
            Op::Create => change
                .parent
                .as_ref()
                .filter(|parent| !created.contains(parent))
                .cloned(),
            _ => Some(change.subject.clone()),
        })
        .collect()
}

/// A plan that would touch an Installation, a plugin or a Release.
async fn touches_protected(db: &Db, plan: &RunPlan) -> Option<String> {
    for change in &plan.changes {
        let classes: Vec<String> = match change.op {
            Op::Create => change.is_a.clone(),
            _ => match db.get_resource(&change.subject.as_str().into()).await {
                Ok(resource) => resource
                    .get(urls::IS_A)
                    .ok()
                    .and_then(|v| v.to_subjects(None).ok())
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            },
        };
        if classes
            .iter()
            .any(|c| PROTECTED_CLASSES.contains(&c.as_str()))
        {
            return Some(change.subject.clone());
        }
        // A set that turns something into one of them.
        let becomes_protected = change
            .properties
            .iter()
            .filter(|p| p.property == urls::IS_A)
            .filter_map(|p| p.to.as_ref())
            .any(|to| match to {
                serde_json::Value::String(class) => PROTECTED_CLASSES.contains(&class.as_str()),
                serde_json::Value::Array(all) => all
                    .iter()
                    .filter_map(|c| c.as_str())
                    .any(|c| PROTECTED_CLASSES.contains(&c)),
                _ => false,
            });
        if becomes_protected {
            return Some(change.subject.clone());
        }
    }
    None
}

impl store::Host for AbiState {
    async fn get(&mut self, subject: String) -> Result<WitResource, HostError> {
        let resource = self
            .host
            .core
            .get_resource(&subject)
            .await
            .map_err(classify)?;
        Ok(to_wit_resource(&resource))
    }

    async fn get_many(&mut self, subjects: Vec<String>) -> Vec<Result<WitResource, HostError>> {
        let mut out = Vec::with_capacity(subjects.len());
        for (i, subject) in subjects.into_iter().enumerate() {
            // Same bound as a frame's `getMany`; the rest are answered in place.
            if i >= MAX_GET_MANY {
                out.push(Err(error(
                    code::INVALID_ARGUMENT,
                    format!("get-many reads at most {MAX_GET_MANY} subjects at a time"),
                )));
                continue;
            }
            out.push(store::Host::get(self, subject).await);
        }
        out
    }

    async fn query(&mut self, q: QuerySpec) -> Result<Page, HostError> {
        let (offset, limit) = check_spec(&q)?;
        let host = &self.host;

        let mut query = to_query(&host.db, &q, &host.drive).await?;
        query.for_agent = host.core.grant().caller().clone();
        // One row past the page tells whether there is a next one; reading
        // more than that is what a chat with ten thousand messages cannot pay
        // for on every read. A row the caller may not see makes the answer
        // `complete: false`, as before.
        query.limit = Some(
            offset
                .saturating_add(limit)
                .saturating_add(1)
                .min(convert::SCAN_CAP + 1),
        );

        let result = host
            .db
            .query(&query)
            .await
            .map_err(|e| classify(e.to_string()))?;

        let truncated = result.subjects.len() > convert::SCAN_CAP;
        // Bodies are needed to ask the Installation's agent too. A missing body
        // is a row that could not be checked, which is not complete either.
        let mut incomplete =
            truncated || result.resources.len() < result.subjects.len().min(convert::SCAN_CAP);

        let mut visible = Vec::new();
        for resource in result.resources.into_iter().take(convert::SCAN_CAP) {
            match host.core.grant().check_read(&host.db, &resource).await {
                Ok(()) => visible.push(resource),
                Err(_) => incomplete = true,
            }
        }

        let end = offset.saturating_add(limit).min(visible.len());
        let page: Vec<_> = visible
            .get(offset.min(end)..end)
            .unwrap_or_default()
            .to_vec();
        let cursor = (end < visible.len()).then(|| end.to_string());

        Ok(Page {
            subjects: page.iter().map(|r| r.get_subject().to_string()).collect(),
            resources: if q.with_resources {
                page.iter().map(to_wit_resource).collect()
            } else {
                Vec::new()
            },
            // A page that is not the last one is a piece of the answer, not the
            // answer; a hidden or unchecked member makes it partial for good.
            complete: !incomplete && cursor.is_none(),
            cursor,
        })
    }

    async fn search(
        &mut self,
        _text: String,
        _class: Option<String>,
        _limit: u32,
    ) -> Result<Vec<String>, HostError> {
        Err(error(
            code::UNSUPPORTED,
            "search is not available on the host ABI yet",
        ))
    }

    async fn subscribe(&mut self, _q: QuerySpec) -> Result<String, HostError> {
        Err(error(
            code::UNSUPPORTED,
            "subscribe is not available on the host ABI yet",
        ))
    }

    async fn unsubscribe(&mut self, _subscription: String) {}

    async fn apply(&mut self, intents: Vec<Intent>) -> Result<Applied, HostError> {
        if intents.is_empty() || intents.len() > MAX_INTENTS {
            return Err(error(
                code::INVALID_ARGUMENT,
                format!("apply takes 1..={MAX_INTENTS} intents"),
            ));
        }
        let verdict = intents_to_verdict(&intents)?;
        let host = &self.host;
        // A chain limited to reads, or vouched for by a node that may not
        // write, never writes, whatever the export that got here is called.
        if !host.budget.may_write() {
            return Err(error(
                code::FORBIDDEN,
                "this call may not write: its effects leave out 'write'",
            ));
        }
        if host.budget.has_voucher() {
            let drive = host
                .db
                .get_resource(&host.drive.as_str().into())
                .await
                .map_err(|e| error(code::FORBIDDEN, e.to_string()))?;
            host.budget.check_vouch_write(&host.db, &drive).await?;
        }
        let caller = host.core.grant().caller().clone();

        let mut writer = StoreApplyHost::for_installation(
            &host.db,
            &host.drive,
            &host.installation,
            caller.clone(),
        )
        .await
        .map_err(classify)?;

        let plan = plan_verdict(&verdict, &mut writer).await;
        let refused = |problems: Vec<Problem>| Applied {
            outcome: Outcome::Refused,
            created: Vec::new(),
            problems,
            undo_token: None,
        };

        // 1. The plan itself is wrong: nothing to commit.
        if plan.blocked {
            return Ok(refused(plan_problems(&plan)));
        }
        if let Some(subject) = touches_protected(&host.db, &plan).await {
            return Ok(refused(vec![problem(
                "an app cannot change an Installation, a plugin or a Release",
                Some(subject),
            )]));
        }

        // 2. Both the caller and the Installation's own agent must be able to
        //    write there; the first that cannot is the reason. An
        //    installation without a key has no identity to write as.
        if writer.signing_as.is_none() {
            return Ok(refused(vec![problem(
                "this installation has no identity of its own to write as",
                None,
            )]));
        }
        for target in write_targets(&plan) {
            if let Err(e) = writer.may_write(&target).await {
                return Ok(refused(vec![problem(e, Some(target))]));
            }
        }

        // 3. Write it, as the Installation.
        let report = match apply_plan(&plan, &mut writer, ApplyOptions::default()).await {
            Ok(report) => report,
            Err(e) => return Ok(refused(vec![problem(e, None)])),
        };
        if report.failed > 0 || report.stopped_early {
            let mut problems: Vec<Problem> = report
                .outcomes
                .iter()
                .filter_map(|o| {
                    o.error
                        .as_ref()
                        .map(|e| problem(e.clone(), Some(o.planned.clone())))
                })
                .collect();
            problems.push(problem(
                format!(
                    "{} change(s) were applied before one failed; the rest were not attempted",
                    report.applied
                ),
                None,
            ));
            return Ok(refused(problems));
        }

        let asked: std::collections::HashMap<String, String> = intents
            .iter()
            .filter_map(|intent| match intent {
                Intent::Create(create) => Some((
                    create
                        .local_id
                        .strip_prefix("local:")
                        .unwrap_or(&create.local_id)
                        .to_string(),
                    create.local_id.clone(),
                )),
                _ => None,
            })
            .collect();
        let created = plan
            .changes
            .iter()
            .filter(|c| c.op == Op::Create)
            .filter_map(|c| {
                let local = c.local_id.as_ref()?;
                let real = report
                    .subjects
                    .get(&c.subject)
                    .cloned()
                    .unwrap_or_else(|| c.subject.clone());
                Some((
                    asked.get(local).cloned().unwrap_or_else(|| local.clone()),
                    real,
                ))
            })
            .collect();

        Ok(Applied {
            outcome: Outcome::Committed,
            created,
            problems: plan_problems(&plan),
            undo_token: None,
        })
    }

    async fn undo(&mut self, _undo_token: String) -> Result<(), HostError> {
        Err(error(
            code::UNSUPPORTED,
            "undo is not available on the host ABI yet",
        ))
    }
}
