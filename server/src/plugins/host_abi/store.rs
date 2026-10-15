//! `atomic:host/store`: reads, queries, subscriptions and `apply`.
//!
//! Every read goes through [`HostCore`]'s grant (the caller and the
//! Installation's agent must both be able to read). Every write is planned by
//! [`plan_verdict`] and applied by [`apply_plan`] through [`StoreApplyHost`],
//! signed by the Installation's agent.

use atomic_lib::{agents::ForAgent, hierarchy::check_write, urls, Db, Storelike};

use super::{
    bindings::atomic::host::{
        store::{self, Applied, Intent, Outcome, Page, QuerySpec},
        types::{Problem, Resource as WitResource, Severity},
    },
    classify, code,
    convert::{self, check_spec, intents_to_verdict, to_query, to_wit_resource},
    error,
    registry::{Proposal, SUBSCRIPTION_CAP},
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

/// Refuses unless `agent` may write `subject`.
async fn may_write(db: &Db, subject: &str, agent: &ForAgent) -> Result<(), String> {
    let resource = db
        .get_resource(&subject.into())
        .await
        .map_err(|e| format!("{subject} could not be read: {e}"))?;
    check_write(db, &resource, agent)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
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

        let mut query = to_query(&host.db, &q, &host.app.drive).await?;
        query.for_agent = host.core.grant().caller().clone();
        query.limit = Some(convert::SCAN_CAP + 1);

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

        let end = (offset + limit).min(visible.len());
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

    async fn subscribe(&mut self, q: QuerySpec) -> Result<String, HostError> {
        check_spec(&q)?;
        // Resolves the properties now, so a bad query fails here and not
        // silently never fires.
        to_query(&self.host.db, &q, &self.host.app.drive).await?;
        self.host
            .registry
            .subscribe(&self.host.app.drive, &self.host.app.installation, q)
            .map_err(|e| {
                error(
                    code::INVALID_ARGUMENT,
                    format!("{e} (limit {SUBSCRIPTION_CAP})"),
                )
            })
    }

    async fn unsubscribe(&mut self, subscription: String) {
        self.host.registry.unsubscribe(
            &self.host.app.drive,
            &self.host.app.installation,
            &subscription,
        );
    }

    async fn apply(&mut self, intents: Vec<Intent>) -> Result<Applied, HostError> {
        if intents.is_empty() || intents.len() > MAX_INTENTS {
            return Err(error(
                code::INVALID_ARGUMENT,
                format!("apply takes 1..={MAX_INTENTS} intents"),
            ));
        }
        let verdict = intents_to_verdict(&intents)?;
        let host = &self.host;
        let caller = host.core.grant().caller().clone();

        let mut writer = StoreApplyHost::for_installation(
            &host.db,
            &host.app.drive,
            &host.app.installation,
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

        // 1. The plan itself is wrong: nothing to commit or propose.
        if plan.blocked {
            return Ok(refused(plan_problems(&plan)));
        }
        if let Some(subject) = touches_protected(&host.db, &plan).await {
            return Ok(refused(vec![problem(
                "an app cannot change an Installation, a plugin or a Release",
                Some(subject),
            )]));
        }

        // 2. The caller may not write there: refused, not proposed. A proposal
        //    is for work the caller is entitled to ask for. When the caller is
        //    the app itself (another app called it) there is no separate
        //    caller to ask: only the app's own grant decides, below.
        let targets = write_targets(&plan);
        let app_agent = match &writer.signing_as {
            Some(key) => host
                .db
                .get_app_agent_info(key)
                .ok()
                .flatten()
                .map(|info| ForAgent::AgentSubject(info.agent.into())),
            None => None,
        };
        if app_agent.as_ref() != Some(&caller) {
            for target in &targets {
                if let Err(e) = may_write(&host.db, target, &caller).await {
                    return Ok(refused(vec![problem(e, Some(target.clone()))]));
                }
            }
        }

        // 3. The Installation's own agent may not write there (or it has none):
        //    the work is kept as a proposal and nothing is written.
        let why_not = match &app_agent {
            None => Some("this installation has no identity of its own to write as".to_string()),
            Some(agent) => {
                let mut first = None;
                for target in &targets {
                    if let Err(e) = may_write(&host.db, target, agent).await {
                        first = Some(format!("the installation may not write {target}: {e}"));
                        break;
                    }
                }
                first
            }
        };
        if let Some(reason) = why_not {
            host.registry.keep_proposal(Proposal {
                drive: host.app.drive.clone(),
                installation: host.app.installation.clone(),
                caller: format!("{caller:?}"),
                at_ms: atomic_lib::utils::now(),
                verdict,
            });
            let mut problems = plan_problems(&plan);
            problems.push(Problem {
                severity: Severity::Warning,
                message: format!("kept as a proposal, nothing was written: {reason}"),
                subject: None,
                property: None,
            });
            return Ok(Applied {
                outcome: Outcome::Proposed,
                created: Vec::new(),
                problems,
                undo_token: None,
            });
        }

        // 4. Both may: write it, as the Installation.
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
