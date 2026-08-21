//! Turning a verdict into a plan, server-side.
//!
//! The counterpart to `plugin-plan.ts`. Two planners exist because neither can
//! do the other's job: the browser plans offline against a local store, on
//! drives that never reach a server, and this one plans for runs nobody is
//! watching. They are held together by `testdata/plugin-plans`, because a
//! planner that disagrees with the one that drew the preview means the changes
//! someone approved are not the changes that were made.

use std::collections::{HashMap, HashSet};

use atomic_lib::{datatype::match_datatype, Value};
use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

/// Serialized into the run log, so its shape is the browser's: the same
/// records render in the same UI whichever planner produced them.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Problem {
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

impl Problem {
    fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            subject: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Create,
    Set,
    Remove,
    Destroy,
}

#[derive(Debug, Clone)]
pub struct PlannedProperty {
    pub property: String,
    pub shortname: Option<String>,
    pub from: Option<Json>,
    pub to: Option<Json>,
}

#[derive(Debug, Clone)]
pub struct PlannedChange {
    pub op: Op,
    pub subject: String,
    pub local_id: Option<String>,
    pub parent: Option<String>,
    pub is_a: Vec<String>,
    pub properties: Vec<PlannedProperty>,
    pub problems: Vec<Problem>,
}

#[derive(Debug, Default)]
pub struct RunPlan {
    pub changes: Vec<PlannedChange>,
    pub problems: Vec<Problem>,
    /// localId to the subject minted for it.
    pub minted: HashMap<String, String>,
    pub blocked: bool,
    pub cursor: Option<String>,
}

/// What planning needs from a store.
#[async_trait::async_trait]
pub trait PlanHost: Send {
    fn create_subject(&mut self, parent: &str) -> String;
    /// Datatype and shortname, or `None` when no such property exists.
    async fn get_property(&mut self, subject: &str) -> Option<(String, String)>;
    /// Current values, or `None` when the resource does not exist.
    async fn read_resource(&mut self, subject: &str) -> Option<HashMap<String, Json>>;
}

const LOCAL_PREFIX: &str = "local:";

#[derive(Debug, Clone)]
struct Intent {
    op: Op,
    local_id: Option<String>,
    subject: Option<String>,
    parent: Option<String>,
    is_a: Vec<String>,
    set: Vec<(String, Json)>,
    remove: Vec<String>,
}

/// Normalizes whatever the runtime returned.
///
/// Same posture as `parseVerdict`: the plugin is as likely to have been written
/// by a model as by a person, so anything malformed is dropped and reported
/// rather than trusted.
fn parse_verdict(raw: &Json) -> (Vec<Intent>, Vec<Problem>, Option<String>) {
    let mut problems = Vec::new();

    let Some(object) = raw.as_object() else {
        return (
            Vec::new(),
            vec![Problem::error(
                "run() did not return an object with { intents, problems }",
            )],
            None,
        );
    };

    if let Some(reported) = object.get("problems").and_then(|p| p.as_array()) {
        for entry in reported {
            let Some(message) = entry.get("message").and_then(|m| m.as_str()) else {
                problems.push(Problem::error("a reported problem has no message"));

                continue;
            };

            // Anything a plugin reports blocks unless it opted into a warning:
            // a validator that meant to reject should not be downgraded by a
            // typo in `severity`.
            let severity = match entry.get("severity").and_then(|s| s.as_str()) {
                Some("warning") => Severity::Warning,
                _ => Severity::Error,
            };

            problems.push(Problem {
                severity,
                message: message.to_string(),
                subject: entry
                    .get("subject")
                    .and_then(|s| s.as_str())
                    .map(str::to_string),
            });
        }
    }

    let mut intents = Vec::new();
    let mut local_ids = HashSet::new();

    if let Some(raw_intents) = object.get("intents").and_then(|i| i.as_array()) {
        for (index, entry) in raw_intents.iter().enumerate() {
            match parse_intent(entry, index, &mut local_ids) {
                Ok(intent) => intents.push(intent),
                Err(problem) => problems.push(problem),
            }
        }
    }

    // A reference to a create nobody makes would have the host mint a subject
    // for a resource that never exists, so the intent goes rather than the link.
    let known: HashSet<String> = intents.iter().filter_map(|i| i.local_id.clone()).collect();

    intents.retain(|intent| {
        let dangling: Vec<String> = local_refs(intent)
            .into_iter()
            .filter(|name| !known.contains(name))
            .collect();

        if dangling.is_empty() {
            return true;
        }

        problems.push(Problem::error(format!(
            "intent references {}, which no create intent defines",
            dangling
                .iter()
                .map(|name| format!("\"{LOCAL_PREFIX}{name}\""))
                .collect::<Vec<_>>()
                .join(", "),
        )));

        false
    });

    let cursor = object
        .get("cursor")
        .and_then(|c| c.as_str())
        .map(str::to_string);

    (intents, problems, cursor)
}

fn parse_intent(
    entry: &Json,
    index: usize,
    local_ids: &mut HashSet<String>,
) -> Result<Intent, Problem> {
    let at = format!("intents[{index}]");
    let object = entry
        .as_object()
        .ok_or_else(|| Problem::error(format!("{at} is not an object")))?;

    let set = || -> Vec<(String, Json)> {
        object
            .get("set")
            .and_then(|s| s.as_object())
            .map(|map| {
                map.iter()
                    .filter(|(_, value)| !value.is_null())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    };

    let subject = || {
        object
            .get("subject")
            .and_then(|s| s.as_str())
            .map(str::to_string)
    };

    match object.get("op").and_then(|o| o.as_str()) {
        Some("create") => {
            let local_id = object
                .get("localId")
                .and_then(|l| l.as_str())
                .filter(|l| !l.is_empty())
                .ok_or_else(|| Problem::error(format!("{at} create needs a localId")))?;

            if !local_ids.insert(local_id.to_string()) {
                return Err(Problem::error(format!(
                    "{at} reuses localId \"{local_id}\"; references to it would be ambiguous",
                )));
            }

            let parent = object
                .get("parent")
                .and_then(|p| p.as_str())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| Problem::error(format!("{at} create needs a parent")))?;

            Ok(Intent {
                op: Op::Create,
                local_id: Some(local_id.to_string()),
                subject: None,
                parent: Some(parent.to_string()),
                is_a: object
                    .get("isA")
                    .and_then(|c| c.as_array())
                    .map(|list| {
                        list.iter()
                            .filter_map(|c| c.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                set: set(),
                remove: Vec::new(),
            })
        }
        Some("set") => Ok(Intent {
            op: Op::Set,
            local_id: None,
            subject: Some(
                subject().ok_or_else(|| Problem::error(format!("{at} set needs a subject")))?,
            ),
            parent: None,
            is_a: Vec::new(),
            set: set(),
            remove: Vec::new(),
        }),
        Some("remove") => Ok(Intent {
            op: Op::Remove,
            local_id: None,
            subject: Some(
                subject().ok_or_else(|| Problem::error(format!("{at} remove needs a subject")))?,
            ),
            parent: None,
            is_a: Vec::new(),
            set: Vec::new(),
            remove: object
                .get("properties")
                .and_then(|p| p.as_array())
                .map(|list| {
                    list.iter()
                        .filter_map(|p| p.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        }),
        Some("destroy") => Ok(Intent {
            op: Op::Destroy,
            local_id: None,
            subject: Some(
                subject().ok_or_else(|| Problem::error(format!("{at} destroy needs a subject")))?,
            ),
            parent: None,
            is_a: Vec::new(),
            set: Vec::new(),
            remove: Vec::new(),
        }),
        other => Err(Problem::error(format!("{at} has unknown op {other:?}"))),
    }
}

fn local_refs(intent: &Intent) -> Vec<String> {
    let mut refs = Vec::new();

    if let Some(parent) = &intent.parent {
        if let Some(name) = parent.strip_prefix(LOCAL_PREFIX) {
            refs.push(name.to_string());
        }
    }

    for (_, value) in &intent.set {
        collect_local_refs(value, &mut refs);
    }

    refs
}

fn collect_local_refs(value: &Json, out: &mut Vec<String>) {
    match value {
        Json::String(text) => {
            if let Some(name) = text.strip_prefix(LOCAL_PREFIX) {
                out.push(name.to_string());
            }
        }
        Json::Array(items) => items.iter().for_each(|i| collect_local_refs(i, out)),
        Json::Object(map) => map.values().for_each(|v| collect_local_refs(v, out)),
        _ => {}
    }
}

fn rewrite(value: &Json, minted: &HashMap<String, String>) -> Json {
    match value {
        Json::String(text) => match text.strip_prefix(LOCAL_PREFIX) {
            Some(name) => minted
                .get(name)
                .map(|s| Json::String(s.clone()))
                .unwrap_or_else(|| value.clone()),
            None => value.clone(),
        },
        Json::Array(items) => Json::Array(items.iter().map(|i| rewrite(i, minted)).collect()),
        Json::Object(map) => Json::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), rewrite(v, minted)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Plans a verdict: mints subjects, resolves references, checks the schema.
pub async fn plan_verdict<H: PlanHost>(raw: &Json, host: &mut H) -> RunPlan {
    let (intents, mut problems, cursor) = parse_verdict(raw);

    // Parents first: a create whose parent is another create has to wait for
    // that subject to exist. Creates in a cycle can never be minted.
    let mut minted: HashMap<String, String> = HashMap::new();
    let mut pending: Vec<&Intent> = intents.iter().filter(|i| i.op == Op::Create).collect();
    let mut progressed = true;

    while !pending.is_empty() && progressed {
        progressed = false;

        pending.retain(|create| {
            let parent = create.parent.as_deref().unwrap_or_default();

            let resolved = match parent.strip_prefix(LOCAL_PREFIX) {
                Some(name) => match minted.get(name) {
                    Some(subject) => subject.clone(),
                    None => return true,
                },
                None => parent.to_string(),
            };

            let subject = host.create_subject(&resolved);
            minted.insert(create.local_id.clone().unwrap_or_default(), subject);
            progressed = true;

            false
        });
    }

    let stuck: HashSet<String> = pending.iter().filter_map(|i| i.local_id.clone()).collect();

    if !stuck.is_empty() {
        let mut names: Vec<String> = stuck.iter().cloned().collect();
        names.sort();

        problems.push(Problem::error(format!(
            "these resources are each other's parent, so none of them can be created: {}",
            names.join(", "),
        )));
    }

    let mut changes = Vec::new();

    for intent in &intents {
        if intent.op == Op::Create && stuck.contains(intent.local_id.as_deref().unwrap_or_default())
        {
            continue;
        }

        changes.push(plan_intent(intent, &minted, host).await);
    }

    let blocked = problems.iter().any(|p| p.severity == Severity::Error)
        || changes
            .iter()
            .any(|c| c.problems.iter().any(|p| p.severity == Severity::Error));

    RunPlan {
        changes,
        problems,
        minted,
        blocked,
        cursor,
    }
}

async fn plan_intent<H: PlanHost>(
    intent: &Intent,
    minted: &HashMap<String, String>,
    host: &mut H,
) -> PlannedChange {
    let subject = match intent.op {
        Op::Create => minted
            .get(intent.local_id.as_deref().unwrap_or_default())
            .cloned()
            .unwrap_or_default(),
        _ => intent.subject.clone().unwrap_or_default(),
    };

    let mut change = PlannedChange {
        op: intent.op.clone(),
        subject: subject.clone(),
        local_id: intent.local_id.clone(),
        parent: intent.parent.as_ref().map(|p| {
            rewrite(&Json::String(p.clone()), minted)
                .as_str()
                .unwrap_or(p)
                .to_string()
        }),
        is_a: intent.is_a.clone(),
        properties: Vec::new(),
        problems: Vec::new(),
    };

    if intent.op == Op::Create {
        if intent.is_a.is_empty() {
            change.problems.push(Problem {
                severity: Severity::Warning,
                message: "created without a class, so nothing will validate it later".to_string(),
                subject: Some(subject.clone()),
            });
        }

        check_properties(intent, None, &mut change, minted, host).await;

        return change;
    }

    let current = host.read_resource(&subject).await;

    let Some(current) = current else {
        change.problems.push(Problem {
            severity: Severity::Error,
            message: format!("{subject} does not exist, so it cannot be changed"),
            subject: Some(subject),
        });

        return change;
    };

    match intent.op {
        Op::Destroy => change,
        Op::Remove => {
            for property in &intent.remove {
                match current.get(property) {
                    None => change.problems.push(Problem {
                        severity: Severity::Warning,
                        message: "is not set, so removing it does nothing".to_string(),
                        subject: Some(subject.clone()),
                    }),
                    Some(from) => change.properties.push(PlannedProperty {
                        property: property.clone(),
                        shortname: None,
                        from: Some(from.clone()),
                        to: None,
                    }),
                }
            }

            change
        }
        _ => {
            check_properties(intent, Some(&current), &mut change, minted, host).await;

            change
        }
    }
}

async fn check_properties<H: PlanHost>(
    intent: &Intent,
    current: Option<&HashMap<String, Json>>,
    change: &mut PlannedChange,
    minted: &HashMap<String, String>,
    host: &mut H,
) {
    for (property, raw_value) in &intent.set {
        let Some((datatype, shortname)) = host.get_property(property).await else {
            change.problems.push(Problem {
                severity: Severity::Error,
                message: format!("no property {property} exists, so this value has nowhere to go"),
                subject: Some(change.subject.clone()),
            });

            continue;
        };

        let value = rewrite(raw_value, minted);

        if let Err(e) = check_datatype(&value, &datatype) {
            change.problems.push(Problem {
                severity: Severity::Error,
                message: format!("{shortname} expects {datatype}: {e}"),
                subject: Some(change.subject.clone()),
            });

            continue;
        }

        let from = current.and_then(|c| c.get(property)).cloned();

        if from.as_ref() == Some(&value) {
            change.problems.push(Problem {
                severity: Severity::Warning,
                message: format!("{shortname} already has this value"),
                subject: Some(change.subject.clone()),
            });

            continue;
        }

        change.properties.push(PlannedProperty {
            property: property.clone(),
            shortname: Some(shortname),
            from,
            to: Some(value),
        });
    }
}

/// Whether a JSON value fits a datatype.
///
/// A JSON number stays a number rather than being stringified into one: `"42"`
/// is a string a plugin meant as text, and letting it satisfy an integer would
/// make this planner more permissive than the browser's.
fn check_datatype(value: &Json, datatype: &str) -> Result<(), String> {
    use atomic_lib::datatype::DataType;

    let expected = match_datatype(datatype);

    match (&expected, value) {
        (DataType::Integer | DataType::Timestamp, Json::Number(n)) if n.is_i64() => Ok(()),
        (DataType::Float, Json::Number(_)) => Ok(()),
        (DataType::Boolean, Json::Bool(_)) => Ok(()),
        (DataType::ResourceArray, Json::Array(_)) => Ok(()),
        (DataType::Json | DataType::LocalizedText, _) => Ok(()),
        (_, Json::String(text)) => Value::new(text, &expected)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        _ => Err(format!("{value} is not a {datatype}")),
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    /// The shared plan corpus, run against this planner.
    ///
    /// The same files are run by `plugin-plan.fixtures.test.ts`. When these two
    /// disagree, one of them is about to write changes a person did not
    /// approve — see `testdata/plugin-plans/README.md`.
    struct FixtureHost {
        schema: HashMap<String, (String, String)>,
        resources: HashMap<String, HashMap<String, Json>>,
        minted: usize,
    }

    #[async_trait::async_trait]
    impl PlanHost for FixtureHost {
        fn create_subject(&mut self, parent: &str) -> String {
            self.minted += 1;

            format!("{parent}/minted-{}", self.minted)
        }

        async fn get_property(&mut self, subject: &str) -> Option<(String, String)> {
            self.schema.get(subject).cloned()
        }

        async fn read_resource(&mut self, subject: &str) -> Option<HashMap<String, Json>> {
            self.resources.get(subject).cloned()
        }
    }

    fn fixtures() -> Vec<(String, Json)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("testdata/plugin-plans");

        let mut found: Vec<(String, Json)> = std::fs::read_dir(&dir)
            .expect("the plan corpus is readable")
            .filter_map(|entry| {
                let path = entry.ok()?.path();

                if path.extension()? != "json" {
                    return None;
                }

                let text = std::fs::read_to_string(&path).ok()?;

                Some((
                    path.file_name()?.to_string_lossy().into_owned(),
                    serde_json::from_str(&text).expect("a fixture is valid JSON"),
                ))
            })
            .collect();

        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }

    #[tokio::test]
    async fn the_corpus_agrees_with_this_planner() {
        let all = fixtures();

        // A corpus that silently matched nothing would report success for
        // having pinned nothing at all.
        assert!(!all.is_empty(), "no plan fixtures were found");

        for (file, fixture) in all {
            let mut host = FixtureHost {
                schema: fixture["schema"]
                    .as_object()
                    .map(|map| {
                        map.iter()
                            .map(|(k, v)| {
                                (
                                    k.clone(),
                                    (
                                        v["datatype"].as_str().unwrap().to_string(),
                                        v["shortname"].as_str().unwrap().to_string(),
                                    ),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                resources: fixture["resources"]
                    .as_object()
                    .map(|map| {
                        map.iter()
                            .map(|(k, v)| {
                                (
                                    k.clone(),
                                    v.as_object()
                                        .map(|props| {
                                            props
                                                .iter()
                                                .map(|(pk, pv)| (pk.clone(), pv.clone()))
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                minted: 0,
            };

            let plan = plan_verdict(&fixture["verdict"], &mut host).await;
            let expect = &fixture["expect"];

            assert_eq!(
                plan.blocked,
                expect["blocked"].as_bool().unwrap(),
                "{file}: blocked",
            );

            let messages: Vec<String> = plan
                .problems
                .iter()
                .chain(plan.changes.iter().flat_map(|c| c.problems.iter()))
                .map(|p| p.message.clone())
                .collect();

            for expected in expect["problems"].as_array().unwrap() {
                let needle = expected.as_str().unwrap();

                assert!(
                    messages.iter().any(|m| m.contains(needle)),
                    "{file}: no problem mentioned {needle:?}; got {messages:?}",
                );
            }

            let expected_changes = expect["changes"].as_array().unwrap();

            assert_eq!(
                plan.changes.len(),
                expected_changes.len(),
                "{file}: number of changes",
            );

            for (index, expected) in expected_changes.iter().enumerate() {
                let change = &plan.changes[index];

                assert_eq!(
                    format!("{:?}", change.op).to_lowercase(),
                    expected["op"].as_str().unwrap(),
                    "{file}: change {index} op",
                );

                if let Some(local_id) = expected["localId"].as_str() {
                    assert_eq!(change.local_id.as_deref(), Some(local_id), "{file}");
                }

                if let Some(subject) = expected["subject"].as_str() {
                    assert_eq!(change.subject, subject, "{file}");
                }

                let expected_properties = expected["properties"].as_array().unwrap();

                assert_eq!(
                    change.properties.len(),
                    expected_properties.len(),
                    "{file}: change {index} properties",
                );

                for (i, expected_property) in expected_properties.iter().enumerate() {
                    let property = &change.properties[i];

                    assert_eq!(
                        property.property,
                        expected_property["property"].as_str().unwrap(),
                        "{file}",
                    );

                    if !expected_property["from"].is_null() {
                        assert_eq!(
                            property.from.as_ref(),
                            Some(&expected_property["from"]),
                            "{file}: from",
                        );
                    }

                    if let Some(local_id) = expected_property["toMintedFor"].as_str() {
                        // The subject is minted, so the fixture pins that it
                        // points at the right create rather than at a literal.
                        assert_eq!(
                            property.to.as_ref().and_then(|v| v.as_str()),
                            plan.minted.get(local_id).map(String::as_str),
                            "{file}: minted reference",
                        );
                    } else if !expected_property["to"].is_null() {
                        assert_eq!(
                            property.to.as_ref(),
                            Some(&expected_property["to"]),
                            "{file}: to",
                        );
                    }
                }
            }
        }
    }
}
