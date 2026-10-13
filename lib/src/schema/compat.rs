//! What a schema edit does to the data written under the old schema.
//!
//! [`fingerprint`] hashes the *contract* of a schema: the ontology, the
//! property IDs, and per class what it requires, recommends, the classtype of
//! its properties and its constraints. Names and descriptions are cosmetic and
//! stay out, so a reworded description does not move it. [`diff`] says how two
//! versions of a schema differ, as a list of [`Change`]s of three [`Level`]s.
//!
//! The lockfile pins the fingerprint (`lockfile.rs`) and `@tomic/lib` computes
//! the same hash (`browser/lib/src/schema-lockfile.ts`); both run
//! `lib/tests/fixtures/schema-lockfile.json`, so change them together. `diff`
//! has no TypeScript twin. See `docs/src/schema/json-schema.md`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde_json::{json, Map, Value as Json};

use super::json_schema::{check_plan, OntologyPlan};
use crate::{
    errors::AtomicResult, identifiers::canonicalize_scheme, property_identity::property_id,
};

/// Domain separation for fingerprints, like the one for property IDs.
const FINGERPRINT_CONTEXT: &str = "atomic schema fingerprint v1";

/// How much a [`Change`] matters to data and readers of the old schema. The
/// order is the severity, so callers can take the maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Existing data stays valid and readers keep working: a new optional
    /// property, a new class, a constraint that got looser (minimum lowered,
    /// maximum raised, enum value added, `additionalProperties: false` removed,
    /// required to recommended).
    Compatible,
    /// The property IDs are the same, but existing data may now fail the class
    /// constraints: a new required property, recommended to required, a
    /// minimum raised or maximum lowered (also the exclusive, length and item
    /// variants), an enum value removed, a `const` or `pattern` added,
    /// `additionalProperties` set to false. A constraint that changed in a way
    /// that has no direction (a different `pattern`, `anyOf`) counts here too.
    Tightening,
    /// Data written under the old schema is no longer read by the new one: a
    /// property removed from a class, a class removed, a property whose
    /// datatype or shortname changed (that is a new property ID, the old
    /// values stay under the old ID), a changed classtype.
    Breaking,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Level::Compatible => "compatible",
            Level::Tightening => "tightening",
            Level::Breaking => "breaking",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub level: Level,
    /// Class shortname. `None` for a change to the ontology or a property as a whole.
    pub class: Option<String>,
    /// Property shortname.
    pub property: Option<String>,
    pub detail: String,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.level)?;
        match (&self.class, &self.property) {
            (Some(c), Some(p)) => write!(f, "{c}.{p}: ")?,
            (Some(c), None) => write!(f, "{c}: ")?,
            (None, Some(p)) => write!(f, "property {p}: ")?,
            (None, None) => {}
        }
        f.write_str(&self.detail)
    }
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

struct PropertyContract {
    id: String,
    datatype: String,
    classtype: Option<String>,
}

struct ClassContract {
    requires: BTreeSet<String>,
    recommends: BTreeSet<String>,
    /// `None`: the plan leaves the constraints alone. Empty ones are dropped.
    constraints: Option<BTreeMap<String, Map<String, Json>>>,
}

/// A checked plan, keyed by shortname.
struct Contract {
    ontology: String,
    properties: BTreeMap<String, PropertyContract>,
    classes: BTreeMap<String, ClassContract>,
}

impl Contract {
    fn of(plan: &OntologyPlan, ontology: &str) -> AtomicResult<Contract> {
        let checked = check_plan(plan)?;
        let mut properties = BTreeMap::new();
        for p in &checked.properties {
            properties.insert(
                p.shortname.clone(),
                PropertyContract {
                    id: property_id(ontology, &p.shortname, &p.datatype)?,
                    datatype: p.datatype.clone(),
                    classtype: p.classtype.clone(),
                },
            );
        }
        let classes = checked
            .classes
            .iter()
            .map(|c| {
                let constraints = c.constraints.as_ref().map(|all| {
                    all.iter()
                        .filter(|(_, keywords)| !keywords.is_empty())
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                });
                (
                    c.shortname.clone(),
                    ClassContract {
                        requires: c.requires.iter().cloned().collect(),
                        recommends: c.recommends.iter().cloned().collect(),
                        constraints,
                    },
                )
            })
            .collect();
        Ok(Contract {
            ontology: canonicalize_scheme(ontology),
            properties,
            classes,
        })
    }

    fn id(&self, shortname: &str) -> &str {
        &self.properties[shortname].id
    }
}

/// `b3-{hex}`: a hash of the schema's contract, see the module docs. The same
/// for any ordering of classes and properties.
pub fn fingerprint(plan: &OntologyPlan, ontology: &str) -> AtomicResult<String> {
    let contract = Contract::of(plan, ontology)?;
    let ids = |names: &BTreeSet<String>| -> Vec<&str> {
        let mut ids: Vec<&str> = names.iter().map(|n| contract.id(n)).collect();
        ids.sort_unstable();
        ids
    };

    let mut classes = Map::new();
    for (shortname, class) in &contract.classes {
        let mut classtypes = Map::new();
        for name in class.requires.iter().chain(&class.recommends) {
            if let Some(classtype) = &contract.properties[name].classtype {
                classtypes.insert(contract.id(name).to_string(), json!(classtype));
            }
        }
        let constraints: Map<String, Json> = class
            .constraints
            .iter()
            .flatten()
            .map(|(name, keywords)| {
                (
                    contract.id(name).to_string(),
                    Json::Object(keywords.clone()),
                )
            })
            .collect();
        classes.insert(
            shortname.clone(),
            json!({
                "classtypes": classtypes,
                "constraints": constraints,
                "recommends": ids(&class.recommends),
                "requires": ids(&class.requires),
            }),
        );
    }
    let mut property_ids: Vec<&str> = contract
        .properties
        .values()
        .map(|p| p.id.as_str())
        .collect();
    property_ids.sort_unstable();

    let canonical = serde_jcs::to_string(&json!({
        "classes": classes,
        "ontology": contract.ontology,
        "properties": property_ids,
    }))
    .map_err(|e| format!("Could not canonicalize the schema contract: {e}"))?;
    let mut hasher = blake3::Hasher::new_derive_key(FINGERPRINT_CONTEXT);
    hasher.update(canonical.as_bytes());
    Ok(format!("b3-{}", hasher.finalize().to_hex()))
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// How `new` differs from `old`, both read in `ontology`. Names and
/// descriptions are not compared. Empty when the contract is the same.
pub fn diff(old: &OntologyPlan, new: &OntologyPlan, ontology: &str) -> AtomicResult<Vec<Change>> {
    let (old, new) = (Contract::of(old, ontology)?, Contract::of(new, ontology)?);
    let mut out = Vec::new();
    let mut add = |level, class: Option<&str>, property: Option<&str>, detail: String| {
        out.push(Change {
            level,
            class: class.map(String::from),
            property: property.map(String::from),
            detail,
        });
    };

    // Properties as a whole: a new datatype is a new ID, the old values stay behind.
    for (name, was) in &old.properties {
        let Some(now) = new.properties.get(name) else {
            continue;
        };
        if was.datatype != now.datatype {
            add(
                Level::Breaking,
                None,
                Some(name),
                format!(
                    "datatype changed from {} to {}. That is a new property ID ({}), the old values stay under the old ID ({})",
                    was.datatype, now.datatype, now.id, was.id
                ),
            );
        } else if was.classtype != now.classtype {
            add(
                Level::Breaking,
                None,
                Some(name),
                format!(
                    "classtype changed from {} to {}",
                    was.classtype.as_deref().unwrap_or("none"),
                    now.classtype.as_deref().unwrap_or("none")
                ),
            );
        }
    }
    for name in old.properties.keys() {
        let used_before = old
            .classes
            .values()
            .any(|c| c.requires.contains(name) || c.recommends.contains(name));
        if !new.properties.contains_key(name) && !used_before {
            add(Level::Breaking, None, Some(name), "property removed".into());
        }
    }

    for class in old.classes.keys() {
        if !new.classes.contains_key(class) {
            add(Level::Breaking, Some(class), None, "class removed".into());
        }
    }
    for (class, now) in &new.classes {
        let Some(was) = old.classes.get(class) else {
            add(Level::Compatible, Some(class), None, "class added".into());
            continue;
        };
        let level_of = |c: &ClassContract, p: &str| {
            if c.requires.contains(p) {
                Some("required")
            } else if c.recommends.contains(p) {
                Some("recommended")
            } else {
                None
            }
        };
        let names: BTreeSet<&String> = [
            &was.requires,
            &was.recommends,
            &now.requires,
            &now.recommends,
        ]
        .into_iter()
        .flatten()
        .collect();
        for name in names {
            match (level_of(was, name), level_of(now, name)) {
                (Some(_), None) => add(
                    Level::Breaking,
                    Some(class),
                    Some(name),
                    "property removed from the class. Data under it is no longer read".into(),
                ),
                (None, Some(kind)) => add(
                    if kind == "required" {
                        Level::Tightening
                    } else {
                        Level::Compatible
                    },
                    Some(class),
                    Some(name),
                    format!("{kind} property added"),
                ),
                (Some("recommended"), Some("required")) => add(
                    Level::Tightening,
                    Some(class),
                    Some(name),
                    "recommended -> required".into(),
                ),
                (Some("required"), Some("recommended")) => add(
                    Level::Compatible,
                    Some(class),
                    Some(name),
                    "required -> recommended".into(),
                ),
                _ => {}
            }
            // Constraints only matter where the property stays, and where the
            // new plan manages them at all.
            if level_of(was, name).is_some() && level_of(now, name).is_some() {
                if let Some(now_all) = &now.constraints {
                    let empty = Map::new();
                    let before = was
                        .constraints
                        .as_ref()
                        .and_then(|c| c.get(name))
                        .unwrap_or(&empty);
                    let after = now_all.get(name).unwrap_or(&empty);
                    diff_keywords(before, after, "", &mut |level, detail| {
                        add(level, Some(class), Some(name), detail)
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Compares the keywords of two constraints (or two nested schemas). `path`
/// names where we are, for the detail.
fn diff_keywords(
    old: &Map<String, Json>,
    new: &Map<String, Json>,
    path: &str,
    emit: &mut dyn FnMut(Level, String),
) {
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for key in keys {
        let (a, b) = (old.get(key), new.get(key));
        if a == b {
            continue;
        }
        let at = |what: String| located(path, what);
        let unknown = |emit: &mut dyn FnMut(Level, String)| {
            emit(
                Level::Tightening,
                at(format!("{key} changed, the direction is unknown")),
            );
        };
        match (key.as_str(), a, b) {
            // A lower bound: raising it tightens.
            ("minimum" | "exclusiveMinimum" | "minLength" | "minItems", a, b) => {
                bound(key, a, b, true, path, emit)
            }
            ("maximum" | "exclusiveMaximum" | "maxLength" | "maxItems", a, b) => {
                bound(key, a, b, false, path, emit)
            }
            ("const", None, Some(_)) | ("const", Some(_), Some(_)) => {
                emit(Level::Tightening, at("const added or changed".into()))
            }
            ("const", Some(_), None) => emit(Level::Compatible, at("const removed".into())),
            ("pattern", None, Some(_)) => emit(Level::Tightening, at("pattern added".into())),
            ("pattern", Some(_), None) => emit(Level::Compatible, at("pattern removed".into())),
            ("enum" | "type", a, b) => {
                let set = |v: Option<&Json>| -> Option<Vec<Json>> {
                    match v? {
                        Json::Array(items) => Some(items.clone()),
                        other => Some(vec![other.clone()]),
                    }
                };
                match (set(a), set(b)) {
                    (None, Some(_)) => emit(Level::Tightening, at(format!("{key} added"))),
                    (Some(_), None) => emit(Level::Compatible, at(format!("{key} removed"))),
                    (Some(before), Some(after)) => {
                        let removed: Vec<_> =
                            before.iter().filter(|v| !after.contains(v)).collect();
                        let added: Vec<_> = after.iter().filter(|v| !before.contains(v)).collect();
                        if !removed.is_empty() {
                            emit(
                                Level::Tightening,
                                at(format!("{key} value removed: {}", list(&removed))),
                            );
                        }
                        if !added.is_empty() {
                            emit(
                                Level::Compatible,
                                at(format!("{key} value added: {}", list(&added))),
                            );
                        }
                    }
                    (None, None) => {}
                }
            }
            ("required", a, b) => {
                let names = |v: Option<&Json>| -> Vec<Json> {
                    v.and_then(Json::as_array).cloned().unwrap_or_default()
                };
                let (before, after) = (names(a), names(b));
                let added: Vec<_> = after.iter().filter(|v| !before.contains(v)).collect();
                if !added.is_empty() {
                    emit(
                        Level::Tightening,
                        at(format!("required key added: {}", list(&added))),
                    );
                }
                if before.iter().any(|v| !after.contains(v)) {
                    emit(Level::Compatible, at("required key removed".into()));
                }
            }
            ("additionalProperties", a, b) => {
                let open = |v: Option<&Json>| v.is_none() || v == Some(&json!(true));
                match (a, b) {
                    (Some(Json::Object(x)), Some(Json::Object(y))) => {
                        diff_keywords(x, y, &nested(path, "additionalProperties"), emit)
                    }
                    (_, Some(Json::Bool(false))) => emit(
                        Level::Tightening,
                        at("additionalProperties set to false".into()),
                    ),
                    (Some(Json::Bool(false)), _) => emit(
                        Level::Compatible,
                        at("additionalProperties: false removed".into()),
                    ),
                    (_, Some(Json::Object(_))) if open(a) => emit(
                        Level::Tightening,
                        at("additionalProperties schema added".into()),
                    ),
                    (Some(Json::Object(_)), _) if open(b) => emit(
                        Level::Compatible,
                        at("additionalProperties schema removed".into()),
                    ),
                    _ => unknown(emit),
                }
            }
            ("properties", a, b) => {
                let empty = Map::new();
                let (x, y) = (
                    a.and_then(Json::as_object).unwrap_or(&empty),
                    b.and_then(Json::as_object).unwrap_or(&empty),
                );
                for name in x.keys().chain(y.keys()).collect::<BTreeSet<_>>() {
                    let sub = nested(path, &format!("properties.{name}"));
                    match (
                        x.get(name).and_then(Json::as_object),
                        y.get(name).and_then(Json::as_object),
                    ) {
                        (Some(p), Some(q)) => diff_keywords(p, q, &sub, emit),
                        (None, Some(q)) if !q.is_empty() => {
                            emit(Level::Tightening, located(&sub, "constraint added".into()))
                        }
                        (Some(p), None) if !p.is_empty() => emit(
                            Level::Compatible,
                            located(&sub, "constraint removed".into()),
                        ),
                        _ => {}
                    }
                }
            }
            ("items", Some(Json::Object(x)), Some(Json::Object(y))) => {
                diff_keywords(x, y, &nested(path, "items"), emit)
            }
            ("items", None, Some(_)) => emit(Level::Tightening, at("items added".into())),
            ("items", Some(_), None) => emit(Level::Compatible, at("items removed".into())),
            ("anyOf" | "class", Some(_), None) => {
                emit(Level::Compatible, at(format!("{key} removed")))
            }
            ("anyOf" | "class", None, Some(_)) => {
                emit(Level::Tightening, at(format!("{key} added")))
            }
            _ => unknown(emit),
        }
    }
}

/// `path` is where in a nested schema we are, empty at the top of a constraint.
fn nested(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn located(path: &str, what: String) -> String {
    if path.is_empty() {
        what
    } else {
        format!("{path}: {what}")
    }
}

fn list(values: &[&Json]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A numeric bound. `lower`: raising it tightens; otherwise lowering does.
fn bound(
    key: &str,
    old: Option<&Json>,
    new: Option<&Json>,
    lower: bool,
    path: &str,
    emit: &mut dyn FnMut(Level, String),
) {
    let (level, what) = match (old.and_then(Json::as_f64), new.and_then(Json::as_f64)) {
        (None, Some(n)) => (Level::Tightening, format!("{key} added ({n})")),
        (Some(_), None) => (Level::Compatible, format!("{key} removed")),
        (Some(o), Some(n)) if (n > o) == lower => (
            Level::Tightening,
            format!(
                "{key} {} from {o} to {n}",
                if lower { "raised" } else { "lowered" }
            ),
        ),
        (Some(o), Some(n)) => (
            Level::Compatible,
            format!(
                "{key} {} from {o} to {n}",
                if lower { "lowered" } else { "raised" }
            ),
        ),
        (None, None) => (
            Level::Tightening,
            format!("{key} changed, the direction is unknown"),
        ),
    };
    emit(level, located(path, what));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        schema::json_schema::{ClassPlan, PropertyPlan},
        urls,
    };

    const ONTOLOGY: &str = "did:ad:shopOntologyGenesis";

    fn prop(shortname: &str, datatype: &str) -> PropertyPlan {
        PropertyPlan {
            shortname: shortname.into(),
            datatype: datatype.into(),
            ..Default::default()
        }
    }

    /// An `item` class: `name` required, `price` (integer) recommended with `constraints`.
    fn plan(constraints: Json) -> OntologyPlan {
        let constraints = constraints.as_object().map(|all| {
            all.iter()
                .map(|(k, v)| (k.clone(), v.as_object().unwrap().clone()))
                .collect()
        });
        OntologyPlan {
            shortname: "shop".into(),
            classes: vec![ClassPlan {
                shortname: "item".into(),
                properties: vec![prop("name", urls::STRING), prop("price", urls::INTEGER)],
                requires: vec!["name".into()],
                constraints,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn levels(old: &OntologyPlan, new: &OntologyPlan) -> Vec<Level> {
        diff(old, new, ONTOLOGY)
            .unwrap()
            .iter()
            .map(|c| c.level)
            .collect()
    }

    fn price(keywords: Json) -> OntologyPlan {
        plan(json!({ "price": keywords }))
    }

    fn assert_level(old: Json, new: Json, want: Level) {
        let changes = diff(&price(old.clone()), &price(new.clone()), ONTOLOGY).unwrap();
        assert_eq!(
            changes.iter().map(|c| c.level).max(),
            Some(want),
            "{old} -> {new}: {changes:?}"
        );
    }

    #[test]
    fn identical_and_cosmetic_changes_are_not_reported() {
        let old = plan(json!({}));
        let mut new = old.clone();
        new.name = Some("Shop".into());
        new.classes[0].description = Some("An item".into());
        new.classes[0].properties[0].name = Some("Name".into());
        new.classes[0].properties.reverse();
        assert!(diff(&old, &new, ONTOLOGY).unwrap().is_empty());
    }

    #[test]
    fn compatible_changes() {
        let old = plan(json!({}));
        let mut optional = old.clone();
        optional.classes[0]
            .properties
            .push(prop("sku", urls::STRING));
        assert_eq!(levels(&old, &optional), [Level::Compatible]);

        let mut class = old.clone();
        class.classes.push(ClassPlan {
            shortname: "order".into(),
            ..Default::default()
        });
        assert_eq!(levels(&old, &class), [Level::Compatible]);

        let mut relaxed = old.clone();
        relaxed.classes[0].requires.clear();
        assert_eq!(levels(&old, &relaxed), [Level::Compatible]);

        assert_level(
            json!({"minimum": 5}),
            json!({"minimum": 1}),
            Level::Compatible,
        );
        assert_level(
            json!({"maximum": 5}),
            json!({"maximum": 10}),
            Level::Compatible,
        );
        assert_level(
            json!({"enum": [1, 2]}),
            json!({"enum": [1, 2, 3]}),
            Level::Compatible,
        );
        assert_level(json!({"minimum": 5}), json!({}), Level::Compatible);
        assert_level(
            json!({"type": "object", "additionalProperties": false}),
            json!({"type": "object"}),
            Level::Compatible,
        );
    }

    #[test]
    fn tightening_changes() {
        let old = plan(json!({}));
        let mut required = old.clone();
        required.classes[0]
            .properties
            .push(prop("sku", urls::STRING));
        required.classes[0].requires.push("sku".into());
        assert_eq!(levels(&old, &required), [Level::Tightening]);

        let mut promoted = old.clone();
        promoted.classes[0].requires.push("price".into());
        assert_eq!(levels(&old, &promoted), [Level::Tightening]);

        for (a, b) in [
            (json!({"minimum": 1}), json!({"minimum": 5})),
            (json!({"maximum": 10}), json!({"maximum": 5})),
            (
                json!({"exclusiveMinimum": 1}),
                json!({"exclusiveMinimum": 2}),
            ),
            (
                json!({"exclusiveMaximum": 9}),
                json!({"exclusiveMaximum": 8}),
            ),
            (json!({"minLength": 1}), json!({"minLength": 2})),
            (json!({"maxLength": 9}), json!({"maxLength": 8})),
            (json!({"minItems": 1}), json!({"minItems": 2})),
            (json!({"maxItems": 9}), json!({"maxItems": 8})),
            (json!({}), json!({"maximum": 8})),
            (json!({"enum": [1, 2, 3]}), json!({"enum": [1, 2]})),
            (json!({}), json!({"const": 1})),
            (json!({"const": 1}), json!({"const": 2})),
            (
                json!({"type": "object"}),
                json!({"type": "object", "additionalProperties": false}),
            ),
            (json!({}), json!({"pattern": "^a"})),
        ] {
            assert_level(a, b, Level::Tightening);
        }
    }

    #[test]
    fn unknown_direction_is_tightening_and_says_so() {
        let changes = diff(
            &price(json!({"pattern": "^a"})),
            &price(json!({"pattern": "^b"})),
            ONTOLOGY,
        )
        .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].level, Level::Tightening);
        assert!(
            changes[0].detail.contains("direction is unknown"),
            "{}",
            changes[0]
        );

        let any = |v: Json| json!({"anyOf": [{"type": v}]});
        assert_level(
            any(json!("string")),
            any(json!("number")),
            Level::Tightening,
        );
    }

    #[test]
    fn nested_constraints_follow_the_same_rules() {
        let nested = |min: i64, extra: bool| {
            let mut properties = json!({"street": {"minLength": min}});
            if extra {
                properties["zip"] = json!({"type": "string"});
            }
            json!({"type": "object", "properties": properties})
        };
        assert_level(nested(1, false), nested(3, false), Level::Tightening);
        assert_level(nested(3, false), nested(1, false), Level::Compatible);
        let changes = diff(&price(nested(1, false)), &price(nested(3, false)), ONTOLOGY).unwrap();
        assert!(
            changes[0].detail.contains("properties.street"),
            "{}",
            changes[0]
        );
        assert_level(nested(1, false), nested(1, true), Level::Tightening);
        assert_level(
            json!({"type": "array", "items": {"maxLength": 3}}),
            json!({"type": "array", "items": {"maxLength": 9}}),
            Level::Compatible,
        );
    }

    #[test]
    fn breaking_changes() {
        let old = plan(json!({}));

        let mut removed = old.clone();
        removed.classes[0].properties.pop();
        assert_eq!(levels(&old, &removed), [Level::Breaking]);

        let mut class = old.clone();
        class.classes.clear();
        assert_eq!(levels(&old, &class), [Level::Breaking]);

        let mut datatype = old.clone();
        datatype.classes[0].properties[1].datatype = urls::STRING.into();
        let changes = diff(&old, &datatype, ONTOLOGY).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].level, Level::Breaking);
        assert!(changes[0]
            .detail
            .contains("old values stay under the old ID"));

        let mut renamed = old.clone();
        renamed.classes[0].properties[1].shortname = "cost".into();
        assert_eq!(levels(&old, &renamed), [Level::Compatible, Level::Breaking]);

        let mut classtype = old.clone();
        classtype.classes[0].properties[1].classtype = Some("https://example.com/Thing".into());
        assert_eq!(levels(&old, &classtype), [Level::Breaking]);
    }

    #[test]
    fn levels_are_ordered_and_changes_display() {
        assert!(Level::Compatible < Level::Tightening && Level::Tightening < Level::Breaking);
        let change = Change {
            level: Level::Breaking,
            class: Some("item".into()),
            property: Some("price".into()),
            detail: "gone".into(),
        };
        assert_eq!(change.to_string(), "[breaking] item.price: gone");
    }

    #[test]
    fn fingerprint_ignores_order_and_cosmetics_but_not_the_contract() {
        let base = price(json!({"minimum": 1}));
        let print = |p: &OntologyPlan| fingerprint(p, ONTOLOGY).unwrap();
        let want = print(&base);
        assert!(want.starts_with("b3-") && want.len() == 3 + 64);

        let mut shuffled = base.clone();
        shuffled.classes[0].properties.reverse();
        shuffled.classes[0].name = Some("Item".into());
        shuffled.classes[0].description = Some("Reworded".into());
        shuffled.classes.push(ClassPlan {
            shortname: "zzz".into(),
            ..Default::default()
        });
        shuffled.classes.rotate_right(1);
        let mut other = shuffled.clone();
        other.classes.retain(|c| c.shortname != "zzz");
        assert_eq!(print(&other), want);
        assert_ne!(print(&shuffled), want);

        assert_eq!(
            fingerprint(&base, "atomic:shopOntologyGenesis").unwrap(),
            print(&base)
        );
        assert_ne!(print(&price(json!({"minimum": 5}))), want);
        assert_ne!(fingerprint(&base, "did:ad:otherOntology").unwrap(), want);
    }
}
