//! The schema lockfile: the ontology subject, the class subjects and the
//! content-addressed property IDs of a schema file, pinned next to it.
//!
//! Property IDs are a pure function of ontology, shortname and datatype
//! ([`property_id`]), so [`Lockfile::from_plan`] needs no server. Class
//! subjects are DIDs minted by the server's first commit, so only a push can
//! fill them in.
//!
//! The text form is canonical: sorted keys, 2-space indent, trailing newline.
//! `@tomic/lib` writes the same bytes (`browser/lib/src/schema-lockfile.ts`);
//! both run `lib/tests/fixtures/schema-lockfile.json`, so change them
//! together. See `docs/src/schema/json-schema.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    compat::fingerprint,
    json_schema::{check_plan, EnsuredOntology, OntologyPlan},
};
use crate::{errors::AtomicResult, property_identity::property_id};

/// Field order is alphabetical on purpose: it is the order of the text form.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    /// Class shortname to subject. Empty until the ontology has been pushed.
    #[serde(default)]
    pub classes: BTreeMap<String, String>,
    /// `b3-{hex}`, see [`fingerprint`]: a hash of the schema's contract when it
    /// was locked. Absent in lockfiles from before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The subject of the Ontology resource.
    pub ontology: String,
    /// Property shortname to `atomic:prop:{hex}`.
    pub properties: BTreeMap<String, String>,
}

impl Lockfile {
    /// The lockfile of `plan` in `ontology`, with the given class subjects
    /// (`BTreeMap::new()` when they are not known yet). Pure: no network.
    pub fn from_plan(
        plan: &OntologyPlan,
        ontology: &str,
        classes: BTreeMap<String, String>,
    ) -> AtomicResult<Lockfile> {
        let checked = check_plan(plan)?;
        let mut properties = BTreeMap::new();
        for property in &checked.properties {
            properties.insert(
                property.shortname.clone(),
                property_id(ontology, &property.shortname, &property.datatype)?,
            );
        }
        Ok(Lockfile {
            classes,
            fingerprint: Some(fingerprint(plan, ontology)?),
            ontology: ontology.to_string(),
            properties,
        })
    }

    /// The lockfile of an ontology that [`super::json_schema::ensure_ontology`]
    /// made or found from `plan`.
    pub fn from_ensured(ensured: &EnsuredOntology, plan: &OntologyPlan) -> AtomicResult<Lockfile> {
        Ok(Lockfile {
            classes: ensured.classes.clone(),
            fingerprint: Some(fingerprint(plan, &ensured.ontology)?),
            ontology: ensured.ontology.clone(),
            properties: ensured.properties.clone(),
        })
    }

    pub fn parse(text: &str) -> AtomicResult<Lockfile> {
        serde_json::from_str(text).map_err(|e| format!("Not a valid lockfile: {e}").into())
    }

    /// The canonical text: sorted keys, 2-space indent, trailing newline.
    pub fn to_canonical_string(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("a lockfile is always JSON");
        text.push('\n');
        text
    }

    /// Fails unless this lockfile still describes `plan`: [`Self::check_identities`],
    /// and the fingerprint must match when the lockfile has one.
    pub fn check(&self, plan: &OntologyPlan) -> AtomicResult<()> {
        self.check_identities(plan)?;
        if let Some(pinned) = &self.fingerprint {
            let now = fingerprint(plan, &self.ontology)?;
            if *pinned != now {
                return Err(format!(
                    "The lockfile does not match the schema:\n- the schema changed since it was locked \
                     (fingerprint {pinned}, now {now}); run `schema diff` to see how"
                )
                .into());
            }
        }
        Ok(())
    }

    /// Fails unless every property of the plan is pinned to the ID its current
    /// ontology, shortname and datatype give, and nothing else is pinned. A
    /// class the lockfile knows must still be in the plan; a class it does not
    /// know yet is fine, that is what a push adds. Other edits to the schema
    /// pass: that is what `schema diff` and a push are for.
    pub fn check_identities(&self, plan: &OntologyPlan) -> AtomicResult<()> {
        let expected = Lockfile::from_plan(plan, &self.ontology, BTreeMap::new())?;
        let mut problems = Vec::new();

        for (shortname, id) in &expected.properties {
            match self.properties.get(shortname) {
                Some(pinned) if pinned == id => {}
                Some(pinned) => problems.push(format!(
                    "property '{shortname}': the lockfile pins {pinned}, the schema now gives {id}. \
                     A property's identity is its ontology, shortname and datatype, so changing its \
                     shortname or datatype makes a new property and leaves the old one behind. \
                     Change it back, or re-lock to accept the new property"
                )),
                None => problems.push(format!(
                    "property '{shortname}' is in the schema but not in the lockfile ({id})"
                )),
            }
        }
        for shortname in self.properties.keys() {
            if !expected.properties.contains_key(shortname) {
                problems.push(format!(
                    "property '{shortname}' is in the lockfile but no longer in the schema"
                ));
            }
        }
        let class_names: Vec<&str> = plan.classes.iter().map(|c| c.shortname.as_str()).collect();
        for shortname in self.classes.keys() {
            if !class_names.contains(&shortname.as_str()) {
                problems.push(format!(
                    "class '{shortname}' is in the lockfile but no longer in the schema"
                ));
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "The lockfile does not match the schema:\n- {}",
                problems.join("\n- ")
            )
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::json_schema::{ontology_from_json_schema_str, ImportOptions};

    const FIXTURE: &str = include_str!("../../tests/fixtures/schema-lockfile.json");

    fn fixture() -> serde_json::Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn plan_of(case: &serde_json::Value) -> OntologyPlan {
        if let Some(schema) = case.get("jsonSchema") {
            ontology_from_json_schema_str(&schema.to_string(), &ImportOptions::default()).unwrap()
        } else {
            serde_json::from_value(case["plan"].clone()).unwrap()
        }
    }

    #[test]
    fn fixture_lockfiles_are_byte_identical() {
        for case in fixture()["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let classes: BTreeMap<String, String> =
                serde_json::from_value(case["classes"].clone()).unwrap();
            let lock =
                Lockfile::from_plan(&plan_of(case), case["ontology"].as_str().unwrap(), classes)
                    .unwrap();
            assert_eq!(
                lock.to_canonical_string(),
                case["lockfile"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                lock.fingerprint.as_deref(),
                Some(case["fingerprint"].as_str().unwrap()),
                "{name}"
            );
            assert_eq!(Lockfile::parse(&lock.to_canonical_string()).unwrap(), lock);
            lock.check(&plan_of(case)).unwrap();
        }
    }

    #[test]
    fn check_names_a_changed_datatype() {
        let case = &fixture()["cases"][0];
        let plan = plan_of(case);
        let lock = Lockfile::from_plan(&plan, "atomic:ontologyGenesis", BTreeMap::new()).unwrap();
        let mut changed = plan.clone();
        changed.classes[1].properties[1].datatype = crate::urls::INTEGER.to_string();
        let error = lock.check(&changed).unwrap_err().to_string();
        assert!(
            error.contains("shortname or datatype makes a new property"),
            "{error}"
        );
        assert!(
            error.contains(&changed.classes[1].properties[1].shortname),
            "{error}"
        );
    }

    #[test]
    fn check_reports_added_and_removed_properties() {
        let plan = plan_of(&fixture()["cases"][0]);
        let lock = Lockfile::from_plan(&plan, "atomic:ontologyGenesis", BTreeMap::new()).unwrap();
        let mut grown = plan.clone();
        grown
            .properties
            .push(crate::schema::json_schema::PropertyPlan {
                shortname: "extra".into(),
                datatype: crate::urls::STRING.into(),
                ..Default::default()
            });
        assert!(lock
            .check(&grown)
            .unwrap_err()
            .to_string()
            .contains("not in the lockfile"));
        let mut shrunk = plan.clone();
        shrunk.classes[0].properties.clear();
        shrunk.classes[0].requires.clear();
        shrunk.classes[0].recommends.clear();
        assert!(lock
            .check(&shrunk)
            .unwrap_err()
            .to_string()
            .contains("no longer in the schema"));
    }

    #[test]
    fn a_lockfile_without_fingerprint_still_parses_and_writes_the_same() {
        let old = "{\n  \"classes\": {},\n  \"ontology\": \"x\",\n  \"properties\": {}\n}\n";
        let lock = Lockfile::parse(old).unwrap();
        assert_eq!(lock.fingerprint, None);
        assert_eq!(lock.to_canonical_string(), old);
    }

    #[test]
    fn check_reports_a_changed_contract_but_check_identities_does_not() {
        let plan = plan_of(&fixture()["cases"][0]);
        let lock = Lockfile::from_plan(&plan, "atomic:ontologyGenesis", BTreeMap::new()).unwrap();
        lock.check(&plan).unwrap();

        let mut tighter = plan.clone();
        tighter.classes[0].requires.push("email".into());
        let error = lock.check(&tighter).unwrap_err().to_string();
        assert!(error.contains("changed since it was locked"), "{error}");
        assert!(error.contains("`schema diff`"), "{error}");
        lock.check_identities(&tighter).unwrap();

        // Without a fingerprint there is nothing to compare.
        let mut bare = lock.clone();
        bare.fingerprint = None;
        bare.check(&tighter).unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Lockfile::parse(r#"{"ontology":"x","properties":{},"extra":1}"#).is_err());
    }
}
