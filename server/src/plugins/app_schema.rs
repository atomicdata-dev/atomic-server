//! The schema an app defines or uses, declared in its manifest.
//!
//! There is no schema system of its own here. An app names the shared
//! vocabularies it uses (ontology resources at fixed subjects, such as
//! `https://atomicdata.dev/work/v1`) and may carry one inline ontology
//! ([`OntologyPlan`], the plan `ensureOntology` takes). Installing makes the
//! inline one real in the drive with `ensure_ontology`, the path the MCP tool
//! and the CLI use, and checks that each vocabulary exists. An export field
//! points at a Property of either (`property`), and the host checks the value
//! it receives or returns with [`Value::new`] for that Property's datatype and
//! its `allowsOnly`: the checks every other value in the store goes through.

use atomic_lib::{
    agents::ForAgent,
    datatype::DataType,
    errors::AtomicResult,
    hierarchy,
    schema::json_schema::{ensure_ontology, validate_plan, OntologyPlan},
    urls, Db, Storelike, Value,
};
use serde::{Deserialize, Serialize};

use super::actions::InputSchema;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppSchema {
    /// Subjects of shared ontologies the app uses. They are never copied into
    /// the drive; installing fails when one does not exist on this server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vocabularies: Vec<String>,
    /// Classes and properties this app defines, made real in the drive as an
    /// ordinary ontology. Installing again finds it by its shortname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ontology: Option<OntologyPlan>,
}

impl AppSchema {
    pub fn validate(&self) -> Result<(), String> {
        if self.vocabularies.len() > 16 {
            return Err("at most 16 vocabularies per release".into());
        }
        let mut seen = std::collections::HashSet::new();
        for vocabulary in &self.vocabularies {
            if !(vocabulary.starts_with("https://") || vocabulary.starts_with("did:ad:"))
                || !seen.insert(vocabulary)
            {
                return Err(format!(
                    "vocabulary '{vocabulary}' must be a unique https: or did:ad: subject"
                ));
            }
        }
        if let Some(plan) = &self.ontology {
            validate_plan(plan).map_err(|e| format!("schema.ontology: {e}"))?;
        }
        Ok(())
    }

    /// The datatype subject of an inline property, by shortname.
    fn inline_datatype(&self, shortname: &str) -> Option<&str> {
        let plan = self.ontology.as_ref()?;
        plan.properties
            .iter()
            .chain(plan.classes.iter().flat_map(|c| &c.properties))
            .find(|p| p.shortname == shortname)
            .map(|p| p.datatype.as_str())
    }

    /// Whether a field's `property` names something this app declared: a
    /// shortname of its inline ontology, or a property of one of its vocabularies.
    pub fn declares(&self, reference: &str) -> bool {
        if reference.contains(':') {
            self.vocabularies.iter().any(|v| {
                reference
                    .strip_prefix(v.as_str())
                    .is_some_and(|rest| rest.len() > 1 && rest.starts_with('/'))
            })
        } else {
            self.inline_datatype(reference).is_some()
        }
    }

    /// Makes the schema exist in `drive` on behalf of `installer`, who must be
    /// able to write there: the ontology is created as the server's own agent,
    /// so nobody gets more than they hold by installing an app.
    pub async fn ensure(&self, store: &Db, drive: &str, installer: &ForAgent) -> AtomicResult<()> {
        let drive_resource = store.get_resource(&drive.into()).await?;
        for vocabulary in &self.vocabularies {
            let found = store.get_resource(&vocabulary.as_str().into()).await;
            let is_ontology = found.as_ref().is_ok_and(|r| {
                r.get(urls::IS_A)
                    .and_then(|v| v.to_subjects(None))
                    .is_ok_and(|classes| classes.iter().any(|c| c == urls::ONTOLOGY))
            });
            if !is_ontology {
                return Err(
                    format!("vocabulary {vocabulary} is not an ontology on this server").into(),
                );
            }
        }
        let Some(plan) = &self.ontology else {
            return Ok(());
        };
        hierarchy::check_write(store, &drive_resource, installer)
            .await
            .map_err(|e| format!("you cannot add an ontology to this drive: {e}"))?;
        let agent = store.get_default_agent()?;
        ensure_ontology(store, &drive.into(), plan, &agent).await?;
        Ok(())
    }

    /// The datatype and allowed values of the Property a field points at.
    async fn property(
        &self,
        store: &Db,
        reference: &str,
    ) -> Result<(DataType, Option<Vec<String>>), String> {
        if !reference.contains(':') {
            let datatype = self.inline_datatype(reference).ok_or("unknown property")?;
            return Ok((datatype.parse().map_err(|_| "unknown datatype")?, None));
        }
        let property = store
            .get_property(reference)
            .await
            .map_err(|e| e.to_string())?;
        Ok((property.data_type, property.allows_only))
    }
}

/// Checks the fields of `value` that point at a Property against it. The JSON
/// shape was checked by [`InputSchema::validate`] first.
pub async fn check_values(
    store: &Db,
    schema: Option<&AppSchema>,
    shape: &InputSchema,
    value: &serde_json::Value,
) -> Result<(), String> {
    let (Some(schema), Some(args)) = (schema, value.as_object()) else {
        return Ok(());
    };
    for (name, value) in args {
        let Some(reference) = shape.properties.get(name).and_then(|f| f.property.as_ref()) else {
            continue;
        };
        let (datatype, allows_only) = schema.property(store, reference).await?;
        let text = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        Value::new(&text, &datatype)
            .map_err(|e| format!("{name} is not valid for {reference}: {e}"))?;
        if allows_only.is_some_and(|allowed| !allowed.contains(&text)) {
            return Err(format!(
                "{name} is not one of the values {reference} allows"
            ));
        }
    }
    Ok(())
}
