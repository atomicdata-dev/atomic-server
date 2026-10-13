//! `schema push | lock | check`: a schema file in your own language (a JSON
//! Schema or an `OntologyInput` JSON) becomes a real ontology plus a lockfile
//! that pins its property IDs. See `docs/src/schema/json-schema.md`.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use atomic_lib::{
    agents::Agent,
    errors::AtomicResult,
    schema::{
        json_schema::{
            ensure_ontology_with, ontology_from_json_schema_str, EnsureTarget, ImportOptions,
            OntologyPlan,
        },
        lockfile::Lockfile,
    },
    Subject,
};
use colored::Colorize;

use crate::Context;

/// `<file>.lock.json`, next to the schema file.
pub fn default_lockfile_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".lock.json");
    PathBuf::from(name)
}

/// True for a JSON Schema: it has `$schema` or `$defs`, or is `type: object`.
/// Anything else is read as an `OntologyInput` (`{ shortname, classes }`).
pub fn is_json_schema(json: &serde_json::Value) -> bool {
    json.get("$schema").is_some()
        || json.get("$defs").is_some()
        || json.get("type").and_then(|t| t.as_str()) == Some("object")
}

/// Reads the text of a schema file into a plan.
pub fn parse_plan(text: &str, shortname: Option<String>) -> AtomicResult<OntologyPlan> {
    let json: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("Not valid JSON: {e}"))?;
    if !json.is_object() {
        return Err("A schema file must hold a JSON object".into());
    }
    if is_json_schema(&json) {
        // Re-read the text, not `json`: the order of the keys is the order of the classes.
        ontology_from_json_schema_str(text, &ImportOptions { shortname })
    } else {
        let mut plan: OntologyPlan = serde_json::from_value(json).map_err(|e| {
            format!("Neither a JSON Schema ($schema, $defs or type: object) nor an ontology ({{ shortname, classes }}): {e}")
        })?;
        if let Some(shortname) = shortname {
            plan.shortname = shortname;
        }
        Ok(plan)
    }
}

fn read_plan(file: &Path, shortname: Option<String>) -> AtomicResult<OntologyPlan> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("Could not read {}: {e}", file.display()))?;
    parse_plan(&text, shortname).map_err(|e| format!("{}: {e}", file.display()).into())
}

fn read_lockfile(path: &Path) -> AtomicResult<Option<Lockfile>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    Lockfile::parse(&text)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()).into())
}

fn write_lockfile(path: &Path, lock: &Lockfile) -> AtomicResult<()> {
    std::fs::write(path, lock.to_canonical_string())
        .map_err(|e| format!("Could not write {}: {e}", path.display()).into())
}

/// Offline. Pins the property IDs of the schema in `ontology`. Class subjects
/// of an earlier push of the same ontology are kept; a push adds new ones.
pub fn lock(
    file: &Path,
    ontology: &str,
    shortname: Option<String>,
    lockfile: Option<PathBuf>,
) -> AtomicResult<PathBuf> {
    let plan = read_plan(file, shortname)?;
    let path = lockfile.unwrap_or_else(|| default_lockfile_path(file));
    let classes = match read_lockfile(&path)? {
        Some(previous) if previous.ontology == ontology => previous.classes,
        _ => BTreeMap::new(),
    };
    let lock = Lockfile::from_plan(&plan, ontology, classes)?;
    write_lockfile(&path, &lock)?;
    Ok(path)
}

/// Offline. Fails when the lockfile no longer matches the schema.
pub fn check(
    file: &Path,
    shortname: Option<String>,
    lockfile: Option<PathBuf>,
) -> AtomicResult<()> {
    let plan = read_plan(file, shortname)?;
    let path = lockfile.unwrap_or_else(|| default_lockfile_path(file));
    let lock = read_lockfile(&path)?.ok_or_else(|| {
        format!(
            "No lockfile at {}. Run `schema push` or `schema lock` first",
            path.display()
        )
    })?;
    lock.check(&plan)
        .map_err(|e| format!("{}: {e}", path.display()).into())
}

/// Makes the schema real on the configured server and writes the lockfile.
pub async fn push(
    context: &Context,
    file: &Path,
    parent: Option<String>,
    shortname: Option<String>,
    lockfile: Option<PathBuf>,
    accept_changes: bool,
) -> AtomicResult<()> {
    let plan = read_plan(file, shortname)?;
    let path = lockfile.unwrap_or_else(|| default_lockfile_path(file));
    let previous = read_lockfile(&path)?;

    // A pinned lockfile must still match, or the push would quietly make new
    // properties next to the old ones.
    if let Some(previous) = &previous {
        if let Err(e) = previous.check(&plan) {
            if !accept_changes {
                return Err(format!(
                    "{}: {e}\nPass --accept-changes to push anyway",
                    path.display()
                )
                .into());
            }
        }
    }

    let config = context.read_config();
    let parent = parent
        .or(config.shared.initial_drive.clone())
        .ok_or("No parent to put the ontology in. Pass --parent <subject>")?;
    let agent = Agent::from_secret(&config.shared.agent_secret)?;

    let target = EnsureTarget {
        remote: true,
        ontology: previous.map(|p| p.ontology),
        ..Default::default()
    };
    let ensured = ensure_ontology_with(
        &context.store,
        &Subject::from(parent.as_str()),
        &plan,
        &agent,
        &target,
    )
    .await?;

    let lock = Lockfile::from_ensured(&ensured);
    write_lockfile(&path, &lock)?;
    println!(
        "{} {} ({} classes, {} properties)",
        "Ontology".green().bold(),
        ensured.ontology,
        ensured.classes.len(),
        ensured.properties.len()
    );
    println!("Lockfile written to {}", path.display());
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    const SCHEMA: &str = r#"{
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "title": "Notes",
      "$defs": { "note": { "type": "object",
        "properties": { "title": { "type": "string" }, "pinned": { "type": "boolean" } },
        "required": ["title"] } }
    }"#;

    const INPUT: &str = r#"{
      "shortname": "notes",
      "classes": [ { "shortname": "note", "requires": ["title"],
        "properties": [ { "shortname": "title", "datatype": "https://atomicdata.dev/datatypes/string" } ] } ]
    }"#;

    const ONTOLOGY: &str = "did:ad:notesOntologyGenesis";

    fn temp_file(name: &str, text: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("atomic-cli-schema-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn detects_json_schema_and_ontology_input() {
        assert!(is_json_schema(&serde_json::json!({"$defs": {}})));
        assert!(is_json_schema(&serde_json::json!({"type": "object"})));
        assert!(!is_json_schema(
            &serde_json::json!({"shortname": "x", "classes": []})
        ));

        let schema = parse_plan(SCHEMA, None).unwrap();
        assert_eq!(schema.shortname, "notes");
        assert_eq!(schema.classes[0].shortname, "note");

        let input = parse_plan(INPUT, None).unwrap();
        assert_eq!(input.shortname, "notes");
        assert_eq!(input.classes[0].properties[0].shortname, "title");

        assert_eq!(
            parse_plan(INPUT, Some("other".into())).unwrap().shortname,
            "other"
        );
        assert!(parse_plan("[]", None).is_err());
        assert!(parse_plan("{\"nonsense\": 1}", None).is_err());
    }

    #[test]
    fn lock_then_check_offline() {
        let file = temp_file("lock-check.schema.json", SCHEMA);
        let lockfile = lock(&file, ONTOLOGY, None, None).unwrap();
        assert_eq!(lockfile, default_lockfile_path(&file));

        let text = std::fs::read_to_string(&lockfile).unwrap();
        assert!(text.ends_with("}\n"));
        let lock = Lockfile::parse(&text).unwrap();
        assert_eq!(lock.ontology, ONTOLOGY);
        assert!(lock.properties["title"].starts_with("atomic:prop:"));
        assert!(lock.classes.is_empty());
        assert_eq!(text, lock.to_canonical_string());

        check(&file, None, None).unwrap();
    }

    #[test]
    fn check_fails_when_a_datatype_changes() {
        let file = temp_file("changed.schema.json", SCHEMA);
        lock(&file, ONTOLOGY, None, None).unwrap();
        std::fs::write(
            &file,
            SCHEMA.replace(
                "\"pinned\": { \"type\": \"boolean\" }",
                "\"pinned\": { \"type\": \"string\" }",
            ),
        )
        .unwrap();

        let error = check(&file, None, None).unwrap_err().to_string();
        assert!(error.contains("property 'pinned'"), "{error}");
        assert!(
            error.contains("shortname or datatype makes a new property"),
            "{error}"
        );
    }

    #[test]
    fn check_without_lockfile_says_so() {
        let file = temp_file("unlocked.schema.json", SCHEMA);
        let _ = std::fs::remove_file(default_lockfile_path(&file));
        assert!(check(&file, None, None)
            .unwrap_err()
            .to_string()
            .contains("No lockfile"));
    }

    #[test]
    fn relock_keeps_class_subjects_of_the_same_ontology() {
        let file = temp_file("relock.schema.json", SCHEMA);
        let path = default_lockfile_path(&file);
        let mut pushed = Lockfile::from_plan(
            &parse_plan(SCHEMA, None).unwrap(),
            ONTOLOGY,
            BTreeMap::new(),
        )
        .unwrap();
        pushed
            .classes
            .insert("note".into(), "did:ad:noteGenesis".into());
        write_lockfile(&path, &pushed).unwrap();

        lock(&file, ONTOLOGY, None, None).unwrap();
        assert_eq!(read_lockfile(&path).unwrap().unwrap(), pushed);

        // Another ontology starts from scratch.
        lock(&file, "did:ad:otherOntology", None, None).unwrap();
        assert!(read_lockfile(&path).unwrap().unwrap().classes.is_empty());
    }
}
