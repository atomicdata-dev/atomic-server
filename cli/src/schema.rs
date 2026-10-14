//! `schema push | lock | check | diff`: a schema file in your own language (a JSON
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
        compat::{self, Change, Level},
        json_schema::{
            ensure_ontology_with, ontology_from_json_schema_str, ontology_to_json_schema,
            EnsureTarget, ImportOptions, OntologyPlan,
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

/// The ontology as the server has it, read back into a plan. Names are the
/// server's, so compare it with [`compat::diff`], which ignores them.
async fn server_plan(
    context: &Context,
    ontology: &str,
    shortname: &str,
) -> AtomicResult<OntologyPlan> {
    let json = ontology_to_json_schema(&context.store, ontology).await?;
    ontology_from_json_schema_str(
        &json.to_string(),
        &ImportOptions {
            shortname: Some(shortname.to_string()),
        },
    )
}

/// The changes grouped by level, worst first. Empty text when there are none.
pub fn format_changes(changes: &[Change]) -> String {
    let mut text = String::new();
    for level in [Level::Breaking, Level::Tightening, Level::Compatible] {
        let of_level: Vec<_> = changes.iter().filter(|c| c.level == level).collect();
        if of_level.is_empty() {
            continue;
        }
        let title = format!("{} ({})", level.to_string().to_uppercase(), of_level.len());
        text.push_str(&match level {
            Level::Breaking => title.red().bold().to_string(),
            Level::Tightening => title.yellow().bold().to_string(),
            Level::Compatible => title.green().bold().to_string(),
        });
        text.push('\n');
        for change in of_level {
            let place = match (&change.class, &change.property) {
                (Some(c), Some(p)) => format!("{c}.{p}"),
                (Some(c), None) => c.clone(),
                (None, Some(p)) => format!("property {p}"),
                (None, None) => "ontology".to_string(),
            };
            text.push_str(&format!("  {place}: {}\n", change.detail));
        }
    }
    text
}

/// How `file` differs from `against` (a schema file), or from the ontology on
/// the server that the lockfile pins. Prints the changes, and fails when one
/// of them is breaking.
pub async fn diff(
    context: &Context,
    file: &Path,
    against: Option<PathBuf>,
    shortname: Option<String>,
    lockfile: Option<PathBuf>,
) -> AtomicResult<()> {
    let new = read_plan(file, shortname.clone())?;
    let lock = read_lockfile(&lockfile.unwrap_or_else(|| default_lockfile_path(file)))?;
    let changes = match against {
        Some(old_file) => {
            let old = read_plan(&old_file, shortname)?;
            let ontology = lock.map_or(OFFLINE_ONTOLOGY.to_string(), |l| l.ontology);
            compat::diff(&old, &new, &ontology)?
        }
        None => {
            let lock = lock.ok_or(
                "No lockfile to say which ontology on the server to compare with. \
                 Run `schema push` first, or pass --against <old schema file>",
            )?;
            let old = server_plan(context, &lock.ontology, &new.shortname).await?;
            compat::diff(&old, &new, &lock.ontology)?
        }
    };
    report(&changes)
}

/// Any ontology will do offline: IDs are only compared with each other.
const OFFLINE_ONTOLOGY: &str = "atomic:ontologyGenesis";

fn report(changes: &[Change]) -> AtomicResult<()> {
    if changes.is_empty() {
        println!("{}", "No changes to the schema's contract".green());
        return Ok(());
    }
    print!("{}", format_changes(changes));
    let breaking = changes
        .iter()
        .filter(|c| c.level == Level::Breaking)
        .count();
    if breaking > 0 {
        return Err(format!("{breaking} breaking change(s)").into());
    }
    Ok(())
}

/// Makes the schema real on the configured server and writes the lockfile.
pub async fn push(
    context: &Context,
    file: &Path,
    parent: Option<String>,
    shortname: Option<String>,
    lockfile: Option<PathBuf>,
    accept_changes: bool,
    allow_breaking: bool,
) -> AtomicResult<()> {
    let plan = read_plan(file, shortname)?;
    let path = lockfile.unwrap_or_else(|| default_lockfile_path(file));
    let previous = read_lockfile(&path)?;

    // A pinned lockfile must still match, or the push would quietly make new
    // properties next to the old ones.
    if let Some(previous) = &previous {
        if let Err(e) = previous.check_identities(&plan) {
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

    // What this push would do to data under the ontology as it is now.
    if let Some(previous) = &previous {
        match server_plan(context, &previous.ontology, &plan.shortname).await {
            Ok(old) => {
                let changes = compat::diff(&old, &plan, &previous.ontology)?;
                let worst = changes.iter().map(|c| c.level).max();
                if worst >= Some(Level::Tightening) {
                    print!("{}", format_changes(&changes));
                }
                if worst == Some(Level::Breaking) && !allow_breaking {
                    return Err("The push has breaking changes. Pass --allow-breaking to push anyway".into());
                }
                if worst == Some(Level::Tightening) {
                    println!(
                        "{}",
                        "Existing data may fail the new constraints".yellow()
                    );
                }
            }
            Err(e) if !allow_breaking => {
                return Err(format!(
                    "Could not read the ontology on the server to compare with: {e}\nPass --allow-breaking to push without comparing"
                )
                .into())
            }
            Err(_) => {}
        }
    }

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

    let lock = Lockfile::from_ensured(&ensured, &plan)?;
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

    const OLD_SCHEMA: &str = r#"{
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "title": "Notes",
      "$defs": { "note": { "type": "object",
        "properties": { "title": { "type": "string", "minLength": 1 }, "pinned": { "type": "boolean" } },
        "required": ["title"] } }
    }"#;

    fn changes_between(old: &str, new: &str) -> Vec<Change> {
        compat::diff(
            &parse_plan(old, None).unwrap(),
            &parse_plan(new, None).unwrap(),
            OFFLINE_ONTOLOGY,
        )
        .unwrap()
    }

    #[test]
    fn diff_against_a_file_groups_by_level() {
        // Tighter (minLength 1 -> 3) and a new optional property.
        let new = OLD_SCHEMA
            .replace("\"minLength\": 1", "\"minLength\": 3")
            .replace(
                "\"pinned\"",
                "\"color\": { \"type\": \"string\" }, \"pinned\"",
            );
        let changes = changes_between(OLD_SCHEMA, &new);
        let text = format_changes(&changes);
        assert!(text.find("TIGHTENING").unwrap() < text.find("COMPATIBLE").unwrap());
        assert!(!text.contains("BREAKING"));
        assert!(
            text.contains("note.title: minLength raised from 1 to 3"),
            "{text}"
        );
        assert!(report(&changes).is_ok());
    }

    #[test]
    fn diff_fails_on_breaking_changes_only() {
        let breaking = OLD_SCHEMA.replace(
            "\"pinned\": { \"type\": \"boolean\" }",
            "\"pinned\": { \"type\": \"string\" }",
        );
        let changes = changes_between(OLD_SCHEMA, &breaking);
        assert_eq!(changes[0].level, Level::Breaking);
        let error = report(&changes).unwrap_err().to_string();
        assert!(error.contains("1 breaking"), "{error}");

        assert!(changes_between(OLD_SCHEMA, OLD_SCHEMA).is_empty());
        assert!(report(&[]).is_ok());
    }

    #[test]
    fn lockfile_made_by_lock_notices_a_tightened_schema() {
        let file = temp_file("fingerprint.schema.json", OLD_SCHEMA);
        lock(&file, ONTOLOGY, None, None).unwrap();
        check(&file, None, None).unwrap();
        std::fs::write(
            &file,
            OLD_SCHEMA.replace("\"minLength\": 1", "\"minLength\": 3"),
        )
        .unwrap();
        let error = check(&file, None, None).unwrap_err().to_string();
        assert!(error.contains("`schema diff`"), "{error}");
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
