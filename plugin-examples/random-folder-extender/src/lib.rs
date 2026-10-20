use atomic_plugin::{ClassExtender, Commit, CommitBuilder, Resource};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::Deserialize;

struct RandomFolderExtender;

#[derive(Deserialize)]
struct Config {
    #[serde(rename = "blacklistedFolderNames")]
    blacklisted_folder_names: Option<Vec<String>>,
}

const FOLDER_CLASS: &str = "https://atomicdata.dev/classes/Folder";
const NAME_PROP: &str = "https://atomicdata.dev/properties/name";
const IS_A: &str = "https://atomicdata.dev/properties/isA";

fn get_name_from_folder(folder: &Resource) -> Result<&str, String> {
    let name = folder
        .props
        .get(NAME_PROP)
        .and_then(|val| val.as_str())
        .ok_or("Folder name not found")?;

    Ok(name)
}

impl ClassExtender for RandomFolderExtender {
    fn class_url() -> Vec<String> {
        vec![FOLDER_CLASS.to_string()]
    }

    // Modify the response from the server every time a folder is fetched.
    // Appends a random number to the end of the folder name.
    fn on_resource_get(resource: &mut Resource) -> Result<Option<&Resource>, String> {
        let base_name = resource
            .props
            .get(NAME_PROP)
            .and_then(|val| val.as_str())
            .unwrap_or("Folder");

        let random_suffix = rand::thread_rng().gen_range(0..=9999);
        let updated_name = format!("{} {}", base_name.trim_end(), random_suffix);

        resource
            .props
            .insert(NAME_PROP.to_string(), updated_name.into());

        Ok(Some(resource))
    }

    // Enforce that folder names are unique. It looks up all folders and checks if any of them have the same name.
    fn before_commit(commit: &Commit, _snapshot: &Resource, _is_new: bool) -> Result<(), String> {
        let Some(set) = &commit.set else {
            return Ok(());
        };

        let Some(name) = set.get(NAME_PROP).and_then(|val| val.as_str()) else {
            return Ok(());
        };

        let all_folders = atomic_plugin::query(IS_A.to_string(), FOLDER_CLASS.to_string())?;
        let all_names: Vec<&str> = all_folders
            .iter()
            .filter_map(|folder| get_name_from_folder(folder).ok())
            .collect();

        if all_names.contains(&name) {
            return Err("Folder name must be unique".into());
        }

        let config = atomic_plugin::get_config::<Config>()
            .map_err(|_| "Could not parse plugin config".to_string())?;

        // Check if the folder name is in the blacklist.
        if config.blacklisted_folder_names.is_some()
            && config
                .blacklisted_folder_names
                .unwrap()
                .contains(&name.to_string())
        {
            return Err("Folder name is not allowed".into());
        }

        Ok(())
    }

    // Shuffle the name of the folder after every update, as the module's own agent.
    // The commit this writes does not trigger the hook again.
    fn after_commit(_commit: &Commit, resource: &Resource, _is_new: bool) -> Result<(), String> {
        let shuffled_name = shuffle_string(get_name_from_folder(resource)?);

        let mut commit_builder = CommitBuilder::new(resource.subject.clone());
        commit_builder.set(NAME_PROP.to_string(), shuffled_name.into());

        atomic_plugin::commit(&commit_builder)
    }
}

fn shuffle_string(string: &str) -> String {
    let mut chars = string.chars().collect::<Vec<char>>();
    let mut rng = rand::thread_rng();
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

atomic_plugin::export_plugin!(RandomFolderExtender);
