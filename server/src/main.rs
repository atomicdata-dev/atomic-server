mod actor_messages;
mod appstate;
mod commit_monitor;
mod config;
mod content_types;
mod errors;
mod handlers;
mod helpers;
mod https;
mod jsonerrors;
mod process;
mod routes;
mod serve;
#[cfg(feature = "desktop")]
mod tray_icon;

use atomic_lib::{errors::AtomicResult, Storelike};
use std::{fs::File, io::Write};

#[actix_web::main]
async fn main() -> AtomicResult<()> {
    // Parse CLI commands, env vars
    let config = config::init().map_err(|e| format!("Initialization failed: {}", e))?;

    // All subcommands (as of now) also require appstate, which is why we have this logic below initial CLI logic.
    match &config.opts.command {
        Some(config::Command::Export(e)) => {
            let path = match e.path.clone() {
                Some(p) => std::path::Path::new(&p).to_path_buf(),
                None => {
                    let date = chrono::Local::now().to_rfc3339();
                    let pathstr = format!("backups/{}.json", date);
                    let mut pt = config.config_dir.clone();
                    pt.push(&pathstr);
                    pt
                }
            };
            let appstate = appstate::init(config.clone())?;
            let outstr = appstate.store.export(true)?;
            std::fs::create_dir_all(path.parent().unwrap())
                .map_err(|e| format!("Failed to create directory {:?}. {}", path, e))?;
            let mut file = File::create(&path)
                .map_err(|e| format!("Failed to write file to {:?}. {}", path, e))?;
            use std::io::Write;
            write!(file, "{}", outstr)?;
            println!("Succesfully exported data to {}", path.to_str().unwrap());
            Ok(())
        }
        Some(config::Command::Import(o)) => {
            let path = std::path::Path::new(&o.path);
            let readstring = std::fs::read_to_string(path)?;
            let appstate = appstate::init(config.clone())?;
            appstate.store.import(&readstring)?;

            println!("Sucesfully imported {:?} to store.", o.path);
            Ok(())
        }
        Some(config::Command::SetupEnv) => {
            let current_path = std::env::current_dir()?;
            let pathstr = format!(
                "{}/.env",
                current_path.to_str().expect("Cannot render path")
            );
            if std::path::Path::new(&pathstr).exists() {
                log::error!(".env already exists at {}", pathstr);
                panic!("{} already exists", pathstr);
            }
            let mut file = File::create(&pathstr)
                .map_err(|e| format!("Failed to write file to {:?}. {}", current_path, e))?;
            let default_env = include_str!("../default.env");
            file.write_all(default_env.as_bytes())?;

            println!("Sucesfully created {}", pathstr);
            Ok(())
        }
        None => crate::serve::serve(config).await,
    }
}
