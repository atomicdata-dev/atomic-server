use atomic_lib::{agents::ForAgent, Storelike};
use atomic_server_lib::config::Opts;
use std::{fs::File, io::Write};

mod actor_messages;
mod appstate;
mod commit_monitor;
pub mod config;
mod content_types;
mod context;
mod errors;
mod handlers;
mod helpers;
mod host_mode;
#[cfg(feature = "https")]
mod https;
mod invite_token;
mod jsonerrors;
mod metrics;
pub mod plugins;
mod routes;
pub mod serve;
pub mod vector_search;
// #[cfg(feature = "search")]
mod iroh_transport;
#[cfg(test)]
mod tests;
mod trace;

#[actix_web::main]
async fn main() -> () {
    if let Err(e) = main_wrapped().await {
        use colored::Colorize;
        eprintln!("{}: {}", "Error".red(), e.message);
        std::process::exit(1);
    }
    std::process::exit(0);
}

async fn main_wrapped() -> errors::AtomicServerResult<()> {
    // Parse CLI commands, env vars
    let config = config::build_config(config::read_opts())
        .map_err(|e| format!("Initialization failed: {}", e))?;

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
            let appstate = appstate::AppState::init(config.clone()).await?;
            let outstr = appstate.store.export(!e.only_internal)?;
            std::fs::create_dir_all(path.parent().unwrap())
                .map_err(|e| format!("Failed to create directory {:?}. {}", path, e))?;
            let mut file = File::create(&path)
                .map_err(|e| format!("Failed to write file to {:?}. {}", path, e))?;
            write!(file, "{}", outstr)?;
            println!("Succesfully exported data to {}", path.to_str().unwrap());
            Ok(())
        }
        Some(config::Command::Import(import_opts)) => {
            let readstring = {
                let path = std::path::Path::new(&import_opts.file);
                std::fs::read_to_string(path)?
            };

            let appstate = appstate::AppState::init(config.clone()).await?;
            let importer_subject = if let Some(i) = &import_opts.parent {
                atomic_lib::Subject::from_raw(i, None)
            } else {
                atomic_lib::Subject::from_raw("internal:/import", None)
            };
            let parse_opts = atomic_lib::parse::ParseOpts {
                importer: Some(importer_subject),
                for_agent: ForAgent::Sudo,
                overwrite_outside: true,
                save: if import_opts.force {
                    atomic_lib::parse::SaveOpts::Save
                } else {
                    atomic_lib::parse::SaveOpts::Commit
                },
                signer: Some(appstate.store.get_default_agent()?),
                ..Default::default()
            };
            println!("Importing...");
            appstate.store.import(&readstring, &parse_opts).await?;
            atomic_lib::search::build_search_index(&appstate.store)?;
            println!("Successfully imported {:?} to store.", import_opts.file);
            Ok(())
        }
        Some(config::Command::ShowConfig) => {
            println!("{:#?}", config);
            Ok(())
        }
        Some(config::Command::Compact) => {
            let redb_path = config.store_path.join("atomic.redb");
            if !redb_path.exists() {
                return Err(format!(
                    "No redb file found at {}. Has the server ever run with this --data-dir?",
                    redb_path.display()
                )
                .into());
            }
            println!("Compacting {}...", redb_path.display());
            println!("(This holds an exclusive lock — make sure no atomic-server is running.)");
            let t = std::time::Instant::now();
            let (size_before, size_after, did_compact) =
                atomic_lib::db::redb_store::compact_file(&redb_path)?;
            let elapsed = t.elapsed();
            let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
            let saved = size_before.saturating_sub(size_after);
            println!(
                "{} in {:.1?}: {:.1} MiB → {:.1} MiB (saved {:.1} MiB, {:.1}%)",
                if did_compact {
                    "Compacted"
                } else {
                    "No compaction needed"
                },
                elapsed,
                mib(size_before),
                mib(size_after),
                mib(saved),
                if size_before > 0 {
                    100.0 * saved as f64 / size_before as f64
                } else {
                    0.0
                },
            );
            Ok(())
        }
        Some(config::Command::Reset) => {
            if dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                format!("Warning!! Do you really want to remove all data from your atomic-server? This will delete {:?}", &config.store_path),
            )
            .interact()
            .unwrap()
            {
                std::fs::remove_dir_all(config.store_path).map(|e| format!("unable to remove directory: {:?}", e))?;
                let _ = std::fs::remove_dir_all(&config.search_index_path);
                println!("Done");
            } else {
                println!("Ok, not removing anything.");
            }
            Ok(())
        }
        Some(config::Command::CreateDotEnv) => {
            let current_path = std::env::current_dir()?;
            let pathstr = format!(
                "{}/.env",
                current_path.to_str().expect("Cannot render path")
            );
            if std::path::Path::new(&pathstr).exists() {
                tracing::error!(".env already exists at {}", pathstr);
                panic!("{} already exists", pathstr);
            }
            let mut file = File::create(&pathstr)
                .map_err(|e| format!("Failed to write file to {:?}. {}", current_path, e))?;

            use clap::CommandFactory;
            let command = Opts::command();

            let mut out = String::from("# Generated by `atomic-server generate-dotenv`. \n\n");
            for arg in command.get_arguments() {
                if let Some(env) = arg.get_env() {
                    let Some(hint) = arg.get_help() else {
                        continue;
                    };
                    out.push_str(&format!("# {}\n", hint));
                    let possible_vals = arg.get_possible_values();
                    if !possible_vals.is_empty() {
                        out.push_str(&format!(
                            "# Possible values: {:?}\n",
                            possible_vals
                                .iter()
                                .map(|v| v.get_name())
                                .collect::<Vec<&str>>()
                        ));
                    }
                    let default = arg
                        .get_default_values()
                        .first()
                        .map(|v| v.to_str().expect("Can't convert default value to str"));
                    out.push_str(&format!(
                        "# {}={}\n\n",
                        env.to_str().expect("Can't convert env to string"),
                        default.unwrap_or("")
                    ));
                }
            }
            file.write_all(out.as_bytes())?;

            println!("Successfully created {}", pathstr);
            Ok(())
        }
        None => serve::serve(config).await,
    }
}
