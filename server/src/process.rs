//! Checks if the process is running, kills a runnig process if it is.

use crate::{config::Config, errors::BetterResult};

/// Checks if the server is running. If it is, kill that process. Also creates creates a new PID.
pub fn terminate_existing_processes(config: &Config) -> BetterResult<()> {
    let pid_maybe = match std::fs::read_to_string(pid_path(config)) {
        Ok(content) => str::parse::<i32>(&content).ok(),
        Err(_e) => None,
    };
    if let Some(pid) = pid_maybe {
        let retry_secs = 1;
        let mut tries_left = 15;
        match futures::executor::block_on(heim::process::get(pid)) {
            Ok(process) => {
                log::warn!(
                    "Terminating existing running instance of atomic-server (process ID: {})...",
                    process.pid()
                );
                futures::executor::block_on(process.terminate())
                    .expect("Found running atomic-server, but could not terminate it.");
                log::info!("Checking if other server has succesfully terminated...",);
                loop {
                    if let Err(_e) = futures::executor::block_on(heim::process::get(pid)) {
                        log::info!("No other atomic-server is running, continuing start-up",);
                        break;
                    };
                    if tries_left > 1 {
                        tries_left -= 1;
                        log::info!(
                            "Other instance is still running, checking again in {} seconds, for {} more times ",
                            retry_secs,
                            tries_left
                        );
                        std::thread::sleep(std::time::Duration::from_secs(retry_secs));
                    } else {
                        log::error!("Could not terminate other atomic-server, exiting...");
                        std::process::exit(1);
                    }
                }
            }
            Err(_e) => (),
        }
    }
    create_pid(config)
}

/// Removes the process id file in the config directory meant for signaling this instance is running.
pub fn remove_pid(config: &Config) -> BetterResult<()> {
    if std::fs::remove_file(pid_path(config)).is_err() {
        log::warn!(
            "Could not remove process file at {}",
            pid_path(config).to_str().unwrap()
        )
    }
    Ok(())
}

const PID_NAME: &str = "atomic_server_process_id";

fn pid_path(config: &Config) -> std::path::PathBuf {
    std::path::Path::join(&config.config_dir, PID_NAME)
}

/// Writes a `pid` file in the config directory to signal which instance is running.
fn create_pid(config: &Config) -> BetterResult<()> {
    use std::io::Write;
    let pid = futures::executor::block_on(heim::process::current())
        .map_err(|_| "Failed to get process info required to create process ID")?
        .pid();
    let mut pid_file = std::fs::File::create(pid_path(config)).map_err(|_| {
        format!(
            "Could not create process file at {}",
            pid_path(config).to_str().unwrap(),
        )
    })?;
    pid_file
        .write_all(pid.to_string().as_bytes())
        .map_err(|_| "failed to write process file")?;
    Ok(())
}
