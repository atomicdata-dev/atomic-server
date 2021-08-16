//! Checks if the process is running, kills a runnig process if it is.

use crate::{config::Config, errors::BetterResult};

/// Checks if the server is running. If it is, kill that process. Also creates creates a new PID.
pub fn check_and_stop_running(config: &Config) -> BetterResult<()> {
    let pid_maybe = match std::fs::read_to_string(pid_path(config)) {
        Ok(content) => str::parse::<i32>(&content).ok(),
        Err(_e) => None,
    };
    if let Some(pid) = pid_maybe {
        match futures::executor::block_on(heim::process::get(pid)) {
            Ok(process) => {
                log::warn!("Terminating other running instance of atomic-server and waiting two seconds...");
                futures::executor::block_on(process.terminate())
                    .expect("Found running Atomic Server, but could not terminate it.");
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            Err(_e) => (),
        }
    }
    create_pid(config)
}

const PID_NAME: &str = "atomic_server_process_id";

fn pid_path(config: &Config) -> std::path::PathBuf {
    std::path::Path::join(&config.config_dir, PID_NAME)
}

/// Writes a `pid` file in the config directory to signal which instance is running.
fn create_pid(config: &Config) -> BetterResult<()> {
    use std::io::Write;
    let pid = futures::executor::block_on(heim::process::current())
        .unwrap()
        .pid();
    let mut pid_file = std::fs::File::create(pid_path(config)).unwrap();
    pid_file.write_all(pid.to_string().as_bytes()).unwrap();
    Ok(())
}

pub fn remove_pid(config: &Config) -> BetterResult<()> {
    std::fs::remove_file(pid_path(config)).unwrap();
    Ok(())
}
