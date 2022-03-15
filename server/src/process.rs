//! Checks if the process is running, kills a running process if it is.

use crate::{config::Config, errors::AtomicServerResult};

/// Checks if the server is running. If it is, kill that process. Also creates creates a new PID.
pub fn terminate_existing_processes(config: &Config) -> AtomicServerResult<()> {
    let pid_maybe = match std::fs::read_to_string(pid_path(config)) {
        Ok(content) => str::parse::<i32>(&content).ok(),
        Err(_e) => None,
    };
    if let Some(pid_int) = pid_maybe {
        let pid = pid_int.into();
        use sysinfo::{ProcessExt, SystemExt};
        let mut s = sysinfo::System::new_all();
        let retry_secs = 1;
        let mut tries_left = 30;
        // either friendly (Terminate) or not friendly (Kill)
        let mut signal = sysinfo::Signal::Term;
        if let Some(process) = s.process(pid) {
            tracing::warn!(
                "Terminating existing running instance of atomic-server (process ID: {})...",
                process.pid()
            );
            process.kill();
            tracing::info!("Checking if other server has successfully terminated...",);
            loop {
                s.refresh_processes();
                if let Some(_process) = s.process(pid) {
                    if tries_left > 1 {
                        tries_left -= 1;
                        tracing::info!(
                            "Other instance is still running, checking again in {} seconds, for {} more times ",
                            retry_secs,
                            tries_left
                        );
                        std::thread::sleep(std::time::Duration::from_secs(retry_secs));
                    } else {
                        if signal == sysinfo::Signal::Kill {
                            tracing::error!("Could not terminate other atomic-server, exiting...");
                            std::process::exit(1);
                        }
                        tracing::warn!(
                            "Terminate signal did not work, let's try again with Kill...",
                        );
                        _process.kill();
                        tries_left = 15;
                        signal = sysinfo::Signal::Kill;
                    }
                    continue;
                };
                tracing::info!("No other atomic-server is running, continuing start-up",);
                break;
            }
        }
    }
    create_pid(config)
}

/// Removes the process id file in the config directory meant for signaling this instance is running.
pub fn remove_pid(config: &Config) -> AtomicServerResult<()> {
    if std::fs::remove_file(pid_path(config)).is_err() {
        tracing::warn!(
            "Could not remove process file at {}",
            pid_path(config).to_str().unwrap()
        )
    } else {
        tracing::info!(
            "Removed process file at {}",
            pid_path(config).to_str().unwrap()
        );
    }
    Ok(())
}

const PID_NAME: &str = "atomic_server_process_id";

fn pid_path(config: &Config) -> std::path::PathBuf {
    std::path::Path::join(&config.config_dir, PID_NAME)
}

/// Writes a `pid` file in the config directory to signal which instance is running.
fn create_pid(config: &Config) -> AtomicServerResult<()> {
    use std::io::Write;
    let pid = sysinfo::get_current_pid()
        .map_err(|_| "Failed to get process info required to create process ID")?;
    let mut pid_file = std::fs::File::create(pid_path(config)).map_err(|e| {
        format!(
            "Could not create process file at {}. {}",
            pid_path(config).to_str().unwrap(),
            e
        )
    })?;
    pid_file
        .write_all(pid.to_string().as_bytes())
        .map_err(|e| format!("failed to write process file. {}", e))?;
    Ok(())
}
