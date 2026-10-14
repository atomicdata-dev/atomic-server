//! `atomic-loadtest`: load generator for atomic-server.
//!
//! One tokio task per virtual user, built on `atomic_lib::client::ws::WsClient`
//! so the crypto and wire format match the real client. See README.md.

mod commit;
mod common;
mod connect;
mod storm;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "atomic-loadtest", about = "Load generator for atomic-server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Flags shared by every scenario.
#[derive(Args, Clone)]
pub struct Common {
    /// Server base URL, e.g. http://localhost:9883
    #[arg(long, default_value = "http://localhost:9883")]
    pub server: String,
    /// Write the JSON results here
    #[arg(long, default_value = "results.json")]
    pub out: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// N clients connect, AUTH and SUB; hold with keepalives
    Connect {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 100)]
        clients: usize,
        /// Spread the connection attempts evenly over this many seconds
        #[arg(long, default_value_t = 10.0)]
        ramp_secs: f64,
        /// Keep connections open this long after they are all started
        #[arg(long, default_value_t = 30.0)]
        hold_secs: f64,
        /// Spread clients over this many drives (round robin)
        #[arg(long, default_value_t = 1)]
        drives: usize,
    },
    /// W writers commit edits at R/s each; N subscribers measure fan-out lag
    Commit {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 2)]
        writers: usize,
        #[arg(long, default_value_t = 5)]
        subscribers: usize,
        /// Commits per second, per writer
        #[arg(long, default_value_t = 1.0)]
        rate: f64,
        /// Seconds of load
        #[arg(long, default_value_t = 30.0)]
        duration: f64,
        /// Spread the subscriber connections over this many seconds
        #[arg(long, default_value_t = 5.0)]
        ramp_secs: f64,
    },
    /// Reconnect storm: connect N clients, wait for the server to drop, measure recovery
    Storm {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 100)]
        clients: usize,
        #[arg(long, default_value_t = 10.0)]
        ramp_secs: f64,
        /// Shell command that kills/restarts the server. Its start is t0.
        #[arg(long)]
        kill_cmd: Option<String>,
        /// The operator restarts the server by hand; t0 is the first observed drop
        #[arg(long)]
        expect_restart: bool,
        /// Full jitter on the reconnect delay (the real client has none)
        #[arg(long)]
        jitter: bool,
        /// How long to wait for the drop to happen
        #[arg(long, default_value_t = 600.0)]
        wait_secs: f64,
        /// Give up this long after t0 and report who is still missing
        #[arg(long, default_value_t = 300.0)]
        max_recover_secs: f64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let (common, result) = match cli.cmd {
        Cmd::Connect {
            common,
            clients,
            ramp_secs,
            hold_secs,
            drives,
        } => {
            let r = connect::run(&common, clients, ramp_secs, hold_secs, drives).await;
            (common, r)
        }
        Cmd::Commit {
            common,
            writers,
            subscribers,
            rate,
            duration,
            ramp_secs,
        } => {
            let r = commit::run(&common, writers, subscribers, rate, duration, ramp_secs).await;
            (common, r)
        }
        Cmd::Storm {
            common,
            clients,
            ramp_secs,
            kill_cmd,
            expect_restart,
            jitter,
            wait_secs,
            max_recover_secs,
        } => {
            let opts = storm::Opts {
                clients,
                ramp_secs,
                kill_cmd,
                expect_restart,
                jitter,
                wait_secs,
                max_recover_secs,
            };
            let r = storm::run(&common, opts).await;
            (common, r)
        }
    };
    match result {
        Ok(json) => {
            let text = serde_json::to_string_pretty(&json).unwrap();
            if let Err(e) = std::fs::write(&common.out, text) {
                eprintln!("could not write {}: {e}", common.out);
                std::process::exit(2);
            }
            println!("results written to {}", common.out);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
