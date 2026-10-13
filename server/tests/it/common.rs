//! Shared server-lifecycle helpers for the integration-test suites.

use atomic_server_lib as atomic_server;
use std::time::Duration;

/// Start an AtomicServer on a random port in a background thread.
/// `name` namespaces the on-disk state under ./.temp/; a random suffix keeps
/// concurrent and repeated runs isolated.
pub fn start_server(name: &str) -> u16 {
    start_server_with_args(name, &[])
}

/// `start_server` with extra CLI flags appended, for suites that exercise a
/// non-default option (a small rate limit, a host mode).
pub fn start_server_with_args(name: &str, extra_args: &[&str]) -> u16 {
    spawn_server(name, extra_args, None)
}

/// `start_server_with_args`, also handing back the running server's store, for
/// suites that must act on the database directly (run a maintenance pass,
/// inspect blobs) while the server keeps serving.
pub fn start_server_with_store(name: &str, extra_args: &[&str]) -> (u16, atomic_lib::Db) {
    let (tx, rx) = std::sync::mpsc::channel();
    let port = spawn_server(name, extra_args, Some(tx));
    let store = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("server did not come up");
    (port, store)
}

fn spawn_server(
    name: &str,
    extra_args: &[&str],
    store_tx: Option<std::sync::mpsc::Sender<atomic_lib::Db>>,
) -> u16 {
    let unique = format!("{}_{}", name, atomic_lib::utils::random_string(10));
    let port = pick_port();

    use clap::Parser;
    let port_str = port.to_string();
    let data_dir = format!("./.temp/{unique}/db");
    let config_dir = format!("./.temp/{unique}/config");
    let mut args = vec![
        "atomic-server",
        "--initialize",
        // Loopback IPv4 rather than the `::` default: the tests connect to
        // `localhost` anyway, and a host without IPv6 (containers, some CI
        // sandboxes) cannot bind `::` at all, which used to kill every suite
        // at startup.
        "--ip",
        "127.0.0.1",
        "--port",
        &port_str,
        "--data-dir",
        &data_dir,
        "--config-dir",
        &config_dir,
    ];
    args.extend_from_slice(extra_args);
    let opts = atomic_server::config::Opts::parse_from(args);

    let mut config = atomic_server::config::build_config(opts).expect("config failed");
    config.search_index_path = format!("./.temp/{unique}/search").into();

    std::thread::spawn(move || {
        let rt = actix_web::rt::System::new();
        rt.block_on(async {
            atomic_server::serve::serve_with_hook(config, move |appstate| {
                if let Some(tx) = store_tx {
                    let _ = tx.send(appstate.store.clone());
                }
            })
            .await
            .unwrap();
        });
    });

    port
}

/// A free TCP port on localhost. `portpicker` insists that the port be free
/// for TCP *and* UDP on both IPv4 and IPv6, and reports "no free port" on a
/// host without a loopback IPv6 address (containers, some CI sandboxes),
/// which failed every suite here before any server started. The server only
/// needs IPv4 TCP, so fall back to asking the OS for one.
fn pick_port() -> u16 {
    if let Some(port) = portpicker::pick_unused_port() {
        return port;
    }
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("no free port")
}

/// Poll until the server answers HTTP. Every suite in this binary boots its
/// own server and they all run concurrently, so a single boot can take far
/// longer than it would alone; the deadline only bounds a wedged server.
pub async fn wait_for_server(port: u16) {
    let base = format!("http://localhost:{port}");

    for _ in 0..600 {
        if reqwest::get(&base).await.is_ok() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("Server did not start within 60 seconds");
}
