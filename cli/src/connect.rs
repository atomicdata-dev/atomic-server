//! `atomic-cli connect`: sign in with a key made on this machine instead of
//! pasting your agent secret. It prints a link to the app, where you pick what
//! the key may reach and whether it may edit, and waits for you to click
//! Allow. You can revoke it later under Connected apps in account settings.
//!
//! Same flow as `@tomic/mcp connect` and `connectAgentUrl` in `@tomic/lib`:
//! the grant is the key being added to `read` (and `write`) on the shared
//! resources, so the key finds its access by searching for what lists it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use atomic_lib::agents::Agent;
use atomic_lib::client::search::SearchOpts;
use atomic_lib::config::{ClientConfig, Config, SharedConfig};
use atomic_lib::{errors::AtomicResult, urls, Storelike};

const WAIT: Duration = Duration::from_secs(15 * 60);
const POLL: Duration = Duration::from_secs(2);

pub struct ConnectOpts {
    pub server: String,
    /// Where the app runs, for the link. Defaults to `server`.
    pub app: Option<String>,
    pub name: String,
    /// Ask for edit rights. The person still decides.
    pub write: bool,
}

/// The page in the app where the person allows a key.
pub fn connect_agent_url(
    app: &str,
    public_key: &str,
    name: &str,
    write: bool,
) -> AtomicResult<String> {
    let mut url = url::Url::parse(app).map_err(|e| format!("Invalid app URL {app}: {e}"))?;
    url.set_path("/app/connect-agent");
    url.query_pairs_mut()
        .append_pair("key", public_key)
        .append_pair("name", name);
    if write {
        url.query_pairs_mut().append_pair("write", "1");
    }
    Ok(url.to_string())
}

/// What the person shared with the store's agent: resources whose `read`
/// lists it. Where it only has `write`, it created the resource itself.
async fn shared_with(store: &atomic_lib::Store, agent: &str) -> AtomicResult<Vec<String>> {
    let opts = SearchOpts {
        limit: Some(100),
        filters: Some(HashMap::from([(urls::READ.to_string(), agent.to_string())])),
        ..Default::default()
    };
    Ok(store
        .search("", opts)
        .await?
        .iter()
        .map(|r| r.get_subject().to_string())
        .collect())
}

/// Makes a key, waits for the person to allow it, and returns the config to save.
pub async fn connect(store: &atomic_lib::Store, opts: ConnectOpts) -> AtomicResult<Config> {
    let mut agent = Agent::new(Some(&opts.name))?;
    let subject = agent.subject.to_string();
    store.set_base_url(&opts.server);
    store.set_default_agent(agent.clone());

    // Only an agent may edit its own Agent resource, so this is the one place
    // the name the person sees in Connected apps can be set.
    if let Err(e) = publish_name(store, &subject, &opts.name).await {
        eprintln!("Could not publish this key's name ({e}); it will show as a key.");
    }

    let link = connect_agent_url(
        opts.app.as_deref().unwrap_or(&opts.server),
        &agent.public_key,
        &opts.name,
        opts.write,
    )?;
    println!(
        "\nOpen this link to let \"{}\" use your Atomic data:\n\n  {link}\n",
        opts.name
    );
    println!("Waiting for you to click Allow...");
    open_in_browser(&link);

    let deadline = Instant::now() + WAIT;
    let shared = loop {
        let shared = shared_with(store, &subject).await.unwrap_or_default();
        if !shared.is_empty() {
            break shared;
        }
        if Instant::now() > deadline {
            return Err(
                "Gave up waiting. Run `atomic-cli connect` again when you are ready.".into(),
            );
        }
        tokio::time::sleep(POLL).await;
    };

    let initial_drive = shared.first().cloned();
    agent.initial_drive = initial_drive.as_deref().map(Into::into);
    Ok(Config {
        shared: SharedConfig {
            agent_secret: agent.build_secret()?,
            initial_drive,
        },
        client: Some(ClientConfig {
            server_url: opts.server,
        }),
    })
}

async fn publish_name(store: &atomic_lib::Store, subject: &str, name: &str) -> AtomicResult<()> {
    let mut profile = store.get_resource(&subject.into()).await?;
    profile
        .set(
            urls::NAME.into(),
            atomic_lib::Value::String(name.into()),
            store,
        )
        .await?;
    profile.save_remote(store).await?;
    Ok(())
}

fn open_in_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    // No browser to open is fine: the printed link is enough.
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
