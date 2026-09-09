//! Everything required for setting up HTTPS / TLS.
//! Instantiate a server for HTTP-01 check with letsencrypt,
//! checks if certificates are not outdated,
//! persists files on disk.

use crate::errors::AtomicServerResult;
use actix_web::{dev::ServerHandle, App, HttpServer};
use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};
use tracing::{info, warn};

/// Create RUSTLS server config from certificates in config dir
pub fn get_https_config(
    config: &crate::config::Config,
) -> AtomicServerResult<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    let https_config = rustls::ServerConfig::builder().with_no_client_auth();
    let cert_file =
        &mut BufReader::new(File::open(config.cert_path.clone()).expect("No HTTPS TLS key found."));
    let key_file =
        &mut BufReader::new(File::open(&config.key_path).expect("Could not open config key path"));
    let mut cert_chain = Vec::new();

    for cert in certs(cert_file) {
        cert_chain.push(cert?);
    }
    let mut keys = pkcs8_private_keys(key_file).collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        panic!("No key found. Consider deleting the `.https` directory and restart to create new keys.")
    }
    Ok(https_config
        .with_single_cert(cert_chain, keys.remove(0).into())
        .expect("Unable to create HTTPS config from certificates"))
}

pub fn certs_created_at_path(config: &crate::config::Config) -> PathBuf {
    let mut path = config
        .cert_path
        .parent()
        .unwrap_or_else(|| {
            panic!(
                "Cannot open parent dir of HTTPS certs {:?}",
                config.cert_path
            )
        })
        .to_path_buf();
    path.push("certs_created_at");
    path
}

/// Adds a file to the .https folder to indicate age of certificates
fn set_certs_created_at_file(config: &crate::config::Config) {
    let now_string = chrono::Utc::now();
    let path = certs_created_at_path(config);
    fs::write(&path, now_string.to_string())
        .unwrap_or_else(|_| panic!("Unable to write {:?}", &path));
}

/// Checks if the certificates need to be renewed.
/// Will be true if there are no certs yet.
pub fn should_renew_certs_check(config: &crate::config::Config) -> AtomicServerResult<bool> {
    if std::fs::File::open(&config.cert_path).is_err() {
        info!(
            "No HTTPS certificates found in {:?}, requesting new ones...",
            &config.https_path
        );
        return Ok(true);
    }
    let path = certs_created_at_path(config);

    let created_at = std::fs::read_to_string(&path)
        .map_err(|_| format!("Unable to read {:?}", &path))?
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| format!("failed to parse {:?}", &path))?;
    let certs_age: chrono::Duration = chrono::Utc::now() - created_at;
    // Let's Encrypt certificates are valid for three months, but I think renewing earlier provides a better UX
    let expired = certs_age > chrono::Duration::weeks(4);
    if expired {
        warn!("HTTPS Certificates expired, requesting new ones...")
        // This is where I might need to remove the `.https/` folder, but it seems like it's not necessary
    };
    Ok(expired)
}

/// Starts an HTTP Actix server for HTTPS certificate initialization.
/// Hosts `.well-known/acme-challenge` folder and the challenge file.
async fn cert_init_server(
    config: &crate::config::Config,
    challenge: &instant_acme::Challenge,
    key_auth: &instant_acme::KeyAuthorization,
) -> AtomicServerResult<ServerHandle> {
    let address = format!("{}:{}", config.opts.ip, config.opts.port);
    warn!("Server temporarily running in HTTP mode at {}, running Let's Encrypt Certificate initialization...", address);

    if config.opts.port != 80 {
        warn!(
            "HTTP port is {}, not 80. Should be 80 in most cases during LetsEncrypt setup. If you've correctly forwarded it, you can ignore this warning.",
            config.opts.port
        );
    }

    let mut well_known_folder = config.static_path.clone();
    well_known_folder.push("well-known");
    fs::create_dir_all(&well_known_folder)?;

    let mut challenge_path = well_known_folder.clone();
    challenge_path.push("acme-challenge");
    fs::create_dir_all(&challenge_path)?;
    challenge_path.push(&challenge.token);
    fs::write(challenge_path, key_auth.as_str())?;

    // Channel is used to send the server handle back to the main thread, so we can stop it later
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        actix_web::rt::System::new().block_on(async move {
            info!(
                "Starting HTTP server for HTTPS initialization at {}",
                &address
            );
            let init_server = HttpServer::new(move || {
                App::new().service(
                    actix_files::Files::new("/.well-known", well_known_folder.clone())
                        .show_files_listing(),
                )
            });

            let running_server = init_server.bind(&address)?.run();

            tx.send(running_server.handle())
                .expect("Error sending handle during HTTPS init.");

            running_server.await
        })
    });

    let handle = rx
        .recv()
        .map_err(|e| format!("Error receiving handle during HTTPS init. {}", e))?;

    let well_known_url = format!(
        "http://{}/.well-known/acme-challenge/{}",
        &config.opts.domain, &challenge.token
    );

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    info!("Testing availability of {}", &well_known_url);

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build()
        .into();
    let resp = agent.get(&well_known_url).call().map_err(|e| {
        format!(
            "Unable to test local server. Is it available at the right address? {}",
            e
        )
    })?;
    if resp.status() != 200 {
        warn!("Unable to test local server. Status: {}", resp.status());
    } else {
        info!("Server for HTTP initialization running correctly");
    }
    Ok(handle)
}

/// Sends a request to LetsEncrypt to create a certificate
pub async fn request_cert(config: &crate::config::Config) -> AtomicServerResult<()> {
    use instant_acme::OrderStatus;

    let challenge_type = if config.opts.https_dns {
        info!("Using DNS-01 challenge");
        instant_acme::ChallengeType::Dns01
    } else {
        info!("Using HTTP-01 challenge");
        instant_acme::ChallengeType::Http01
    };

    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let lets_encrypt_url = if config.opts.development {
        warn!(
            "Using LetsEncrypt staging server, not production. This is for testing purposes only and will not provide a working certificate."
        );
        instant_acme::LetsEncrypt::Staging.url()
    } else {
        instant_acme::LetsEncrypt::Production.url()
    };

    let email =
        config.opts.email.clone().ok_or(
            "No email set - required for HTTPS certificate initialization with LetsEncrypt",
        )?;

    info!("Creating LetsEncrypt account with email {}", email);

    let contact = format!("mailto:{}", email);
    let (account, _creds) = instant_acme::Account::builder()
        .map_err(|e| format!("Failed to create account builder: {}", e))?
        .create(
            &instant_acme::NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            lets_encrypt_url.to_owned(),
            None,
        )
        .await
        .map_err(|e| format!("Failed to create account: {}", e))?;

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let mut domain = config.opts.domain.clone();
    if config.opts.https_dns {
        // Set a wildcard subdomain. Not possible with Http-01 challenge, only Dns-01.
        domain = format!("*.{}", domain);
    }
    let identifiers = vec![instant_acme::Identifier::Dns(domain)];
    let mut order = account
        .new_order(&instant_acme::NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("Failed to create ACME order: {}", e))?;

    let order_status = order.state().status;
    if order_status != OrderStatus::Pending {
        return Err(format!(
            "New ACME order is in state {order_status:?}, expected it to be pending"
        )
        .into());
    }

    // For HTTP-01 challenges a temporary server answers on port 80; it must
    // go away again whether or not the order succeeds, since this also runs
    // from the renewal task while the real server is up.
    let mut handle: Option<ServerHandle> = None;
    let result = complete_order(config, &mut order, challenge_type, &mut handle).await;

    if let Some(hnd) = handle {
        match &result {
            Ok(()) => warn!(
                "HTTPS TLS Cert init successful! Stopping temporary HTTP server, starting HTTPS..."
            ),
            Err(_) => warn!("Stopping temporary HTTP server after failed certificate request"),
        }
        hnd.stop(true).await;
    }

    result
}

/// Answers the order's challenges, waits for it, and writes the certificate.
/// The temporary HTTP-01 server, if one was started, is handed back through
/// `handle` so the caller can stop it on either outcome.
async fn complete_order(
    config: &crate::config::Config,
    order: &mut instant_acme::Order,
    challenge_type: instant_acme::ChallengeType,
    handle: &mut Option<ServerHandle>,
) -> AtomicServerResult<()> {
    use instant_acme::OrderStatus;

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| format!("Failed to fetch authorization: {}", e))?;
            match authz.status {
                instant_acme::AuthorizationStatus::Pending => {}
                instant_acme::AuthorizationStatus::Valid => continue,
                other => {
                    return Err(format!(
                        "ACME authorization for {} is {other:?}; cannot request a certificate",
                        authz.identifier()
                    )
                    .into());
                }
            }

            let mut challenge = authz
                .challenge(challenge_type.clone())
                .ok_or(format!("no {:?} challenge found", challenge_type))?;
            let key_auth = challenge.key_authorization();
            match challenge_type {
                instant_acme::ChallengeType::Http01 => {
                    *handle = Some(cert_init_server(config, &challenge, &key_auth).await?);
                }
                instant_acme::ChallengeType::Dns01 => {
                    println!("Please set the following DNS record then press any key:");
                    println!(
                        "_acme-challenge.{} IN TXT {}",
                        challenge.identifier(),
                        key_auth.dns_value()
                    );
                    std::io::stdin()
                        .read_line(&mut String::new())
                        .map_err(|e| format!("Failed to read from stdin: {}", e))?;
                }
                other => {
                    return Err(format!("Unsupported ACME challenge type {other:?}").into());
                }
            }

            info!(
                "Setting challenge ready for {} at {}",
                challenge.identifier(),
                challenge.url
            );
            challenge
                .set_ready()
                .await
                .map_err(|e| format!("Failed to mark ACME challenge ready: {}", e))?;
        }
    }

    // Exponentially back off until the order becomes ready or invalid.
    let status = order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await
        .map_err(|e| format!("Failed while waiting for ACME order: {}", e))?;
    if status != OrderStatus::Ready {
        return Err(format!("unexpected ACME order status: {status:?}").into());
    }

    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("Failed to finalize ACME order: {}", e))?;
    let cert_chain_pem = order
        .poll_certificate(&instant_acme::RetryPolicy::default())
        .await
        .map_err(|e| format!("Error getting certificate {}", e))?;
    info!("Certificate ready!");

    write_certs(config, cert_chain_pem, private_key_pem)
}

fn write_certs(
    config: &crate::config::Config,
    cert_chain_pem: String,
    private_key_pem: String,
) -> AtomicServerResult<()> {
    info!("Writing TLS certificates to {:?}", config.https_path);
    fs::create_dir_all(PathBuf::from(&config.https_path))?;
    fs::write(&config.cert_path, cert_chain_pem)?;
    fs::write(&config.key_path, private_key_pem)?;
    set_certs_created_at_file(config);

    Ok(())
}
