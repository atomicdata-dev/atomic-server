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
    let https_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    let cert_file =
        &mut BufReader::new(File::open(config.cert_path.clone()).expect("No HTTPS TLS key found."));
    let key_file =
        &mut BufReader::new(File::open(&config.key_path).expect("Could not open config key path"));
    let mut cert_chain = Vec::new();

    for bytes in certs(cert_file)? {
        let certificate = rustls::Certificate(bytes);
        cert_chain.push(certificate);
    }
    let mut keys = pkcs8_private_keys(key_file)?;
    if keys.is_empty() {
        panic!("No key found. Consider deleting the `.https` directory and restart to create new keys.")
    }
    Ok(https_config
        .with_single_cert(cert_chain, rustls::PrivateKey(keys.remove(0)))
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

    std::thread::sleep(std::time::Duration::from_secs(2));
    info!("Testing availability of {}", &well_known_url);

    let agent = ureq::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build();
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
        config.opts.email.clone().expect(
            "No email set - required for HTTPS certificate initialization with LetsEncrypt",
        );

    info!("Creating LetsEncrypt account with email {}", email);

    let (account, _creds) = instant_acme::Account::create(
        &instant_acme::NewAccount {
            contact: &[&format!("mailto:{}", email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        lets_encrypt_url,
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
    let identifier = instant_acme::Identifier::Dns(domain);
    let mut order = account
        .new_order(&instant_acme::NewOrder {
            identifiers: &[identifier],
        })
        .await
        .unwrap();

    assert!(matches!(
        order.state().status,
        instant_acme::OrderStatus::Pending
    ));

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations().await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());

    // if we have H11p01 challenges, we need to start a server to handle them, and eventually turn that off again
    let mut handle: Option<ServerHandle> = None;

    for authz in &authorizations {
        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == challenge_type)
            .ok_or(format!("no {:?} challenge found", challenge_type))?;

        let instant_acme::Identifier::Dns(identifier) = &authz.identifier;

        let key_auth = order.key_authorization(challenge);
        match challenge_type {
            instant_acme::ChallengeType::Http01 => {
                handle = Some(cert_init_server(config, challenge, &key_auth).await?);
            }
            instant_acme::ChallengeType::Dns01 => {
                println!("Please set the following DNS record then press any key:");
                println!(
                    "_acme-challenge.{} IN TXT {}",
                    identifier,
                    key_auth.dns_value()
                );
                std::io::stdin().read_line(&mut String::new()).unwrap();
            }
            instant_acme::ChallengeType::TlsAlpn01 => todo!("TLS-ALPN-01 is not supported"),
        }

        challenges.push((identifier, &challenge.url));
    }

    // Let the server know we're ready to accept the challenges.
    for (a, url) in &challenges {
        info!("Setting challenge ready for {} at {}", a, url);
        order.set_challenge_ready(url).await.unwrap();
    }

    // Exponentially back off until the order becomes ready or invalid.
    let mut tries = 1u8;
    let mut delay = std::time::Duration::from_millis(250);
    let url = authorizations.first().expect("Authorizations is empty");
    let state = loop {
        let state = order.state();
        info!("Order state: {:#?}", state);
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
            break state;
        }
        order.refresh().await.unwrap();

        delay *= 2;
        tries += 1;
        match tries < 10 {
            true => info!("order is not ready, waiting {delay:?}"),
            false => {
                return Err(format!(
                    "Giving up: order is not ready. For details, see the url: {url:?}"
                )
                .into());
            }
        }
        actix::clock::sleep(delay).await;
    };

    if state.status == OrderStatus::Invalid {
        return Err(format!("order is invalid, check {url:?}").into());
    }

    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.
    let mut params = rcgen::CertificateParams::new(names);
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = rcgen::Certificate::from_params(params).map_err(|e| e.to_string())?;
    let csr = cert.serialize_request_der().map_err(|e| e.to_string())?;

    // Finalize the order and print certificate chain, private key and account credentials.
    order.finalize(&csr).await.map_err(|e| e.to_string())?;

    let mut tries = 1u8;

    let cert_chain_pem = loop {
        match order.certificate().await {
            Ok(Some(cert_chain_pem)) => {
                info!("Certificate ready!");
                break cert_chain_pem;
            }
            Ok(None) => {
                if tries > 10 {
                    return Err("Giving up: certificate is still not ready".into());
                }
                tries += 1;
                info!("Certificate not ready yet...");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            Err(e) => return Err(format!("Error getting certificate {}", e).into()),
        }
    };

    write_certs(config, cert_chain_pem, cert)?;

    if let Some(hnd) = handle {
        warn!("HTTPS TLS Cert init successful! Stopping temporary HTTP server, starting HTTPS...");
        hnd.stop(true).await;
    }

    Ok(())
}

fn write_certs(
    config: &crate::config::Config,
    cert_chain_pem: String,
    cert: rcgen::Certificate,
) -> AtomicServerResult<()> {
    info!("Writing TLS certificates to {:?}", config.https_path);
    fs::create_dir_all(PathBuf::from(&config.https_path))?;
    fs::write(&config.cert_path, cert_chain_pem)?;
    fs::write(&config.key_path, cert.serialize_private_key_pem())?;
    set_certs_created_at_file(config);

    Ok(())
}
