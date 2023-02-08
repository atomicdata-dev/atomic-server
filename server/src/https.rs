//! Everything required for getting HTTPS config from storage.
use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use crate::errors::AtomicServerResult;
// RUSTLS
pub fn get_https_config(
    config: &crate::config::Config,
) -> AtomicServerResult<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    let https_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    // rustls::NoClientAuth::new()
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
    // ~/.config/atomic/https
    let mut path = config
        .cert_path
        .parent()
        .unwrap_or_else(|| {
            panic!(
                "Cannot open parent dit of HTTPS certs {:?}",
                config.cert_path
            )
        })
        .to_path_buf();
    path.push("certs_created_at");
    path
}

/// Adds a file to the .https folder to indicate age of certificates
pub fn set_certs_created_at_file(config: &crate::config::Config) {
    let now_string = chrono::Utc::now();
    let path = certs_created_at_path(config);
    fs::write(&path, now_string.to_string())
        .unwrap_or_else(|_| panic!("Unable to write {:?}", &path));
}

/// Checks if the certificates need to be renewed.
/// Will be true if there are no certs yet.
pub fn should_renew_certs_check(config: &crate::config::Config) -> bool {
    if std::fs::File::open(&config.cert_path).is_err() {
        return true;
    }
    let path = certs_created_at_path(config);

    let created_at = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Unable to read {:?}", &path))
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|_| panic!("failed to parse {:?}", &path));
    let certs_age: chrono::Duration = chrono::Utc::now() - created_at;
    // Let's Encrypt certificates are valid for three months, but I think renewing earlier provides a better UX.
    let expired = certs_age > chrono::Duration::weeks(4);
    if expired {
        tracing::warn!("HTTPS Certificates expired, requesting new ones...")
        // This is where I might need to remove the `.https/` folder, but it seems like it's not necessary
    };
    expired
}

use actix_web::{App, HttpServer};
use instant_acme::OrderStatus;
use tracing::info;

use std::sync::mpsc;

/// Starts an HTTP Actix server for HTTPS certificate initialization
pub async fn cert_init_server(config: &crate::config::Config) -> AtomicServerResult<()> {
    let address = format!("{}:{}", config.opts.ip, config.opts.port);
    tracing::warn!("Server temporarily running in HTTP mode at {}, running Let's Encrypt Certificate initialization...", address);

    if config.opts.port != 80 {
        tracing::warn!(
            "HTTP port is {}, not 80. Should be 80 in most cases during LetsEncrypt setup.",
            config.opts.port
        );
    }

    let mut well_known_folder = config.static_path.clone();
    well_known_folder.push("well-known");
    fs::create_dir_all(&well_known_folder)?;

    let (tx, rx) = mpsc::channel();

    let address_clone = address.clone();

    std::thread::spawn(move || {
        actix_web::rt::System::new().block_on(async move {
            let init_server = HttpServer::new(move || {
                App::new().service(
                    actix_files::Files::new("/.well-known", well_known_folder.clone())
                        .show_files_listing(),
                )
            });

            let running_server = init_server.bind(&address_clone)?.run();

            tx.send(running_server.handle())
                .expect("Error sending handle during HTTPS init.");

            running_server.await
        })
    });

    let handle = rx
        .recv()
        .map_err(|e| format!("Error receiving handle during HTTPS init. {}", e))?;

    let agent = ureq::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build();

    let well_known_url = format!("http://{}/.well-known/", &config.opts.domain);
    tracing::info!("Testing availability of {}", &well_known_url);
    let resp = agent.get(&well_known_url).call().map_err(|e| {
        format!(
            "Unable to send request for Let's Encrypt initialization. {}",
            e
        )
    })?;
    if resp.status() != 200 {
        return Err(
            "Server for HTTP initialization not available, returning a non-200 status code".into(),
        );
    } else {
        tracing::info!("Server for HTTP initialization running correctly");
    }

    request_cert(config)
        .await
        .map_err(|e| format!("Certification init failed: {}", e))?;
    tracing::warn!("HTTPS TLS Cert init sucesful! Stopping HTTP server, starting HTTPS...");
    handle.stop(true).await;
    Ok(())
}

async fn request_cert(config: &crate::config::Config) -> AtomicServerResult<()> {
    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let url = if config.opts.development {
        instant_acme::LetsEncrypt::Staging.url()
    } else {
        instant_acme::LetsEncrypt::Production.url()
    };

    let email =
        config.opts.email.clone().expect(
            "No email set - required for HTTPS certificate initialization with LetsEncrypt",
        );

    info!("Creating LetsEncrypt account with email {}", email);

    let account = instant_acme::Account::create(
        &instant_acme::NewAccount {
            contact: &[&email],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
    )
    .await
    .map_err(|e| format!("Failed to create account: {}", e))?;

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let identifier = instant_acme::Identifier::Dns(config.opts.domain.clone());
    let (mut order, state) = account
        .new_order(&instant_acme::NewOrder {
            identifiers: &[identifier],
        })
        .await
        .unwrap();

    tracing::info!("order state: {:#?}", state);
    assert!(matches!(state.status, instant_acme::OrderStatus::Pending));

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations(&state.authorizations).await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == instant_acme::ChallengeType::Http01)
            .ok_or("no Http01 challenge found")?;

        let instant_acme::Identifier::Dns(identifier) = &authz.identifier;

        println!("Please set the following DNS record then press any key:");
        println!(
            "_acme-challenge.{} IN TXT {}",
            identifier,
            order.key_authorization(challenge).dns_value()
        );
        std::io::stdin().read_line(&mut String::new()).unwrap();

        challenges.push((identifier, &challenge.url));
    }

    // Let the server know we're ready to accept the challenges.
    for (_, url) in &challenges {
        order.set_challenge_ready(url).await.unwrap();
    }

    // Exponentially back off until the order becomes ready or invalid.
    let mut tries = 1u8;
    let mut delay = std::time::Duration::from_millis(250);
    let state = loop {
        actix::clock::sleep(delay).await;
        let state = order.state().await.unwrap();
        if let instant_acme::OrderStatus::Ready | instant_acme::OrderStatus::Invalid = state.status
        {
            tracing::info!("order state: {:#?}", state);
            break state;
        }

        delay *= 2;
        tries += 1;
        match tries < 5 {
            true => info!(?state, tries, "order is not ready, waiting {delay:?}"),
            false => {
                return Err("order is not ready".into());
            }
        }
    };

    if state.status == OrderStatus::Invalid {
        return Err("order is invalid".into());
    }

    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = rcgen::CertificateParams::new(names.clone());
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = rcgen::Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der().map_err(|e| e.to_string())?;

    // Finalize the order and print certificate chain, private key and account credentials.

    let cert_chain_pem = order.finalize(&csr, &state.finalize).await.unwrap();
    info!("certficate chain:\n\n{}", cert_chain_pem,);
    info!("private key:\n\n{}", cert.serialize_private_key_pem());
    info!(
        "account credentials:\n\n{}",
        serde_json::to_string_pretty(&account.credentials()).unwrap()
    );
    fs::write(&config.cert_path, cert_chain_pem).expect("Unable to write cert file");
    fs::write(&config.key_path, cert.serialize_private_key_pem())
        .expect("Unable to write key file");
    set_certs_created_at_file(config);

    Ok(())
}
