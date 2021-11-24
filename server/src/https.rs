//! Everything required for setting up HTTPS.

use acme_lib::create_p384_key;
use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl, Error};
use actix_web::{App, HttpServer};

use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

/// Path to a file that contains the date where the certificate was created
const CERTS_CREATED_AT: &str = "./.https/certs_created_at";

/// Starts an HTTP Actix server for HTTPS certificate initialization
pub async fn cert_init_server(config: &crate::config::Config) -> Result<(), Error> {
    log::warn!("Server temporarily running in HTTP mode, running Let's Encrypt Certificate initialization...");
    let http_endpoint = format!("{}:{}", config.opts.ip, config.opts.port);
    let mut well_known_folder = config.static_path.clone();
    well_known_folder.push("well-known");
    fs::create_dir_all(&well_known_folder)?;
    let init_server = HttpServer::new(move || {
        App::new().service(
            actix_files::Files::new("/.well-known", well_known_folder.clone()).show_files_listing(),
        )
    });
    let running_server = init_server
        .bind(&http_endpoint)
        .expect(&*format!("Cannot bind to endpoint {}", &http_endpoint))
        .run();
    crate::https::request_cert(config).map_err(|e| format!("Certification init failed: {}", e))?;
    log::warn!("HTTPS TLS Cert init sucesful! Stopping HTTP server, starting HTTPS...");
    running_server.handle().stop(true).await;
    Ok(())
}

/// Writes keys to disk using LetsEncrypt
pub fn request_cert(config: &crate::config::Config) -> Result<(), Error> {
    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    let url = if config.opts.development {
        DirectoryUrl::LetsEncryptStaging
    } else {
        DirectoryUrl::LetsEncrypt
    };

    fs::create_dir_all(PathBuf::from(&config.https_path))?;

    // Save/load keys and certificates to current dir.
    let persist = FilePersist::new(&config.https_path);

    // Create a directory entrypoint.
    let dir = Directory::from_url(persist, url)?;

    // Reads the private account key from persistence, or
    // creates a new one before accessing the API to establish
    // that it's there.
    let email = config
        .opts
        .email
        .clone()
        .expect("ATOMIC_EMAIL must be set for HTTPS init");
    log::info!("Requesting Let's Encrypt account with {}", email);
    let acc = dir.account(&email)?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(&*config.opts.domain, &[])?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = ord_new.authorizations()?;

        // For HTTP, the challenge is a text file that needs to
        // be placed in your web server's root:
        //
        // /var/www/.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://mydomain.io/.well-known/acme-challenge/<token>
        let chall = auths[0].http_challenge();

        // The token is the filename.
        let token = chall.http_token();

        let formatted_path = format!("well-known/acme-challenge/{}", token);
        let mut challenge_path = config.static_path.clone();
        challenge_path.push(formatted_path);

        // The proof is the contents of the file
        let proof = chall.http_proof();

        log::info!("Writing ACME challange to {:?}", challenge_path);

        fs::create_dir_all(
            PathBuf::from(&challenge_path)
                .parent()
                .expect("Could not find parent folder"),
        )
        .expect("Unable to create dirs");

        fs::write(challenge_path, proof).expect("Unable to write file");

        // Here you must do "something" to place
        // the file/contents in the correct place.
        // update_my_web_server(&path, &proof);

        // After the file is accessible from the web, the calls
        // this to tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        chall.validate(5000)?;

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let pkey_pri = create_p384_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;

    // Now download the certificate. Also stores the cert in
    // the persistence.
    log::info!("Downloading certificate...");
    let cert = ord_cert.download_and_save_cert()?;

    fs::write(&config.cert_path, cert.certificate()).expect("Unable to write file");
    fs::write(&config.key_path, cert.private_key()).expect("Unable to write file");
    add_certs_created_at();
    log::info!("HTTPS init Success!");
    Ok(())
}

// RUSTLS
pub fn get_https_config(config: &crate::config::Config) -> Result<rustls::ServerConfig, Error> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    let https_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    // rustls::NoClientAuth::new()
    let cert_file =
        &mut BufReader::new(File::open(config.cert_path.clone()).expect("No HTTPS TLS key found."));
    let key_file = &mut BufReader::new(File::open(&config.key_path).unwrap());
    let cert_chain = certs(cert_file).unwrap();
    let first_cert = cert_chain.first().unwrap().to_owned();
    let mut keys = pkcs8_private_keys(key_file).unwrap();
    if keys.is_empty() {
        panic!("No key found. Consider deleting the `.https` directory and restart to create new keys.")
    }
    let a = https_config
        .with_single_cert(
            vec![rustls::Certificate(first_cert)],
            rustls::PrivateKey(keys.remove(0)),
        )
        .unwrap();
    Ok(a)
}

/// Adds a file to the .https folder to indicate age of certificates
fn add_certs_created_at() {
    let now_string = chrono::Utc::now();
    fs::write(CERTS_CREATED_AT, now_string.to_string())
        .expect(&*format!("Unable to write {}", CERTS_CREATED_AT));
}

/// Checks if the certificates need to be renewed.
pub fn check_expiration_certs() -> bool {
    let created_at = std::fs::read_to_string(CERTS_CREATED_AT)
        .expect(&*format!("Unable to read {}", CERTS_CREATED_AT))
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect(&*format!("failed to parse {}", CERTS_CREATED_AT));
    let certs_age: chrono::Duration = chrono::Utc::now() - created_at;
    // Let's Encrypt certificates are valid for three months, but I think renewing earlier provides a better UX.
    let expired = certs_age > chrono::Duration::weeks(4);
    if expired {
        log::warn!("HTTPS Certificates expired, requesting new ones...")
        // This is where I might need to remove the `.https/` folder, but it seems like it's not necessary
    };
    expired
}
