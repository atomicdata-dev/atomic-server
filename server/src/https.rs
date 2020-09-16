//! Everything required for setting up SSL / HTTPS.

use actix_web::{HttpServer, App};
use acme_lib::create_p384_key;
use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl, Error};

use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

pub async fn cert_init_server(config: &crate::config::Config) -> Result<(), Error> {
    log::warn!("Server temporarily running in HTTP mode, running Let's Encrypt Certificate initialization...");
    let http_endpoint = format!("{}:{}", config.ip, config.port);
    let init_server = HttpServer::new(move || {
        App::new()
            .service(actix_files::Files::new("/.well-known", "static/well-known/").show_files_listing())
    });
    let running_server = init_server
        .bind(&http_endpoint).expect(&*format!("Cannot bind to endpoint {}", &http_endpoint))
        .run();
    crate::https::request_cert(&config).expect("Certification init failed.");
    log::warn!("HTTPS TLS Cert init sucesful! Stopping HTTP server, starting HTTPS...");
    running_server.stop(true).await;
    Ok(())
}

/// Writes keys to disk using LetsEncrypt
pub fn request_cert(config: &crate::config::Config) -> Result<(), Error> {
    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    let mut url = DirectoryUrl::LetsEncrypt;
    if config.development {
        url = DirectoryUrl::LetsEncryptStaging;
    }

    let https_path = ".https";

    fs::create_dir_all(PathBuf::from(&https_path))?;

    // Save/load keys and certificates to current dir.
    let persist = FilePersist::new(https_path);

    // Create a directory entrypoint.
    let dir = Directory::from_url(persist, url)?;

    // Reads the private account key from persistence, or
    // creates a new one before accessing the API to establish
    // that it's there.
    let email = config
        .email
        .clone()
        .expect("ATOMIC_EMAIL must be set for HTTPS init");
    log::info!("Requesting Let's Encrypt account with {}", email);
    let acc = dir.account(&email)?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(&*config.domain, &[])?;

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
        let path = format!("static/well-known/acme-challenge/{}", token);

        // The proof is the contents of the file
        let proof = chall.http_proof();

        log::info!("Writing ACME challange to {}", path);

        fs::create_dir_all(
            PathBuf::from(&path)
                .parent()
                .expect("Could not find parent folder"),
        )
        .expect("Unable to create dirs");

        fs::write(path, proof).expect("Unable to write file");

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

    fs::write(config.cert_path.clone(), cert.certificate()).expect("Unable to write file");
    fs::write(config.key_path.clone(), cert.private_key()).expect("Unable to write file");
    log::info!("HTTPS init Success!");
    Ok(())
}

// RUSTLS
pub fn get_ssl_config(config: &crate::config::Config) -> Result<rustls::ServerConfig, Error> {
    use rustls::internal::pemfile::{certs, pkcs8_private_keys};
    let mut ssl_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let cert_file = &mut BufReader::new(
        File::open(config.cert_path.clone())
            .expect("No SSL key found."),
    );
    let key_file = &mut BufReader::new(File::open(config.key_path.clone()).unwrap());
    let cert_chain = certs(cert_file).unwrap();
    let mut keys = pkcs8_private_keys(key_file).unwrap();
    if keys.is_empty() {
        panic!("No key found. Consider deleting the `.ssl` directory and restart to create new keys.")
    }
    ssl_config
        .set_single_cert(cert_chain, keys.remove(0))
        .unwrap();
    Ok(ssl_config)
}
