//! Everything required for setting up HTTPS.
//! Calls the Let's Encrypt API to get a certificate.

use acme_lib::create_p384_key;
use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl, Error};
use actix_web::{App, HttpServer};

use std::sync::mpsc;
use std::{
    fs::{self},
    path::PathBuf,
};

use crate::errors::AtomicServerResult;
use crate::https::set_certs_created_at_file;

/// Starts an HTTP Actix server for HTTPS certificate initialization
pub async fn cert_init_server(config: &crate::config::Config) -> AtomicServerResult<()> {
    let address = format!("{}:{}", config.opts.ip, config.opts.port);
    tracing::warn!("Server temporarily running in HTTP mode at {}, running Let's Encrypt Certificate initialization...", address);

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
                .expect("Error sending handle during HTTPS init");

            running_server.await
        })
    });

    let handle = rx.recv().expect("Error receiving handle during HTTPS init");

    let agent = ureq::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build();

    let well_known_url = format!("http://{}/.well-known/", &config.opts.domain);
    tracing::info!("Testing availability of {}", &well_known_url);
    let resp = agent
        .get(&well_known_url)
        .call()
        .expect("Unable to send request for Let's Encrypt initialization");
    if resp.status() != 200 {
        return Err(
            "Server for HTTP initialization not available, returning a non-200 status code".into(),
        );
    } else {
        tracing::info!("Server for HTTP initialization running correctly");
    }

    request_cert(config).map_err(|e| format!("Certification init failed: {}", e))?;
    tracing::warn!("HTTPS TLS Cert init sucesful! Stopping HTTP server, starting HTTPS...");
    handle.stop(true).await;
    Ok(())
}

/// Writes keys to disk using LetsEncrypt
fn request_cert(config: &crate::config::Config) -> Result<(), Error> {
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
    tracing::info!("Requesting Let's Encrypt account with {}", email);
    let acc = dir.account(&email)?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(&config.opts.domain, &[])?;

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

        tracing::info!("Writing ACME challange to {:?}", challenge_path);

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
    tracing::info!("Downloading certificate...");
    let cert = ord_cert.download_and_save_cert()?;

    fs::write(&config.cert_path, cert.certificate()).expect("Unable to write file");
    fs::write(&config.key_path, cert.private_key()).expect("Unable to write file");
    set_certs_created_at_file(config);
    tracing::info!("HTTPS init Success!");
    Ok(())
}
