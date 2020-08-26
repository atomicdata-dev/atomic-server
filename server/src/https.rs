use acme_lib::create_p384_key;
use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl, Error};
use rustls::internal::pemfile::{certs, rsa_private_keys};
use rustls::{NoClientAuth, ServerConfig};
use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

/// Writes keys to disk using LetsEncrypt
pub fn request_cert(config: &crate::config::Config) -> Result<(), Error> {
    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    // let url = DirectoryUrl::LetsEncrypt;
    let url = DirectoryUrl::LetsEncryptStaging;

    let ssl_path = ".ssl";

    fs::create_dir_all(
        PathBuf::from(&ssl_path)
            .parent()
            .expect("Could not find parent folder"),
    )?;

    // Save/load keys and certificates to current dir.
    let persist = FilePersist::new(ssl_path);

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

    let cert_path = ".ssl/cert.pem";
    let key_path = ".ssl/key.pem";

    fs::write(cert_path, cert.certificate()).expect("Unable to write file");
    fs::write(key_path, cert.private_key()).expect("Unable to write file");

    Ok(())
}

// RUSTLS
pub fn get_ssl_config(config: &crate::config::Config) -> Result<ServerConfig, Error> {
    let mut ssl_config = ServerConfig::new(NoClientAuth::new());
    let cert_file =
        &mut BufReader::new(File::open(config.cert_path.clone().expect("No cert_path")).unwrap());
    let key_file =
        &mut BufReader::new(File::open(config.key_path.clone().expect("No cert_path")).unwrap());
    let cert_chain = certs(cert_file).unwrap();
    let mut keys = rsa_private_keys(key_file).unwrap();
    ssl_config
        .set_single_cert(cert_chain, keys.remove(0))
        .unwrap();

    Ok(ssl_config)
}
