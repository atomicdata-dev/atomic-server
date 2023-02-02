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
