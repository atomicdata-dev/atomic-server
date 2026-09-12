//! The key this node holds so it can use a secret with nobody present.
//!
//! Kept beside the config rather than inside the database it protects: a key
//! stored in the thing it encrypts protects nothing. What this buys is that
//! every way a store leaves the machine intact — a stolen disk, a backup, a
//! copied file, a support bundle — leaves with ciphertext.
//!
//! It does not protect against a compromised running server. It cannot: a
//! plugin importing at 3am has nobody to ask for a passkey, so the process
//! must be able to open what it opens. Claiming otherwise would be theatre.

use std::io::Write;
use std::path::{Path, PathBuf};

use atomic_lib::errors::AtomicResult;
use atomic_lib::vault::keys::KEK_LEN;

const FILE_NAME: &str = "node.key";

/// Owner read/write only. The default 0644 would leave this readable by every
/// account on the machine, which for a key file is the whole ballgame.
#[cfg(unix)]
const PRIVATE: u32 = 0o600;

pub fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(FILE_NAME)
}

/// Reads the node key, generating one the first time.
///
/// Generation is here rather than in setup so an existing installation gets a
/// key without being reinstalled, and so a deleted key file is a recoverable
/// mistake rather than a broken server: what is lost is what it wrapped, and
/// the message says so.
pub fn load_or_create(config_dir: &Path) -> AtomicResult<[u8; KEK_LEN]> {
    let file = path(config_dir);

    if file.exists() {
        let bytes =
            std::fs::read(&file).map_err(|e| format!("could not read {}: {e}", file.display()))?;

        return bytes.try_into().map_err(|_| {
            format!(
                "{} is not a {KEK_LEN}-byte key. If it was truncated or replaced, \
                 anything wrapped with the original cannot be recovered; delete it to \
                 start over and re-enter those secrets.",
                file.display(),
            )
            .into()
        });
    }

    let mut key = [0u8; KEK_LEN];
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| "could not generate a node key")?;

    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }

    write_private(&file, &key)?;
    tracing::info!("created a node key at {}", file.display());

    Ok(key)
}

/// Writes with owner-only permissions from the start.
///
/// Created private rather than created and then chmod'ed: between those two
/// steps the key would be readable, and that window is exactly when a
/// multi-user machine is interesting.
fn write_private(file: &Path, bytes: &[u8]) -> AtomicResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE);
    }

    let mut handle = options
        .open(file)
        .map_err(|e| format!("could not write {}: {e}", file.display()))?;

    handle
        .write_all(bytes)
        .map_err(|e| format!("could not write {}: {e}", file.display()))?;

    Ok(())
}

/// Narrows an existing file to owner-only.
///
/// For files written before this mattered — `config.toml` holds the server's
/// agent secret and was created world-readable.
pub fn restrict(file: &Path) -> AtomicResult<()> {
    if !file.exists() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let current = std::fs::metadata(file)
            .map_err(|e| format!("could not read {}: {e}", file.display()))?
            .permissions()
            .mode()
            & 0o777;

        if current != PRIVATE {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(PRIVATE))
                .map_err(|e| format!("could not restrict {}: {e}", file.display()))?;
            tracing::info!(
                "narrowed {} from {current:o} to {PRIVATE:o}",
                file.display(),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-node-key-{name}-{}",
            atomic_lib::utils::random_string(8),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        dir
    }

    #[test]
    fn the_same_key_comes_back() {
        let dir = temp_dir("stable");

        let first = load_or_create(&dir).unwrap();
        let second = load_or_create(&dir).unwrap();

        assert_eq!(
            first, second,
            "a new key each boot would orphan every secret"
        );
    }

    #[test]
    fn two_nodes_do_not_share_a_key() {
        assert_ne!(
            load_or_create(&temp_dir("a")).unwrap(),
            load_or_create(&temp_dir("b")).unwrap(),
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_key_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("perms");
        load_or_create(&dir).unwrap();

        let mode = std::fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, PRIVATE);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_file_gets_narrowed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("restrict");
        let file = dir.join("config.toml");
        std::fs::write(&file, "agent_secret = 'hunter2'").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        restrict(&file).unwrap();

        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PRIVATE);
    }

    #[test]
    fn a_truncated_key_says_what_was_lost() {
        let dir = temp_dir("truncated");
        std::fs::write(path(&dir), b"too short").unwrap();

        let error = load_or_create(&dir).unwrap_err().to_string();

        assert!(error.contains("cannot be recovered"), "{error}");
    }
}
