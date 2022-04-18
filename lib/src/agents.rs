//! Logic for Agents
//! Agents are actors (such as users) that can edit content.
//! https://docs.atomicdata.dev/commits/concepts.html

use crate::{errors::AtomicResult, urls, Resource, Storelike};

#[derive(Clone, Debug)]
pub struct Agent {
    /// Private key for signing commits
    pub private_key: Option<String>,
    /// Private key for signing commits
    pub public_key: String,
    /// URL of the Agent
    pub subject: String,
    pub created_at: i64,
    pub name: Option<String>,
}

impl Agent {
    /// Converts Agent to Resource.
    /// Does not include private key, only public.
    pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        let mut agent = Resource::new_instance(urls::AGENT, store)?;
        agent.set_subject(self.subject.clone());
        if let Some(name) = &self.name {
            agent.set_propval_string(crate::urls::NAME.into(), name, store)?;
        }
        agent.set_propval_string(crate::urls::PUBLIC_KEY.into(), &self.public_key, store)?;
        // Agents must be read by anyone when validating their keys
        agent.push_propval(crate::urls::READ, urls::PUBLIC_AGENT.into(), true, store)?;
        agent.set_propval_string(
            crate::urls::CREATED_AT.into(),
            &self.created_at.to_string(),
            store,
        )?;
        Ok(agent)
    }

    /// Creates a new Agent, generates a new Keypair.
    pub fn new(name: Option<&str>, store: &impl Storelike) -> AtomicResult<Agent> {
        let keypair = generate_keypair()?;

        Ok(Agent::new_from_private_key(name, store, &keypair.private))
    }

    pub fn new_from_private_key(
        name: Option<&str>,
        store: &impl Storelike,
        private_key: &str,
    ) -> Agent {
        let keypair = generate_public_key(private_key);

        Agent {
            private_key: Some(keypair.private),
            public_key: keypair.public.clone(),
            subject: format!("{}/agents/{}", store.get_server_url(), keypair.public),
            name: name.map(|x| x.to_owned()),
            created_at: crate::utils::now(),
        }
    }

    pub fn new_from_public_key(store: &impl Storelike, public_key: &str) -> AtomicResult<Agent> {
        verify_public_key(public_key)?;

        Ok(Agent {
            private_key: None,
            public_key: public_key.into(),
            subject: format!("{}/agents/{}", store.get_server_url(), public_key),
            name: None,
            created_at: crate::utils::now(),
        })
    }
}

/// keypair, serialized using base64
pub struct Pair {
    pub private: String,
    pub public: String,
}

/// Returns a new random keypair.
fn generate_keypair() -> AtomicResult<Pair> {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    const SEED_LEN: usize = 32;
    let seed: [u8; SEED_LEN] = ring::rand::generate(&rng)
        .map_err(|_| "Error generating random seed: {}")?
        .expose();
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| format!("Error generating keypair {}", e))
        .unwrap();
    Ok(Pair {
        private: base64::encode(&seed),
        public: base64::encode(&key_pair.public_key()),
    })
}

/// Returns a Key Pair (including public key) from a private key, base64 encoded.
pub fn generate_public_key(private_key: &str) -> Pair {
    use ring::signature::KeyPair;
    let private_key_bytes = base64::decode(private_key).unwrap();
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(private_key_bytes.as_ref())
        .map_err(|_| "Error generating keypair")
        .unwrap();
    Pair {
        private: base64::encode(private_key_bytes),
        public: base64::encode(key_pair.public_key().as_ref()),
    }
}

/// Checks if the public key is a valid ED25519 base64 key.
/// Not perfect - only checks byte length and parses base64.
pub fn verify_public_key(public_key: &str) -> AtomicResult<()> {
    let pubkey_bin = base64::decode(public_key)
        .map_err(|e| format!("Invalid public key. Not valid Base64. {}", e))?;
    if pubkey_bin.len() != 32 {
        return Err(format!(
            "Invalid public key, should be 32 bytes long instead of {}. Key: {}",
            pubkey_bin.len(),
            public_key
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod test {
    #[cfg(test)]
    use super::*;

    #[test]
    fn keypair() {
        let pair = generate_keypair().unwrap();
        let regenerated_pair = generate_public_key(&pair.private);
        assert_eq!(pair.public, regenerated_pair.public);
    }

    #[test]
    fn generate_from_private_key() {
        let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
        let public_key = "7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=";
        let regenerated_pair = generate_public_key(private_key);
        assert_eq!(public_key, regenerated_pair.public);
    }

    #[test]
    fn verifies_public_keys() {
        let valid_public_key = "7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=";
        let invalid_length = "7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwm+h8U";
        let invalid_char = "7LsjMW5gOfDdJzK/atgjQ1t20^/rw8MjVg6xwqm+h8U=";
        verify_public_key(valid_public_key).unwrap();
        verify_public_key(invalid_length).unwrap_err();
        verify_public_key(invalid_char).unwrap_err();
    }
}
