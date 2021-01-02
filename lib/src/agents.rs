//! Logic for Agents - which are like Users

use crate::{Resource, Storelike, errors::AtomicResult, urls};

#[derive(Clone)]
pub struct Agent {
  /// Private key for signing commits
  pub key: String,
  /// URL of the Agent
  pub subject: String,
  pub created_at: u64,
  pub name: String,
}

impl Agent {
  pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<Resource> {
    let keypair = crate::agents::generate_keypair();
    let mut agent = Resource::new_instance(urls::AGENT, store)?;
    agent.set_subject(self.subject.clone());
    agent.set_propval_string(crate::urls::NAME.into(), &self.name, store)?;
    agent.set_propval_string(crate::urls::PUBLIC_KEY.into(), &keypair.public, store)?;
    agent.set_propval_string(crate::urls::CREATED_AT.into(), &self.created_at.to_string(), store)?;
    Ok(agent)
  }
}

/// PKCS#8 keypair, serialized using base64
pub struct Pair {
  pub private: String,
  pub public: String,
}

/// Returns a new random PKCS#8 keypair.
pub fn generate_keypair() -> Pair {
  use ring::signature::KeyPair;
  let rng = ring::rand::SystemRandom::new();
  let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
      .map_err(|_| "Error generating seed").unwrap();
  let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
      .map_err(|_| "Error generating keypair").unwrap();
  Pair {
    private: base64::encode(pkcs8_bytes.as_ref()),
    public: base64::encode(key_pair.public_key().as_ref()),
  }
}
