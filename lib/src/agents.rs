//! Logic for Agents - which are like Users

#[derive(Clone)]
pub struct Agent {
  /// Private key for signing commits
  pub key: String,
  /// URL of the Agent
  pub subject: String,
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
