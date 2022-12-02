//! JWT tokens
//! https://github.com/atomicdata-dev/atomic-data-rust/issues/544

use jwt_simple::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::AtomicResult;
use crate::Storelike;

/// Signs a claim as the Default Agent and creates a JWT token.
pub fn sign_claim<CustomClaims: Serialize + DeserializeOwned>(
    store: &impl Storelike,
    custom_claim: CustomClaims,
) -> AtomicResult<String> {
    let key = HS256Key::from_bytes(
        store
            .get_default_agent()?
            .private_key
            .ok_or("No private key in default agent, can't sign claims")?
            .as_bytes(),
    );
    let time = Duration::from_hours(1u64);
    let claim = Claims::with_custom_claims(custom_claim, time);
    let token = key
        .authenticate(claim)
        .map_err(|e| format!("fail to create token: {}", e))?;
    Ok(token)
}

/// Parses a JWT token, verifies its hash with the Current Agent and returns the Custom Claims.
pub fn verify_claim<CustomClaims: Serialize + DeserializeOwned>(
    store: &impl Storelike,
    token: &str,
) -> AtomicResult<JWTClaims<CustomClaims>> {
    let key = HS256Key::from_bytes(
        store
            .get_default_agent()?
            .private_key
            .ok_or("No private key in default agent, can't sign claims")?
            .as_bytes(),
    );
    let verify_opts = VerificationOptions::default();
    let claims = key
        .verify_token(token, Some(verify_opts))
        .map_err(|e| format!("fail to verify token: {}", e))?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    struct CustomClaims {
        pub name: String,
        pub email: String,
    }

    #[test]
    fn test_sign_claim_store() {
        let store = crate::test_utils::init_store();
        let customclaim = CustomClaims {
            name: "John Doe".to_string(),
            email: "awdaw@adiow.com".to_string(),
        };
        let token = sign_claim(&store, customclaim).unwrap();
        assert!(token.starts_with("ey"));
        let claim = verify_claim::<CustomClaims>(&store, &token).unwrap();
        assert!(claim.expires_at.is_some());
        assert_eq!(claim.custom.email, "awdaw@adiow.com".to_string());

        let malicous_agent = store.create_agent(None).unwrap();
        store.set_default_agent(malicous_agent);
        let wrong_claim = verify_claim::<CustomClaims>(&store, &token);
        assert!(wrong_claim.is_err());
    }
}
