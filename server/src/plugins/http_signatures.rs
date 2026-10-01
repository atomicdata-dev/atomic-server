//! HTTP message signatures, as plugin routes need them (#1718; design
//! `server-plugin-routes.md` in atomic-plugins, sections 2.5 and 2.7, D8).
//!
//! Two schemes, because the fediverse still speaks the first and new
//! protocols speak the second:
//!
//! - **draft-cavage-12**: a `Signature` (or `Authorization: Signature`)
//!   header with `keyId`, `algorithm`, `headers` and `signature`.
//! - **RFC 9421**: `Signature-Input` and `Signature`, structured fields
//!   (RFC 8941) with a signature base over derived components.
//!
//! This module is protocol only: parse a request's signature, build the bytes
//! that were signed, check them against a public key, and hold the result to
//! the host's policy (what must be covered, how old it may be, the body
//! digest). Finding the key is [`super::route_auth`]'s job; holding the
//! installation's private keys is [`super::route_keys`]'s. Nothing here logs.
//!
//! Algorithms: `rsa-sha256` / `rsa-v1_5-sha256`, `rsa-pss-sha512` (verify
//! only), `ed25519` and `ecdsa-p256-sha256` (verify only; the JWK `ES256`
//! Nextcloud 35 signs OCM requests with). `hs2019` picks by key type. Other
//! ECDSA curves and HMAC are refused.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
    signature::Verifier,
    traits::PublicKeyParts,
    RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha512};

/// How far `Date` or `created` may be from now, either way (design 2.7,
/// *proposed*: ±5 minutes).
pub const MAX_SKEW_SECS: i64 = 300;
/// RSA keys smaller than this are refused.
pub const MIN_RSA_BITS: usize = 2048;
/// And larger than this: verifying costs grow with the modulus.
pub const MAX_RSA_BITS: usize = 8192;

// -- keys ---------------------------------------------------------------------

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410): the key
/// follows as 32 bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A public key a signature can be checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    /// ECDSA on P-256, only ever from a JWK (OCM's `ES256`). Verified, never
    /// produced.
    EcdsaP256(p256::ecdsa::VerifyingKey),
}

fn pem_body(pem: &str) -> Result<(String, Vec<u8>), String> {
    let pem = pem.trim();
    let label = pem
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("-----BEGIN "))
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or("not a PEM document")?
        .to_string();
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = B64
        .decode(body)
        .map_err(|e| format!("the PEM body is not base64: {e}"))?;
    Ok((label, der))
}

impl PublicKey {
    /// A `PUBLIC KEY` (SPKI, RSA or Ed25519) or `RSA PUBLIC KEY` (PKCS #1)
    /// PEM document.
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let (label, der) = pem_body(pem)?;
        let key = match label.as_str() {
            "RSA PUBLIC KEY" => PublicKey::Rsa(
                RsaPublicKey::from_pkcs1_der(&der)
                    .map_err(|e| format!("not a PKCS #1 RSA public key: {e}"))?,
            ),
            "PUBLIC KEY" => {
                if let Some(raw) = der.strip_prefix(&ED25519_SPKI_PREFIX[..]) {
                    let raw: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| "an Ed25519 key is 32 bytes".to_string())?;
                    PublicKey::Ed25519(
                        ed25519_dalek::VerifyingKey::from_bytes(&raw)
                            .map_err(|e| format!("not an Ed25519 public key: {e}"))?,
                    )
                } else {
                    PublicKey::Rsa(
                        RsaPublicKey::from_public_key_der(&der)
                            .map_err(|e| format!("not an RSA or Ed25519 public key: {e}"))?,
                    )
                }
            }
            other => return Err(format!("a `{other}` PEM document is not a public key")),
        };
        Ok(key)
    }

    /// Refuses keys this host does not accept from a remote party.
    pub fn check_strength(&self) -> Result<(), String> {
        if let PublicKey::Rsa(key) = self {
            let bits = key.n().bits();
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
                return Err(format!(
                    "an RSA key of {bits} bits is refused; {MIN_RSA_BITS} to {MAX_RSA_BITS} are accepted"
                ));
            }
        }
        Ok(())
    }

    /// SPKI PEM, the shape ActivityPub's `publicKeyPem` uses.
    pub fn to_pem(&self) -> String {
        match self {
            PublicKey::Rsa(key) => key
                .to_public_key_pem(LineEnding::LF)
                .expect("an RSA public key encodes"),
            PublicKey::Ed25519(key) => {
                let mut der = ED25519_SPKI_PREFIX.to_vec();
                der.extend_from_slice(key.as_bytes());
                format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                    B64.encode(der)
                )
            }
            PublicKey::EcdsaP256(key) => p256::PublicKey::from(key)
                .to_public_key_pem(LineEnding::LF)
                .expect("a P-256 public key encodes"),
        }
    }

    /// A public JWK (RFC 7517) with its `alg`, the way Open Cloud Mesh
    /// publishes signing keys: `OKP`/`Ed25519` (`alg` `Ed25519` or `EdDSA`),
    /// `EC`/`P-256` (`alg` `ES256`, what Nextcloud 35 publishes), or `RSA`
    /// (`alg` `RS256` or `PS512`). Other key types and algorithms, and JWKs
    /// without an `alg`, are refused: the algorithm comes from the key,
    /// never from the message.
    pub fn from_jwk(jwk: &serde_json::Value) -> Result<(Self, Algorithm), String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let field = |name: &str| {
            jwk[name]
                .as_str()
                .ok_or_else(|| format!("the JWK has no `{name}`"))
        };
        let bytes = |name: &str| -> Result<Vec<u8>, String> {
            B64URL
                .decode(field(name)?.trim_end_matches('='))
                .map_err(|_| format!("the JWK's `{name}` is not base64url"))
        };
        let alg = field("alg")?;
        let key = match (field("kty")?, alg) {
            ("OKP", "Ed25519" | "EdDSA") => {
                if field("crv")? != "Ed25519" {
                    return Err("only the Ed25519 curve is accepted for OKP keys".into());
                }
                let raw: [u8; 32] = bytes("x")?
                    .try_into()
                    .map_err(|_| "an Ed25519 key is 32 bytes".to_string())?;
                (
                    PublicKey::Ed25519(
                        ed25519_dalek::VerifyingKey::from_bytes(&raw)
                            .map_err(|e| format!("not an Ed25519 public key: {e}"))?,
                    ),
                    Algorithm::Ed25519,
                )
            }
            ("EC", "ES256") => {
                if field("crv")? != "P-256" {
                    return Err("only the P-256 curve is accepted for ES256 keys".into());
                }
                let coordinate = |name: &str| -> Result<[u8; 32], String> {
                    bytes(name)?
                        .try_into()
                        .map_err(|_| format!("a P-256 `{name}` is 32 bytes"))
                };
                let point = p256::EncodedPoint::from_affine_coordinates(
                    &coordinate("x")?.into(),
                    &coordinate("y")?.into(),
                    false,
                );
                (
                    PublicKey::EcdsaP256(
                        p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                            .map_err(|_| "not a P-256 public key".to_string())?,
                    ),
                    Algorithm::EcdsaP256Sha256,
                )
            }
            ("RSA", "RS256" | "PS512") => {
                let n = rsa::BigUint::from_bytes_be(&bytes("n")?);
                let e = rsa::BigUint::from_bytes_be(&bytes("e")?);
                let key = RsaPublicKey::new(n, e).map_err(|e| format!("not an RSA key: {e}"))?;
                (
                    PublicKey::Rsa(key),
                    if alg == "RS256" {
                        Algorithm::RsaV15Sha256
                    } else {
                        Algorithm::RsaPssSha512
                    },
                )
            }
            (kty, alg) => {
                return Err(format!(
                "a `{kty}` JWK with `alg` `{alg}` is not accepted (Ed25519, ES256, RS256 or PS512)"
            ))
            }
        };
        key.0.check_strength()?;
        Ok(key)
    }

    /// The public JWK of this key, without `kid`: `OKP`/`Ed25519` with `alg`
    /// `Ed25519`, or `RSA` with `alg` `RS256` (what this host signs with).
    pub fn to_jwk(&self) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        match self {
            PublicKey::Ed25519(key) => serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "Ed25519",
                "use": "sig",
                "x": B64URL.encode(key.as_bytes()),
            }),
            PublicKey::Rsa(key) => serde_json::json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": B64URL.encode(key.n().to_bytes_be()),
                "e": B64URL.encode(key.e().to_bytes_be()),
            }),
            PublicKey::EcdsaP256(key) => {
                let point = key.to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "x": B64URL.encode(point.x().expect("an uncompressed point has x")),
                    "y": B64URL.encode(point.y().expect("an uncompressed point has y")),
                })
            }
        }
    }

    /// The algorithms this key can have made a signature with, in the order
    /// they are tried when a signature does not say.
    fn algorithms(&self) -> &'static [Algorithm] {
        match self {
            PublicKey::Rsa(_) => &[Algorithm::RsaV15Sha256, Algorithm::RsaPssSha512],
            PublicKey::Ed25519(_) => &[Algorithm::Ed25519],
            PublicKey::EcdsaP256(_) => &[Algorithm::EcdsaP256Sha256],
        }
    }

    pub(crate) fn verify_with(&self, algorithm: Algorithm, base: &[u8], signature: &[u8]) -> bool {
        match (self, algorithm) {
            (PublicKey::Rsa(key), Algorithm::RsaV15Sha256) => {
                rsa::pkcs1v15::Signature::try_from(signature).is_ok_and(|s| {
                    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone())
                        .verify(base, &s)
                        .is_ok()
                })
            }
            (PublicKey::Rsa(key), Algorithm::RsaPssSha512) => {
                rsa::pss::Signature::try_from(signature).is_ok_and(|s| {
                    rsa::pss::VerifyingKey::<Sha512>::new(key.clone())
                        .verify(base, &s)
                        .is_ok()
                })
            }
            (PublicKey::Ed25519(key), Algorithm::Ed25519) => {
                ed25519_dalek::Signature::from_slice(signature)
                    .is_ok_and(|s| key.verify_strict(base, &s).is_ok())
            }
            // RFC 9421 3.3.4: the signature is `r || s`, 32 bytes each; the
            // base is hashed with SHA-256.
            (PublicKey::EcdsaP256(key), Algorithm::EcdsaP256Sha256) => {
                p256::ecdsa::Signature::from_slice(signature)
                    .is_ok_and(|s| key.verify(base, &s).is_ok())
            }
            _ => false,
        }
    }
}

/// A signature algorithm this host verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256: cavage `rsa-sha256`, RFC 9421
    /// `rsa-v1_5-sha256`.
    RsaV15Sha256,
    /// RSASSA-PSS with SHA-512 (RFC 9421 `rsa-pss-sha512`). Verified, never
    /// produced.
    RsaPssSha512,
    Ed25519,
    /// ECDSA on P-256 with SHA-256 (RFC 9421 `ecdsa-p256-sha256`, JWK
    /// `ES256`). Verified, never produced.
    EcdsaP256Sha256,
}

impl Algorithm {
    pub fn rfc9421_name(self) -> &'static str {
        match self {
            Algorithm::RsaV15Sha256 => "rsa-v1_5-sha256",
            Algorithm::RsaPssSha512 => "rsa-pss-sha512",
            Algorithm::Ed25519 => "ed25519",
            Algorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }
}

// -- messages -----------------------------------------------------------------

/// A request as the verifier sees it. Header names are lowercase; a header
/// may appear more than once.
#[derive(Clone, Debug)]
pub struct Message<'a> {
    pub method: &'a str,
    /// `http` or `https`.
    pub scheme: &'a str,
    /// `host[:port]`, as the client addressed it.
    pub authority: &'a str,
    /// The path as sent, percent-encoding kept.
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a [(String, String)],
}

impl Message<'_> {
    /// All values of `name`, trimmed and joined with `, ` (RFC 9421 2.1,
    /// cavage 2.3).
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }

    fn path_and_query(&self) -> String {
        let path = if self.path.is_empty() { "/" } else { self.path };
        match self.query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        }
    }

    /// The authority, lowercased, without the scheme's default port.
    fn normalized_authority(&self) -> String {
        let authority = self.authority.to_ascii_lowercase();
        let default = match self.scheme {
            "https" => ":443",
            "http" => ":80",
            _ => "",
        };
        match authority.strip_suffix(default) {
            Some(bare) if !default.is_empty() => bare.to_string(),
            _ => authority,
        }
    }
}

/// Which specification a signature follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Cavage,
    Rfc9421,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Cavage => "draft-cavage-12",
            Scheme::Rfc9421 => "rfc9421",
        }
    }
}

/// A signature found on a request, with the bytes it claims to sign.
#[derive(Clone, Debug)]
pub struct Parsed {
    pub scheme: Scheme,
    /// The RFC 9421 label; empty for cavage.
    pub label: String,
    pub key_id: String,
    /// The algorithm the signature names, if it names one this host knows.
    /// `None`: decided by the key.
    pub algorithm: Option<Algorithm>,
    /// Covered components, lowercase: cavage header names (with the
    /// `(request-target)` pseudo-headers), or RFC 9421 component names.
    pub covered: Vec<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    /// The RFC 9421 `tag` parameter (`ocm` for Open Cloud Mesh). `None` for
    /// cavage.
    pub tag: Option<String>,
    /// The signing string (cavage) or signature base (RFC 9421).
    pub base: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Why a request's signature was not accepted. The message is safe to show
/// the sender: it never carries key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refused<T>(message: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(message.into()))
}

/// Every signature on `message`. RFC 9421 when `Signature-Input` is present,
/// cavage otherwise. `Ok(empty)` never happens: no signature is an error.
pub fn parse(message: &Message) -> Result<Vec<Parsed>, Refused> {
    if let Some(input) = message.header("signature-input") {
        let signature = message
            .header("signature")
            .ok_or_else(|| Refused("`Signature-Input` without `Signature`".into()))?;
        return parse_rfc9421(message, &input, &signature);
    }
    let cavage = message.header("signature").or_else(|| {
        message
            .header("authorization")
            .and_then(|a| a.strip_prefix("Signature ").map(str::to_string))
    });
    match cavage {
        Some(value) => Ok(vec![parse_cavage(message, &value)?]),
        None => refused("the request is not signed"),
    }
}

// -- draft-cavage-12 ------------------------------------------------------------

/// `name="value"` and `name=number` pairs, comma separated.
fn cavage_params(value: &str) -> Result<Vec<(String, String)>, Refused> {
    let mut out = Vec::new();
    let mut rest = value.trim();
    while !rest.is_empty() {
        let (name, after) = rest
            .split_once('=')
            .ok_or_else(|| Refused("a Signature parameter has no value".into()))?;
        let name = name.trim().to_ascii_lowercase();
        let after = after.trim_start();
        let (value, tail) = if let Some(quoted) = after.strip_prefix('"') {
            let end = quoted
                .find('"')
                .ok_or_else(|| Refused("an unterminated quoted Signature parameter".into()))?;
            (&quoted[..end], &quoted[end + 1..])
        } else {
            match after.find(',') {
                Some(end) => (after[..end].trim(), &after[end..]),
                None => (after.trim(), ""),
            }
        };
        out.push((name, value.to_string()));
        rest = tail.trim_start();
        if let Some(r) = rest.strip_prefix(',') {
            rest = r.trim_start();
        } else if !rest.is_empty() {
            return refused("Signature parameters must be separated by commas");
        }
    }
    Ok(out)
}

fn parse_cavage(message: &Message, value: &str) -> Result<Parsed, Refused> {
    let params = cavage_params(value)?;
    let get = |name: &str| {
        params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let key_id = get("keyid")
        .filter(|k| !k.is_empty())
        .ok_or_else(|| Refused("the signature has no keyId".into()))?
        .to_string();
    let algorithm = match get("algorithm").map(str::to_ascii_lowercase).as_deref() {
        None | Some("hs2019") => None,
        Some("rsa-sha256") => Some(Algorithm::RsaV15Sha256),
        Some("ed25519") => Some(Algorithm::Ed25519),
        Some(other) => return refused(format!("the algorithm `{other}` is not accepted")),
    };
    let int = |name: &str| -> Result<Option<i64>, Refused> {
        get(name)
            .map(|v| {
                // cavage allows a decimal point; the fraction is dropped.
                v.split('.')
                    .next()
                    .unwrap_or("")
                    .parse::<i64>()
                    .map_err(|_| Refused(format!("`{name}` is not a timestamp")))
            })
            .transpose()
    };
    let created = int("created")?;
    let expires = int("expires")?;
    let signature = B64
        .decode(
            get("signature")
                .ok_or_else(|| Refused("the signature has no signature value".into()))?,
        )
        .map_err(|_| Refused("the signature value is not base64".into()))?;
    let covered: Vec<String> = match get("headers") {
        Some(h) => h
            .split_ascii_whitespace()
            .map(str::to_ascii_lowercase)
            .collect(),
        // cavage-12 defaults to `(created)`; earlier drafts, and the published
        // test vectors, to `date`.
        None if created.is_some() => vec!["(created)".into()],
        None => vec!["date".into()],
    };
    if covered.is_empty() {
        return refused("the signature covers nothing");
    }
    let mut lines = Vec::with_capacity(covered.len());
    for name in &covered {
        let value = match name.as_str() {
            "(request-target)" => format!(
                "{} {}",
                message.method.to_ascii_lowercase(),
                message.path_and_query()
            ),
            "(created)" => created
                .ok_or_else(|| Refused("`(created)` is covered but not given".into()))?
                .to_string(),
            "(expires)" => expires
                .ok_or_else(|| Refused("`(expires)` is covered but not given".into()))?
                .to_string(),
            "host" => message
                .header("host")
                .unwrap_or_else(|| message.authority.to_string()),
            header => message
                .header(header)
                .ok_or_else(|| Refused(format!("`{header}` is signed but not sent")))?,
        };
        lines.push(format!("{name}: {value}"));
    }
    Ok(Parsed {
        scheme: Scheme::Cavage,
        label: String::new(),
        key_id,
        algorithm,
        covered,
        created,
        expires,
        tag: None,
        base: lines.join("\n").into_bytes(),
        signature,
    })
}

// -- structured fields (RFC 8941), the part RFC 9421 needs ----------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Bare {
    Integer(i64),
    String(String),
    Token(String),
    Bytes(Vec<u8>),
    Boolean(bool),
}

type Params = Vec<(String, Bare)>;

#[derive(Clone, Debug, PartialEq)]
pub enum Member {
    Item(Bare, Params),
    InnerList(Vec<(Bare, Params)>, Params),
}

struct Sf<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Sf<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            i: 0,
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn skip(&mut self, spaces_only: bool) {
        while let Some(c) = self.peek() {
            if c == b' ' || (!spaces_only && c == b'\t') {
                self.i += 1;
            } else {
                break;
            }
        }
    }
    fn fail<T>(&self, what: &str) -> Result<T, Refused> {
        refused(format!("malformed structured field: {what}"))
    }

    fn key(&mut self) -> Result<String, Refused> {
        let start = self.i;
        match self.peek() {
            Some(c) if c.is_ascii_lowercase() || c == b'*' => self.i += 1,
            _ => return self.fail("a key"),
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c) {
                self.i += 1;
            } else {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn bare(&mut self) -> Result<Bare, Refused> {
        match self.peek() {
            Some(b'"') => {
                self.i += 1;
                let mut out = String::new();
                loop {
                    match self.peek() {
                        None => return self.fail("an unterminated string"),
                        Some(b'"') => {
                            self.i += 1;
                            return Ok(Bare::String(out));
                        }
                        Some(b'\\') => {
                            self.i += 1;
                            match self.peek() {
                                Some(c @ (b'"' | b'\\')) => {
                                    out.push(c as char);
                                    self.i += 1;
                                }
                                _ => return self.fail("an escape"),
                            }
                        }
                        Some(c) if (0x20..0x7f).contains(&c) => {
                            out.push(c as char);
                            self.i += 1;
                        }
                        Some(_) => return self.fail("a string character"),
                    }
                }
            }
            Some(b':') => {
                self.i += 1;
                let start = self.i;
                while self.peek().is_some_and(|c| c != b':') {
                    self.i += 1;
                }
                if self.peek() != Some(b':') {
                    return self.fail("an unterminated byte sequence");
                }
                let bytes = B64
                    .decode(&self.s[start..self.i])
                    .map_err(|_| Refused("malformed structured field: base64".into()))?;
                self.i += 1;
                Ok(Bare::Bytes(bytes))
            }
            Some(b'?') => {
                self.i += 1;
                let value = match self.peek() {
                    Some(b'1') => true,
                    Some(b'0') => false,
                    _ => return self.fail("a boolean"),
                };
                self.i += 1;
                Ok(Bare::Boolean(value))
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                self.i += 1;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.i += 1;
                }
                if self.peek() == Some(b'.') {
                    return self.fail("decimals are not used here");
                }
                std::str::from_utf8(&self.s[start..self.i])
                    .ok()
                    .and_then(|n| n.parse::<i64>().ok())
                    .filter(|_| self.i - start <= 16)
                    .map(Bare::Integer)
                    .ok_or_else(|| Refused("malformed structured field: an integer".into()))
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'*' => {
                let start = self.i;
                while self
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&c))
                {
                    self.i += 1;
                }
                Ok(Bare::Token(
                    String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
                ))
            }
            _ => self.fail("an item"),
        }
    }

    fn params(&mut self) -> Result<Params, Refused> {
        let mut out: Params = Vec::new();
        while self.peek() == Some(b';') {
            self.i += 1;
            self.skip(true);
            let key = self.key()?;
            let value = if self.peek() == Some(b'=') {
                self.i += 1;
                self.bare()?
            } else {
                Bare::Boolean(true)
            };
            out.retain(|(k, _)| k != &key);
            out.push((key, value));
        }
        Ok(out)
    }

    fn member(&mut self) -> Result<Member, Refused> {
        if self.peek() == Some(b'(') {
            self.i += 1;
            let mut items = Vec::new();
            loop {
                self.skip(true);
                if self.peek() == Some(b')') {
                    self.i += 1;
                    break;
                }
                let item = self.bare()?;
                let params = self.params()?;
                items.push((item, params));
                match self.peek() {
                    Some(b' ') | Some(b')') => {}
                    _ => return self.fail("an inner list"),
                }
            }
            let params = self.params()?;
            Ok(Member::InnerList(items, params))
        } else {
            let item = self.bare()?;
            let params = self.params()?;
            Ok(Member::Item(item, params))
        }
    }

    fn dictionary(mut self) -> Result<Vec<(String, Member)>, Refused> {
        let mut out: Vec<(String, Member)> = Vec::new();
        self.skip(true);
        while self.peek().is_some() {
            let key = self.key()?;
            let member = if self.peek() == Some(b'=') {
                self.i += 1;
                self.member()?
            } else {
                let params = self.params()?;
                Member::Item(Bare::Boolean(true), params)
            };
            out.retain(|(k, _)| k != &key);
            out.push((key, member));
            self.skip(false);
            if self.peek().is_none() {
                break;
            }
            if self.peek() != Some(b',') {
                return self.fail("dictionary members must be separated by commas");
            }
            self.i += 1;
            self.skip(false);
            if self.peek().is_none() {
                return self.fail("a trailing comma");
            }
        }
        Ok(out)
    }
}

/// Parses an RFC 8941 dictionary.
pub fn sf_dictionary(value: &str) -> Result<Vec<(String, Member)>, Refused> {
    Sf::new(value).dictionary()
}

fn serialize_bare(bare: &Bare) -> String {
    match bare {
        Bare::Integer(n) => n.to_string(),
        Bare::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Bare::Token(t) => t.clone(),
        Bare::Bytes(b) => format!(":{}:", B64.encode(b)),
        Bare::Boolean(true) => "?1".into(),
        Bare::Boolean(false) => "?0".into(),
    }
}

fn serialize_params(params: &Params) -> String {
    params
        .iter()
        .map(|(k, v)| match v {
            Bare::Boolean(true) => format!(";{k}"),
            v => format!(";{k}={}", serialize_bare(v)),
        })
        .collect()
}

fn serialize_inner_list(items: &[(Bare, Params)], params: &Params) -> String {
    let items: Vec<String> = items
        .iter()
        .map(|(item, p)| format!("{}{}", serialize_bare(item), serialize_params(p)))
        .collect();
    format!("({}){}", items.join(" "), serialize_params(params))
}

// -- RFC 9421 -----------------------------------------------------------------

fn component_value(message: &Message, name: &str) -> Result<String, Refused> {
    Ok(match name {
        "@method" => message.method.to_string(),
        "@target-uri" => format!(
            "{}://{}{}",
            message.scheme,
            message.normalized_authority(),
            message.path_and_query()
        ),
        "@authority" => message.normalized_authority(),
        "@scheme" => message.scheme.to_ascii_lowercase(),
        "@request-target" => message.path_and_query(),
        "@path" => {
            if message.path.is_empty() {
                "/".into()
            } else {
                message.path.to_string()
            }
        }
        "@query" => format!("?{}", message.query.unwrap_or("")),
        derived if derived.starts_with('@') => {
            return refused(format!("the component `{derived}` is not supported"))
        }
        header => message
            .header(header)
            .ok_or_else(|| Refused(format!("`{header}` is signed but not sent")))?,
    })
}

fn parse_rfc9421(message: &Message, input: &str, signature: &str) -> Result<Vec<Parsed>, Refused> {
    let signatures = sf_dictionary(signature)?;
    let mut out = Vec::new();
    for (label, member) in sf_dictionary(input)? {
        let Member::InnerList(items, params) = member else {
            return refused(format!("`Signature-Input` `{label}` is not an inner list"));
        };
        let bytes = match signatures.iter().find(|(l, _)| *l == label) {
            Some((_, Member::Item(Bare::Bytes(b), _))) => b.clone(),
            Some(_) => return refused(format!("`Signature` `{label}` is not a byte sequence")),
            None => return refused(format!("no `Signature` for `{label}`")),
        };
        for (item, item_params) in &items {
            if !item_params.is_empty() {
                return refused(format!(
                    "component parameters (on {}) are not supported",
                    serialize_bare(item)
                ));
            }
        }
        let mut covered = Vec::with_capacity(items.len());
        let mut lines = Vec::with_capacity(items.len() + 1);
        for (item, _) in &items {
            let Bare::String(name) = item else {
                return refused("a covered component is not a string");
            };
            let name = name.to_string();
            if name != name.to_ascii_lowercase() || covered.contains(&name) {
                return refused(format!(
                    "the component `{name}` is not lowercase or repeats"
                ));
            }
            lines.push(format!("\"{name}\": {}", component_value(message, &name)?));
            covered.push(name);
        }
        lines.push(format!(
            "\"@signature-params\": {}",
            serialize_inner_list(&items, &params)
        ));
        let param = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        let int = |name: &str| -> Result<Option<i64>, Refused> {
            match param(name) {
                None => Ok(None),
                Some(Bare::Integer(n)) => Ok(Some(*n)),
                Some(_) => refused(format!("`{name}` is not an integer")),
            }
        };
        let key_id = match param("keyid") {
            Some(Bare::String(k)) if !k.is_empty() => k.clone(),
            _ => return refused(format!("`{label}` has no keyid")),
        };
        let algorithm = match param("alg") {
            None => None,
            Some(Bare::String(a)) => Some(match a.as_str() {
                "rsa-v1_5-sha256" => Algorithm::RsaV15Sha256,
                "rsa-pss-sha512" => Algorithm::RsaPssSha512,
                "ed25519" => Algorithm::Ed25519,
                "ecdsa-p256-sha256" => Algorithm::EcdsaP256Sha256,
                other => return refused(format!("the algorithm `{other}` is not accepted")),
            }),
            Some(_) => return refused("`alg` is not a string"),
        };
        out.push(Parsed {
            scheme: Scheme::Rfc9421,
            label,
            key_id,
            algorithm,
            covered,
            created: int("created")?,
            expires: int("expires")?,
            tag: match param("tag") {
                None => None,
                Some(Bare::String(t)) => Some(t.clone()),
                Some(_) => return refused("`tag` is not a string"),
            },
            base: lines.join("\n").into_bytes(),
            signature: bytes,
        });
    }
    if out.is_empty() {
        return refused("`Signature-Input` names no signature");
    }
    Ok(out)
}

// -- verifying ----------------------------------------------------------------

/// Checks the signature bytes against `key`. Returns the algorithm that
/// verified. A stated algorithm must fit the key.
pub fn verify(parsed: &Parsed, key: &PublicKey) -> Result<Algorithm, Refused> {
    let candidates: Vec<Algorithm> = match parsed.algorithm {
        Some(stated) if key.algorithms().contains(&stated) => vec![stated],
        Some(stated) => {
            return refused(format!(
                "the signature says `{}`, which does not fit the key",
                stated.rfc9421_name()
            ))
        }
        None => key.algorithms().to_vec(),
    };
    candidates
        .into_iter()
        .find(|a| key.verify_with(*a, &parsed.base, &parsed.signature))
        .ok_or_else(|| Refused("the signature does not verify".into()))
}

/// The host's rules for an inbound signature, beyond the math (design 2.7):
///
/// - it is bound to this request: method, target and host are covered;
/// - it is fresh: `Date` or `created` within [`MAX_SKEW_SECS`] of `now`,
///   and not past `expires`;
/// - a body is covered by a `Digest` or `Content-Digest` header, and every
///   digest the request carries matches the body.
pub fn check_policy(
    parsed: &Parsed,
    message: &Message,
    body: &[u8],
    now_secs: i64,
) -> Result<(), Refused> {
    let covers = |name: &str| parsed.covered.iter().any(|c| c == name);
    let fresh = |at: i64, what: &str| {
        if (now_secs - at).abs() > MAX_SKEW_SECS {
            refused(format!(
                "{what} is more than {MAX_SKEW_SECS} seconds from this server's clock"
            ))
        } else {
            Ok(())
        }
    };
    if let Some(expires) = parsed.expires {
        if expires < now_secs {
            return refused("the signature has expired");
        }
    }
    match parsed.scheme {
        Scheme::Cavage => {
            if !(covers("(request-target)") && covers("host")) {
                return refused("the signature must cover `(request-target)` and `host`");
            }
            let mut dated = false;
            if covers("(created)") {
                fresh(parsed.created.unwrap_or_default(), "`created`")?;
                dated = true;
            }
            if covers("date") {
                fresh(date_header(message)?, "`Date`")?;
                dated = true;
            }
            if !dated {
                return refused("the signature must cover `date` or `(created)`");
            }
        }
        Scheme::Rfc9421 => {
            let created = parsed
                .created
                .ok_or_else(|| Refused("the signature has no `created`".into()))?;
            fresh(created, "`created`")?;
            if covers("date") {
                fresh(date_header(message)?, "`Date`")?;
            }
            let target = covers("@target-uri")
                || ((covers("@authority") || covers("host"))
                    && (covers("@request-target")
                        || (covers("@path") && (message.query.is_none() || covers("@query")))));
            if !(covers("@method") && target) {
                return refused(
                    "the signature must cover `@method` and the target (`@target-uri`, or `@authority` with `@path`)",
                );
            }
        }
    }
    let digest = message.header("digest");
    let content_digest = message.header("content-digest");
    if let Some(value) = &digest {
        check_digest(value, body)?;
    }
    if let Some(value) = &content_digest {
        check_content_digest(value, body)?;
    }
    if !body.is_empty()
        && !(covers("digest") && digest.is_some())
        && !(covers("content-digest") && content_digest.is_some())
    {
        return refused("a request with a body must sign a `Digest` or `Content-Digest` of it");
    }
    Ok(())
}

/// The tag Open Cloud Mesh signatures carry (OCM 1.5, "HTTP Message
/// Signatures").
pub const OCM_TAG: &str = "ocm";

/// The one RFC 9421 signature on a request that carries `tag`, or a refusal
/// when there is none or more than one. Signatures with other tags (or none)
/// are disregarded, as OCM requires.
pub fn tagged<'a>(signatures: &'a [Parsed], tag: &str) -> Result<&'a Parsed, Refused> {
    let mut found = signatures
        .iter()
        .filter(|p| p.scheme == Scheme::Rfc9421 && p.tag.as_deref() == Some(tag));
    let first = found
        .next()
        .ok_or_else(|| Refused(format!("the request has no signature with tag `{tag}`")))?;
    if found.next().is_some() {
        return refused(format!(
            "the request has more than one signature with tag `{tag}`"
        ));
    }
    Ok(first)
}

/// OCM's coverage rules on top of [`check_policy`]: `@method`,
/// `@target-uri`, and with a body `content-digest` and `content-length`.
pub fn check_ocm_policy(parsed: &Parsed, body: &[u8]) -> Result<(), Refused> {
    let covers = |name: &str| parsed.covered.iter().any(|c| c == name);
    let mut needed = vec!["@method", "@target-uri"];
    if !body.is_empty() {
        needed.extend(["content-digest", "content-length"]);
    }
    let missing: Vec<&str> = needed.into_iter().filter(|c| !covers(c)).collect();
    if !missing.is_empty() {
        return refused(format!(
            "an OCM signature must cover {}",
            missing
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(())
}

fn date_header(message: &Message) -> Result<i64, Refused> {
    let value = message
        .header("date")
        .ok_or_else(|| Refused("`Date` is signed but not sent".into()))?;
    httpdate::parse_http_date(&value)
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .ok_or_else(|| Refused("`Date` is not an HTTP date".into()))
}

fn digest_of(algorithm: &str, body: &[u8]) -> Option<Vec<u8>> {
    match algorithm.to_ascii_lowercase().as_str() {
        "sha-256" => Some(Sha256::digest(body).to_vec()),
        "sha-512" => Some(Sha512::digest(body).to_vec()),
        _ => None,
    }
}

/// `Digest` (RFC 3230): `SHA-256=<base64>`, comma separated. At least one
/// algorithm this host knows, and every known one matches.
pub fn check_digest(value: &str, body: &[u8]) -> Result<(), Refused> {
    let mut known = 0;
    for part in value.split(',') {
        let Some((algorithm, encoded)) = part.trim().split_once('=') else {
            return refused("`Digest` is malformed");
        };
        let Some(expected) = digest_of(algorithm, body) else {
            continue;
        };
        known += 1;
        if B64.decode(encoded.trim()).ok().as_deref() != Some(&expected[..]) {
            return refused("the body does not match its `Digest`");
        }
    }
    if known == 0 {
        return refused("`Digest` uses no algorithm this server checks (SHA-256, SHA-512)");
    }
    Ok(())
}

/// `Content-Digest` (RFC 9530): `sha-256=:<base64>:`.
pub fn check_content_digest(value: &str, body: &[u8]) -> Result<(), Refused> {
    let mut known = 0;
    for (algorithm, member) in sf_dictionary(value)? {
        let Some(expected) = digest_of(&algorithm, body) else {
            continue;
        };
        known += 1;
        match member {
            Member::Item(Bare::Bytes(got), _) if got == expected => {}
            _ => return refused("the body does not match its `Content-Digest`"),
        }
    }
    if known == 0 {
        return refused("`Content-Digest` uses no algorithm this server checks (sha-256, sha-512)");
    }
    Ok(())
}

// -- signing ------------------------------------------------------------------

/// Something that signs with a private key the caller never sees.
pub trait Signer {
    fn algorithm(&self) -> Algorithm;
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

/// An outbound request to sign.
pub struct Outbound<'a> {
    pub method: &'a str,
    pub url: &'a url::Url,
    pub body: Option<&'a [u8]>,
}

fn authority(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Signs `request` the draft-cavage-12 way the fediverse expects: `Host`,
/// `Date`, a SHA-256 `Digest` when there is a body, and `Signature` over
/// `(request-target) host date [digest]`. Returns the headers to send.
pub fn sign_cavage(
    signer: &dyn Signer,
    key_id: &str,
    request: &Outbound,
    now: std::time::SystemTime,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("host".to_string(), authority(request.url)),
        ("date".to_string(), httpdate::fmt_http_date(now)),
    ];
    if let Some(body) = request.body {
        headers.push((
            "digest".into(),
            format!("SHA-256={}", B64.encode(Sha256::digest(body))),
        ));
    }
    let names: Vec<String> = std::iter::once("(request-target)".to_string())
        .chain(headers.iter().map(|(n, _)| n.clone()))
        .collect();
    let path = match request.url.query() {
        Some(q) => format!("{}?{q}", request.url.path()),
        None => request.url.path().to_string(),
    };
    let mut lines = vec![format!(
        "(request-target): {} {path}",
        request.method.to_ascii_lowercase()
    )];
    lines.extend(headers.iter().map(|(n, v)| format!("{n}: {v}")));
    let signature = B64.encode(signer.sign(lines.join("\n").as_bytes()));
    let algorithm = match signer.algorithm() {
        Algorithm::RsaV15Sha256 => "rsa-sha256",
        _ => "hs2019",
    };
    headers.push((
        "signature".into(),
        format!(
            "keyId=\"{key_id}\",algorithm=\"{algorithm}\",headers=\"{}\",signature=\"{signature}\"",
            names.join(" ")
        ),
    ));
    headers
}

/// Signs `request` per RFC 9421, label `sig1`, covering `@method`,
/// `@target-uri` and, with a body, a SHA-256 `Content-Digest`. Returns the
/// headers to send.
pub fn sign_rfc9421(
    signer: &dyn Signer,
    key_id: &str,
    request: &Outbound,
    now: std::time::SystemTime,
) -> Vec<(String, String)> {
    sign_rfc9421_tagged(signer, key_id, request, now, None)
}

/// [`sign_rfc9421`] with a `tag` parameter. A tagged signature with a body
/// also covers `content-length`, and returns that header: Open Cloud Mesh
/// (`tag="ocm"`) requires it.
pub fn sign_rfc9421_tagged(
    signer: &dyn Signer,
    key_id: &str,
    request: &Outbound,
    now: std::time::SystemTime,
    tag: Option<&str>,
) -> Vec<(String, String)> {
    let created = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let mut headers = Vec::new();
    let mut items = vec![
        (Bare::String("@method".into()), Params::new()),
        (Bare::String("@target-uri".into()), Params::new()),
    ];
    let target = request.url.as_str().to_string();
    let mut lines = vec![
        format!("\"@method\": {}", request.method.to_ascii_uppercase()),
        format!("\"@target-uri\": {target}"),
    ];
    if let Some(body) = request.body {
        let digest = format!("sha-256=:{}:", B64.encode(Sha256::digest(body)));
        lines.push(format!("\"content-digest\": {digest}"));
        items.push((Bare::String("content-digest".into()), Params::new()));
        headers.push(("content-digest".to_string(), digest));
        if tag.is_some() {
            let length = body.len().to_string();
            lines.push(format!("\"content-length\": {length}"));
            items.push((Bare::String("content-length".into()), Params::new()));
            headers.push(("content-length".to_string(), length));
        }
    }
    let mut params: Params = vec![
        ("created".into(), Bare::Integer(created)),
        ("keyid".into(), Bare::String(key_id.into())),
        (
            "alg".into(),
            Bare::String(signer.algorithm().rfc9421_name().into()),
        ),
    ];
    if let Some(tag) = tag {
        params.push(("tag".into(), Bare::String(tag.into())));
    }
    let signature_params = serialize_inner_list(&items, &params);
    lines.push(format!("\"@signature-params\": {signature_params}"));
    let signature = signer.sign(lines.join("\n").as_bytes());
    headers.push(("signature-input".into(), format!("sig1={signature_params}")));
    headers.push((
        "signature".into(),
        format!("sig1=:{}:", B64.encode(signature)),
    ));
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    /// The published test vectors: draft-cavage-12 appendix C and RFC 9421
    /// appendix B and section 4.3. `testdata/http-signatures/vectors.json`.
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../testdata/http-signatures/vectors.json"
        ))
        .unwrap()
    }

    fn headers(v: &serde_json::Value) -> Vec<(String, String)> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h[0].as_str().unwrap().to_ascii_lowercase(),
                    h[1].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    struct Request {
        method: String,
        scheme: String,
        authority: String,
        path: String,
        query: Option<String>,
        headers: Vec<(String, String)>,
    }

    impl Request {
        fn from(v: &serde_json::Value) -> Self {
            Self {
                method: v["method"].as_str().unwrap().into(),
                scheme: v["scheme"].as_str().unwrap_or("https").into(),
                authority: v["authority"].as_str().unwrap().into(),
                path: v["path"].as_str().unwrap().into(),
                query: v["query"].as_str().map(str::to_string),
                headers: headers(&v["headers"]),
            }
        }
        fn message(&self) -> Message<'_> {
            Message {
                method: &self.method,
                scheme: &self.scheme,
                authority: &self.authority,
                path: &self.path,
                query: self.query.as_deref(),
                headers: &self.headers,
            }
        }
    }

    #[test]
    fn cavage_12_vectors_verify() {
        let v = vectors();
        let cavage = &v["cavage12"];
        let key = PublicKey::from_pem(cavage["publicKeyPem"].as_str().unwrap()).unwrap();
        let request = Request::from(&cavage["request"]);
        for case in cavage["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let mut request_headers = request.headers.clone();
            request_headers.push((
                "signature".into(),
                case["signature"].as_str().unwrap().into(),
            ));
            let r = Request {
                headers: request_headers,
                ..Request::from(&cavage["request"])
            };
            let parsed = parse(&r.message()).unwrap().remove(0);
            assert_eq!(
                String::from_utf8(parsed.base.clone()).unwrap(),
                case["signingString"].as_str().unwrap(),
                "{name}: signing string"
            );
            let verified = verify(&parsed, &key);
            if case["valid"].as_bool().unwrap() {
                assert_eq!(verified, Ok(Algorithm::RsaV15Sha256), "{name}");
            } else {
                // C.3's value predates `(created)`/`(expires)`: the draft
                // warns its vectors are old and possibly wrong. The next case
                // is the same value over the signing string it prints.
                assert!(verified.is_err(), "{name} is known not to verify");
            }
        }
        // The same signatures under `Authorization: Signature`.
        let case = &cavage["cases"][1];
        let mut h = request.headers.clone();
        h.push((
            "authorization".into(),
            format!("Signature {}", case["signature"].as_str().unwrap()),
        ));
        let r = Request {
            headers: h,
            ..Request::from(&cavage["request"])
        };
        let parsed = parse(&r.message()).unwrap().remove(0);
        assert_eq!(verify(&parsed, &key), Ok(Algorithm::RsaV15Sha256));
        // The vector key signs deterministically, so signing reproduces C.2.
        let private =
            rsa::RsaPrivateKey::from_pkcs1_pem(cavage["privateKeyPem"].as_str().unwrap()).unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private);
        let again = B64.encode(
            signer
                .sign_with_rng(&mut rand::rngs::OsRng, &parsed.base)
                .to_bytes(),
        );
        assert!(case["signature"].as_str().unwrap().contains(&again));
    }

    #[test]
    fn rfc9421_vectors_verify() {
        let v = vectors();
        let rfc = &v["rfc9421"];
        let request = Request::from(&rfc["request"]);
        for case in rfc["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let r = Request {
                authority: case["authority"]
                    .as_str()
                    .unwrap_or(&request.authority)
                    .to_string(),
                headers: request
                    .headers
                    .iter()
                    .cloned()
                    .chain(headers(&case["extraHeaders"]))
                    .chain([
                        (
                            "signature-input".to_string(),
                            case["signatureInput"].as_str().unwrap().to_string(),
                        ),
                        (
                            "signature".to_string(),
                            case["signature"].as_str().unwrap().to_string(),
                        ),
                    ])
                    .collect(),
                ..Request::from(&rfc["request"])
            };
            let parsed = parse(&r.message()).unwrap();
            let parsed = parsed
                .iter()
                .find(|p| p.label == case["label"].as_str().unwrap())
                .unwrap_or_else(|| panic!("{name}: label"));
            assert_eq!(
                String::from_utf8(parsed.base.clone()).unwrap(),
                case["signatureBase"].as_str().unwrap(),
                "{name}: signature base"
            );
            let key =
                PublicKey::from_pem(rfc["keys"][case["key"].as_str().unwrap()].as_str().unwrap())
                    .unwrap();
            let expected = match case["alg"].as_str().unwrap() {
                "rsa-v1_5-sha256" => Algorithm::RsaV15Sha256,
                "rsa-pss-sha512" => Algorithm::RsaPssSha512,
                _ => Algorithm::Ed25519,
            };
            assert_eq!(verify(parsed, &key), Ok(expected), "{name}");
            let mut tampered = parsed.clone();
            tampered.base.push(b' ');
            assert!(verify(&tampered, &key).is_err(), "{name}: tampered");
        }
        // Component parameters (`@query-param;name=...`) are refused, not
        // verified wrongly.
        for case in rfc["unsupported"].as_array().unwrap() {
            let r = Request {
                headers: vec![
                    (
                        "signature-input".into(),
                        case["signatureInput"].as_str().unwrap().into(),
                    ),
                    (
                        "signature".into(),
                        case["signature"].as_str().unwrap().into(),
                    ),
                ],
                ..Request::from(&rfc["request"])
            };
            let err = parse(&r.message()).unwrap_err();
            assert!(err.0.contains("not supported"), "{err}");
        }
    }

    #[test]
    fn rfc9421_ed25519_signing_reproduces_b26() {
        // Ed25519 is deterministic: the host's signer, given the vector's
        // private key, produces the published signature for the same base.
        let v = vectors();
        let rfc = &v["rfc9421"];
        let case = rfc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["label"] == "sig-b26")
            .unwrap();
        let seed: [u8; 32] = B64
            .decode(rfc["ed25519Seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        use ed25519_dalek::Signer as _;
        let signature = key.sign(case["signatureBase"].as_str().unwrap().as_bytes());
        assert!(case["signature"]
            .as_str()
            .unwrap()
            .contains(&B64.encode(signature.to_bytes())));
    }

    #[test]
    fn structured_fields_round_trip_signature_params() {
        let dict = sf_dictionary(
            r#"sig1=("@method" "@target-uri" "content-digest");created=1618884473;keyid="k\"1";alg="ed25519", b=?0, c;x=:AQI=:"#,
        )
        .unwrap();
        let Member::InnerList(items, params) = &dict[0].1 else {
            panic!()
        };
        assert_eq!(
            serialize_inner_list(items, params),
            r#"("@method" "@target-uri" "content-digest");created=1618884473;keyid="k\"1";alg="ed25519""#
        );
        assert_eq!(
            dict[1],
            ("b".into(), Member::Item(Bare::Boolean(false), vec![]))
        );
        assert_eq!(
            dict[2],
            (
                "c".into(),
                Member::Item(
                    Bare::Boolean(true),
                    vec![("x".into(), Bare::Bytes(vec![1, 2]))]
                )
            )
        );
        for bad in ["sig1=(", "sig1=\"x", "Sig=1", "a=1,", "a=1.5", "a=:*:"] {
            assert!(sf_dictionary(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn digests_are_checked() {
        let body = br#"{"hello": "world"}"#;
        check_digest("SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=", body).unwrap();
        assert!(check_digest(
            "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
            b"{}"
        )
        .is_err());
        assert!(check_digest("MD5=abc", body).is_err());
        check_content_digest(
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            body,
        )
        .unwrap();
        assert!(check_content_digest("sha-256=:AAAA:", body).is_err());
        assert!(check_content_digest("md5=:AAAA:", body).is_err());
    }

    struct Ed(ed25519_dalek::SigningKey);
    impl Signer for Ed {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Ed25519
        }
        fn sign(&self, data: &[u8]) -> Vec<u8> {
            use ed25519_dalek::Signer as _;
            self.0.sign(data).to_bytes().to_vec()
        }
    }

    /// A request signed now, as the host's policy wants it, in both schemes.
    fn signed(rfc: bool, body: &[u8]) -> (Request, PublicKey, i64) {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public = PublicKey::Ed25519(key.verifying_key());
        let url = url::Url::parse("https://example.com/inbox?x=1").unwrap();
        let now = std::time::SystemTime::now();
        let outbound = Outbound {
            method: "POST",
            url: &url,
            body: Some(body),
        };
        let mut headers = if rfc {
            sign_rfc9421(&Ed(key), "https://a.example/k", &outbound, now)
        } else {
            sign_cavage(&Ed(key), "https://a.example/k", &outbound, now)
        };
        if !headers.iter().any(|(n, _)| n == "host") {
            headers.push(("host".into(), "example.com".into()));
        }
        let secs = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        (
            Request {
                method: "POST".into(),
                scheme: "https".into(),
                authority: "example.com".into(),
                path: "/inbox".into(),
                query: Some("x=1".into()),
                headers,
            },
            public,
            secs,
        )
    }

    fn check(r: &Request, key: &PublicKey, body: &[u8], now: i64) -> Result<(), Refused> {
        let parsed = parse(&r.message())?.remove(0);
        verify(&parsed, key)?;
        check_policy(&parsed, &r.message(), body, now)
    }

    #[test]
    fn a_fresh_signature_over_the_body_passes_in_both_schemes() {
        for rfc in [false, true] {
            let body = b"{\"a\":1}";
            let (r, key, now) = signed(rfc, body);
            check(&r, &key, body, now).unwrap();
            // Another body: the digest no longer matches.
            let err = check(&r, &key, b"{\"a\":2}", now).unwrap_err();
            assert!(err.0.contains("does not match"), "{rfc}: {err}");
            // Too old and too new.
            assert!(check(&r, &key, body, now + MAX_SKEW_SECS + 5)
                .unwrap_err()
                .0
                .contains("seconds"));
            assert!(check(&r, &key, body, now - MAX_SKEW_SECS - 5).is_err());
            // Another key.
            let other = PublicKey::Ed25519(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key(),
            );
            assert_eq!(
                check(&r, &other, body, now).unwrap_err().0,
                "the signature does not verify"
            );
            // Another path.
            let moved = Request {
                path: "/elsewhere".into(),
                ..r
            };
            assert!(check(&moved, &key, body, now).is_err(), "{rfc}");
        }
    }

    #[test]
    fn unbound_or_undated_signatures_are_refused() {
        let v = vectors();
        let cavage = &v["cavage12"];
        let key = PublicKey::from_pem(cavage["publicKeyPem"].as_str().unwrap()).unwrap();
        let mut h = headers(&cavage["request"]["headers"]);
        // C.1 signs only `Date`: valid math, bound to nothing.
        h.push((
            "signature".into(),
            cavage["cases"][0]["signature"].as_str().unwrap().into(),
        ));
        let r = Request {
            headers: h,
            ..Request::from(&cavage["request"])
        };
        let parsed = parse(&r.message()).unwrap().remove(0);
        verify(&parsed, &key).unwrap();
        let date = 1388957500; // Sun, 05 Jan 2014 21:31:40 GMT
        let err = check_policy(&parsed, &r.message(), br#"{"hello": "world"}"#, date).unwrap_err();
        assert!(err.0.contains("(request-target)"), "{err}");
        // A body without a signed digest.
        let mut c2 = parse(
            &Request {
                headers: {
                    let mut h = headers(&cavage["request"]["headers"]);
                    h.push((
                        "signature".into(),
                        cavage["cases"][1]["signature"].as_str().unwrap().into(),
                    ));
                    h
                },
                ..Request::from(&cavage["request"])
            }
            .message(),
        )
        .unwrap()
        .remove(0);
        let r = Request::from(&cavage["request"]);
        let err = check_policy(&c2, &r.message(), br#"{"hello": "world"}"#, date).unwrap_err();
        assert!(err.0.contains("Digest"), "{err}");
        // Undated.
        c2.covered.retain(|c| c != "date");
        let err = check_policy(&c2, &r.message(), b"", date).unwrap_err();
        assert!(err.0.contains("`date` or `(created)`"), "{err}");
    }

    #[test]
    fn weak_and_unknown_keys_and_algorithms_are_refused() {
        let v = vectors();
        let weak = PublicKey::from_pem(v["cavage12"]["publicKeyPem"].as_str().unwrap()).unwrap();
        assert!(weak.check_strength().unwrap_err().contains("1024"));
        let strong =
            PublicKey::from_pem(v["rfc9421"]["keys"]["test-key-rsa"].as_str().unwrap()).unwrap();
        strong.check_strength().unwrap();
        assert!(PublicKey::from_pem(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        )
        .is_err());
        let message = Message {
            method: "GET",
            scheme: "https",
            authority: "a",
            path: "/",
            query: None,
            headers: &[(
                "signature".into(),
                "keyId=\"k\",algorithm=\"hmac-sha256\",signature=\"AAAA\"".into(),
            )],
        };
        assert!(parse(&message).unwrap_err().0.contains("hmac-sha256"));
        // An Ed25519 signature claimed by an RSA key's `alg`.
        let ed = PublicKey::Ed25519(
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key(),
        );
        let parsed = Parsed {
            scheme: Scheme::Rfc9421,
            label: "s".into(),
            key_id: "k".into(),
            algorithm: Some(Algorithm::RsaV15Sha256),
            covered: vec![],
            created: None,
            expires: None,
            tag: None,
            base: vec![],
            signature: vec![0; 64],
        };
        assert!(verify(&parsed, &ed).unwrap_err().0.contains("does not fit"));
        // Round trip of both key kinds through PEM.
        assert_eq!(PublicKey::from_pem(&ed.to_pem()).unwrap(), ed);
        assert_eq!(PublicKey::from_pem(&strong.to_pem()).unwrap(), strong);
    }
}
