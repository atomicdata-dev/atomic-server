#!/usr/bin/env python3
"""Signing for the TestFlight build in CI, through the App Store Connect API.

The only secret is an App Store Connect API key (Admin role). Each run gets a
fresh Apple Distribution certificate and App Store profile, and `cleanup`
revokes and deletes them again, so no signing key has to be stored anywhere.
Builds already uploaded to TestFlight stay valid: Apple re-signs them.

    python3 testflight.py prepare DIR   # writes signing files into DIR
    python3 testflight.py cleanup DIR   # revokes what prepare created

Reads APP_STORE_CONNECT_KEY_ID, APP_STORE_CONNECT_ISSUER_ID and
APP_STORE_CONNECT_PRIVATE_KEY (the .p8 contents) from the environment.
Needs the `cryptography` package.
"""

import base64
import json
import os
import plistlib
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

API = "https://api.appstoreconnect.apple.com/v1"
BUNDLE_ID = "io.ontola.atomic"
PROFILE_PREFIX = "Atomic Place CI"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token() -> str:
    key = serialization.load_pem_private_key(
        os.environ["APP_STORE_CONNECT_PRIVATE_KEY"].encode(), None)
    header = {"alg": "ES256", "kid": os.environ["APP_STORE_CONNECT_KEY_ID"], "typ": "JWT"}
    now = int(time.time())
    claims = {"iss": os.environ["APP_STORE_CONNECT_ISSUER_ID"], "iat": now,
              "exp": now + 15 * 60, "aud": "appstoreconnect-v1"}
    signing_input = (b64url(json.dumps(header).encode()) + "." +
                     b64url(json.dumps(claims).encode()))
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def call(method: str, path: str, body: dict | None = None) -> dict:
    request = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read()
    except urllib.error.HTTPError as error:
        sys.exit(f"App Store Connect {method} {path}: {error.code} {error.read().decode()}")
    return json.loads(text) if text else {}


def bundle_id() -> str:
    found = call("GET", f"/bundleIds?filter[identifier]={BUNDLE_ID}&filter[platform]=IOS")["data"]
    for entry in found:
        if entry["attributes"]["identifier"] == BUNDLE_ID:
            return entry["id"]
    print(f"Registering the bundle ID {BUNDLE_ID}")
    return call("POST", "/bundleIds", {"data": {"type": "bundleIds", "attributes": {
        "identifier": BUNDLE_ID, "name": "Atomic Place", "platform": "IOS"}}})["data"]["id"]


def prepare(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    bundle = bundle_id()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Atomic Place CI")]))
           .sign(key, hashes.SHA256()))
    created = call("POST", "/certificates", {"data": {"type": "certificates", "attributes": {
        "certificateType": "DISTRIBUTION",
        "csrContent": csr.public_bytes(serialization.Encoding.PEM).decode()}}})["data"]
    (out / "certificate-id").write_text(created["id"])
    cert = x509.load_der_x509_certificate(base64.b64decode(created["attributes"]["certificateContent"]))
    team = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
    identity = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    password = secrets.token_hex(16)
    (out / "distribution.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"Atomic Place CI", key, cert, None,
        # The macOS keychain only imports the legacy 3DES/SHA-1 format.
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())))
    (out / "p12-password").write_text(password)

    name = f"{PROFILE_PREFIX} {os.environ.get('GITHUB_RUN_ID', int(time.time()))}"
    profile = call("POST", "/profiles", {"data": {
        "type": "profiles",
        "attributes": {"name": name, "profileType": "IOS_APP_STORE"},
        "relationships": {
            "bundleId": {"data": {"type": "bundleIds", "id": bundle}},
            "certificates": {"data": [{"type": "certificates", "id": created["id"]}]}}}})["data"]
    (out / "profile-id").write_text(profile["id"])
    uuid = profile["attributes"]["uuid"]
    (out / f"{uuid}.mobileprovision").write_bytes(
        base64.b64decode(profile["attributes"]["profileContent"]))

    # Only the Runner target includes this file (from Flutter/Release.xcconfig),
    # so the plugins' pods keep building unsigned.
    (out / "Signing.xcconfig").write_text(
        "CODE_SIGN_STYLE = Manual\n"
        f"DEVELOPMENT_TEAM = {team}\n"
        f"CODE_SIGN_IDENTITY = {identity}\n"
        f"CODE_SIGN_IDENTITY[sdk=iphoneos*] = {identity}\n"
        f"PROVISIONING_PROFILE_SPECIFIER = {name}\n")
    (out / "ExportOptions.plist").write_bytes(plistlib.dumps({
        "method": "app-store-connect", "teamID": team, "signingStyle": "manual",
        "signingCertificate": identity, "provisioningProfiles": {BUNDLE_ID: name},
        "uploadSymbols": True}))
    print(f"Signing as {identity} with profile {name}")


def cleanup(out: Path) -> None:
    profile = out / "profile-id"
    if profile.exists():
        call("DELETE", f"/profiles/{profile.read_text()}")
    certificate = out / "certificate-id"
    if certificate.exists():
        call("DELETE", f"/certificates/{certificate.read_text()}")


if __name__ == "__main__":
    {"prepare": prepare, "cleanup": cleanup}[sys.argv[1]](Path(sys.argv[2]))
