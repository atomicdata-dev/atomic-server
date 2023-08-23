# -*- coding: utf-8 -*-
import jwt
import uuid
from datetime import datetime, timezone
from OpenSSL import crypto
from typing import Tuple, Optional
import sys


def make_client_assertion(clientID: str, targetID: str, cert_str: str, priv_key: str) -> str:

    # Create header
    # Specifying additional header values ("x5c" & "typ"), in addition to the standard value "alg"
    x5c = [cert_str]
    header = {}
    header["typ"] = "JWT"
    header["x5c"] = x5c

    now = datetime.now(timezone.utc).timestamp()
    # Create payload
    iss = clientID
    sub = clientID
    aud = targetID
    jti = str(uuid.uuid1())
    iat = int(now)
    nbf = iat
    exp = int(now) + 3600

    payload = {}
    payload["iss"] = iss
    payload["sub"] = sub
    payload["nbf"] = nbf
    payload["aud"] = aud
    payload["jti"] = jti
    payload["iat"] = iat
    payload["exp"] = exp

    # Generate client assertion
    key_from_str = jwt.jwk_from_pem(priv_key.encode('utf-8'))
    client_assertion = jwt.JWT().encode(payload, key_from_str, optional_headers=header, alg="RS256")

    return client_assertion

def normalize_pubkey(pubkey: str) -> str:
    parts = pubkey.split("\n")
    final = ''

    for part in parts[1:len(parts)-2]:
        final += part

    return final

def normalize_cert(cert: str) -> str:
    parts = cert.split("\n")
    final = ''

    for part in parts[1:len(parts)-2]:
        final += part

    return final

def normalize_privkey(privkey: str) -> str:
    parts = privkey.split("\n")
    final = parts[0] + "\n"

    for part in parts[1:len(parts)-2]:
        final += part

    final += "\n" + parts[len(parts)-2]

    return final

def parse_cert(cert_file: str, password: str) -> Tuple[str, str, Optional[str]]:
    with open(cert_file, "rb") as f:
        cert_data = f.read()
        p12 = crypto.load_pkcs12(cert_data, str.encode(password))

        cert = p12.get_certificate()
        subject = cert.get_subject()
        comps = subject.get_components()
        serial_nr : str|None = None
        for comp in comps:
            if comp[0].decode('utf-8') == 'serialNumber':
                serial_nr = comp[1].decode('utf-8')
                break

        cert_str = normalize_cert(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))

        priv_key = p12.get_privatekey()
        priv_key_str = normalize_privkey(crypto.dump_privatekey(crypto.FILETYPE_PEM, priv_key).decode('utf-8'))

        return [cert_str, priv_key_str, serial_nr]

def main():
    import argparse

    parser = argparse.ArgumentParser("Makes client assertion for iShare")
    parser.add_argument("-t", "--target_id", help="For which target (aud) is this client_assertion?", required=True)
    parser.add_argument("-c", "--cert", help="Certificate file", required=True)
    parser.add_argument("-p", "--password", help="Certificate password", required=False)

    args = parser.parse_args()

    if not args.password:
        args.password = input("Enter password:")

    if not args.password or args.password == '':
        print('no password')
        return 1

    cert_str, priv_key, serial_nr = parse_cert(args.cert, args.password)
    if not serial_nr:
        print("Couldn't extract serial number from cert")
        return 1

    assertion = make_client_assertion(
        clientID=serial_nr,
        targetID=args.target_id,
        cert_str=cert_str,
        priv_key=priv_key,
    )

    print(assertion)

    return 0


if __name__ == "__main__":
    sys.exit(main())
