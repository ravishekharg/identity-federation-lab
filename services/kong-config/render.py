"""Render Kong's declarative config with the realm's current signing key.

Kong OSS's jwt plugin verifies RS256 tokens against a public key stored on a consumer, matched by
the token's `iss` claim. It can't read a JWKS URL itself, so this one-shot job fetches the JWKS,
converts the RS256 signing key to PEM and writes kong.yml before Kong starts. When the realm key
rotates, rerun it and reload Kong (`kong reload`); see docs/runbook.md.
"""
import json
import os
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8180/realms/company")
JWKS_URL = os.environ.get("OIDC_JWKS_URL", "http://keycloak:8080/realms/company/protocol/openid-connect/certs")
UPSTREAM = os.environ.get("UPSTREAM", "http://orders-api:8000")
OUT = os.environ.get("OUT", "/kong/kong.yml")


def fetch_jwks(attempts=60):
    for i in range(attempts):
        try:
            r = requests.get(JWKS_URL, timeout=5)
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
        time.sleep(2)
    sys.exit(f"JWKS not reachable at {JWKS_URL}")


def pem(jwk: dict) -> str:
    key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def render(public_key_pem: str) -> str:
    indented = "\n".join("          " + line for line in public_key_pem.strip().splitlines())
    return f"""_format_version: "3.0"
services:
  - name: orders-api
    url: {UPSTREAM}
    routes:
      - name: orders
        paths: [/api]
        strip_path: true
    plugins:
      - name: jwt                       # edge check: valid signature from our IdP, not expired
        config:
          key_claim_name: iss
          claims_to_verify: [exp]
          header_names: [authorization]
          uri_param_names: []           # tokens only in the header, never in URLs (they get logged)
      - name: rate-limiting
        config:
          minute: 120
          policy: local
consumers:
  - username: company-realm
    jwt_secrets:
      - key: {ISSUER}
        algorithm: RS256
        rsa_public_key: |
{indented}
"""


if __name__ == "__main__":
    keys = [k for k in fetch_jwks()["keys"] if k.get("alg") == "RS256" and k.get("use") == "sig"]
    if not keys:
        sys.exit("no RS256 signing key in the JWKS")
    with open(OUT, "w") as f:
        f.write(render(pem(keys[0])))
    print(f"wrote {OUT} for issuer {ISSUER} (kid {keys[0]['kid']})")
