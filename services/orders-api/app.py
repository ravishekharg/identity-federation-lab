"""Orders API: a resource server. It doesn't take anyone's word for who the caller is; it validates
the JWT itself on every request: signature (key from the issuer's JWKS, chosen by `kid`), issuer,
audience, expiry, then authorises by realm role.

GET  /orders  needs role orders-reader                   (local JWT checks only: fast, no IdP call)
POST /orders  needs role orders-admin, AND the IdP must confirm the token is still active (RFC 7662 introspection)

Why both: a JWT stays valid until it expires, even after the user signs out, is disabled or leaves the
company. Local validation can't know; only the IdP can. Asking it on every request costs a round trip and
makes the IdP a dependency of every call, so it's used where the risk is: writes. Reads accept up to one token
lifetime (5 minutes here) of staleness. INTROSPECT=off turns it off; INTROSPECT=all applies it to reads too.
"""
import os
import time

import jwt
import requests
from fastapi import Depends, FastAPI, HTTPException, Request

ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8180/realms/company")
JWKS_URL = os.environ.get("OIDC_JWKS_URL", "http://keycloak:8080/realms/company/protocol/openid-connect/certs")
AUDIENCE = os.environ.get("OIDC_AUDIENCE", "orders-api")
LEEWAY = 30  # seconds of clock skew tolerated on exp/iat/nbf
INTROSPECT = os.environ.get("INTROSPECT", "writes")          # off | writes | all
INTROSPECT_URL = os.environ.get("OIDC_INTROSPECT_URL",
                                "http://keycloak:8080/realms/company/protocol/openid-connect/token/introspect")
INTROSPECT_CLIENT = (os.environ.get("INTROSPECT_CLIENT_ID", "orders-api"),
                     os.environ.get("INTROSPECT_CLIENT_SECRET", "orders-api-secret"))

app = FastAPI(title="orders-api")
# Caches keys; on an unknown kid (the IdP rotated its key) it refetches the JWKS.
jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True, lifespan=600)
ORDERS = [{"id": 1, "item": "laptop", "by": "seed"}]


def signing_key(token: str):
    return jwks.get_signing_key_from_jwt(token).key


def unauthorized(reason: str) -> HTTPException:
    return HTTPException(401, reason, headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{reason}"'})


def validate(token: str, key) -> dict:
    try:
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],  # never "none", never an algorithm the token picks for itself
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=LEEWAY,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise unauthorized("token expired")
    except jwt.InvalidAudienceError:
        raise unauthorized("token not issued for this API")
    except jwt.InvalidIssuerError:
        raise unauthorized("untrusted issuer")
    except jwt.PyJWTError as e:
        raise unauthorized(f"invalid token: {e.__class__.__name__}")


def claims(request: Request) -> dict:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    token = header[7:]
    try:
        key = signing_key(token)
    except (jwt.PyJWTError, jwt.PyJWKClientError) as e:
        raise unauthorized(f"invalid token: {e.__class__.__name__}")
    c = validate(token, key)
    c["_token"] = token
    return c


def still_active(token: str) -> bool:
    """Ask the IdP. A revoked session, a disabled or deleted user, or a logged-out token all come back active=false.
    If the IdP can't answer, refuse: for a write, "can't check" must not mean "allowed"."""
    try:
        r = requests.post(INTROSPECT_URL, data={"token": token, "token_type_hint": "access_token"},
                          auth=INTROSPECT_CLIENT, timeout=3)
        return r.status_code == 200 and r.json().get("active") is True
    except requests.RequestException:
        return False


def roles(c: dict) -> set:
    return set(c.get("realm_access", {}).get("roles", []))


def require(role: str, write: bool = False):
    def check(c: dict = Depends(claims)) -> dict:
        if role not in roles(c):
            raise HTTPException(403, f"requires role {role}")
        if (INTROSPECT == "all" or (write and INTROSPECT == "writes")) and not still_active(c["_token"]):
            raise unauthorized("token no longer active (revoked or user disabled)")
        return c
    return check


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/orders")
def list_orders(c: dict = Depends(require("orders-reader"))):
    return {"caller": c.get("preferred_username") or c.get("azp"), "roles": sorted(roles(c)), "orders": ORDERS}


@app.post("/orders", status_code=201)
def create_order(body: dict, c: dict = Depends(require("orders-admin", write=True))):
    order = {"id": len(ORDERS) + 1, "item": str(body.get("item", "?")), "by": c.get("preferred_username"), "at": int(time.time())}
    ORDERS.append(order)
    return order
