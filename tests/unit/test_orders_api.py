"""orders-api token validation and role checks, offline: tokens are signed with a key generated
here, and the API's JWKS lookup is replaced with that key."""
import importlib.util
import pathlib
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location("orders_api", pathlib.Path(__file__).parents[2] / "services/orders-api/app.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
api.signing_key = lambda token: KEY.public_key()
client = TestClient(api.app)


def make_token(key=KEY, alg="RS256", **overrides):
    now = int(time.time())
    claims = {"iss": api.ISSUER, "aud": "orders-api", "sub": "u1", "iat": now, "exp": now + 300,
              "preferred_username": "alice", "realm_access": {"roles": ["orders-reader"]}}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg)


def get(token):
    return client.get("/orders", headers={"Authorization": f"Bearer {token}"})


def test_valid_reader_token():
    r = get(make_token())
    assert r.status_code == 200 and r.json()["caller"] == "alice"


def test_missing_token_is_401_with_challenge():
    r = client.get("/orders")
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("token, reason", [
    (make_token(key=OTHER_KEY), "invalid token"),                       # signed by someone else
    (make_token(aud="another-api"), "token not issued for this API"),
    (make_token(iss="https://evil.example/realms/company"), "untrusted issuer"),
    (make_token(exp=int(time.time()) - 120), "token expired"),           # beyond the 30 s leeway
    (make_token(exp=None), "invalid token"),                            # exp is required
])
def test_rejected_tokens(token, reason):
    r = get(token)
    assert r.status_code == 401 and reason in r.json()["detail"]


def test_alg_none_is_rejected():
    unsigned = jwt.encode({"iss": api.ISSUER, "aud": "orders-api", "sub": "u1", "iat": 0, "exp": 2**31}, None, algorithm="none")
    assert get(unsigned).status_code == 401


def test_symmetric_algorithm_is_rejected():
    """Algorithm confusion: a token that switches itself to HS256 (an attacker would use the public
    key as the HMAC secret). The API pins RS256, so the token's own `alg` is never trusted."""
    assert get(make_token(key="any-shared-secret-at-least-32-bytes!!", alg="HS256")).status_code == 401


def test_clock_skew_within_leeway_is_accepted():
    assert get(make_token(exp=int(time.time()) - 10)).status_code == 200


def test_reader_cannot_create_admin_can(monkeypatch):
    monkeypatch.setattr(api, "still_active", lambda token: True)
    assert client.post("/orders", json={"item": "x"}, headers={"Authorization": f"Bearer {make_token()}"}).status_code == 403
    admin = make_token(realm_access={"roles": ["orders-admin"]})
    assert client.post("/orders", json={"item": "x"}, headers={"Authorization": f"Bearer {admin}"}).status_code == 201


def test_writes_need_an_active_token_reads_dont(monkeypatch):
    asked = []
    monkeypatch.setattr(api, "still_active", lambda token: asked.append(token) or False)   # the IdP says: revoked
    admin = make_token(realm_access={"roles": ["orders-admin", "orders-reader"]})
    r = client.post("/orders", json={"item": "x"}, headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code == 401 and "no longer active" in r.json()["detail"]
    assert get(admin).status_code == 200                     # reads: local checks only, no IdP call
    assert asked == [admin]


def test_introspection_failure_refuses_the_write(monkeypatch):
    def down(*_a, **_k):
        raise api.requests.ConnectionError("idp down")
    monkeypatch.setattr(api.requests, "post", down)
    assert api.still_active("t") is False                    # "can't check" never means "allowed"


def test_user_without_roles_is_403_not_401():
    assert get(make_token(realm_access={"roles": []})).status_code == 403
