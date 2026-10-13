"""A web app that signs users in with OpenID Connect, written by hand (no OIDC library) so every
step is visible:

  /login       state + nonce + PKCE verifier kept server-side; redirect to the authorization endpoint
  /callback    check state, exchange code + verifier (+ client secret) at the token endpoint over
               the back channel, validate the ID token (signature, iss, aud, exp, nonce)
  /api/orders  call orders-api with the user's access token. The browser never sees the tokens
               (backend-for-frontend): it holds only an opaque session cookie
  /logout      RP-initiated logout at the IdP

Browser-facing URLs use the public issuer (localhost:8180); server-to-server calls use the
internal one (keycloak:8080). Keycloak puts the public issuer in tokens either way.
"""
import base64
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode

import jwt
import requests
from flask import Flask, abort, jsonify, redirect, request, session

PUBLIC = os.environ.get("OIDC_PUBLIC_ISSUER", "http://localhost:8180/realms/company")
INTERNAL = os.environ.get("OIDC_INTERNAL_ISSUER", "http://keycloak:8080/realms/company")
CLIENT_ID = os.environ.get("CLIENT_ID", "web-app")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "web-app-secret")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8280/callback")
ORDERS_API = os.environ.get("ORDERS_API", "http://orders-api:8000")

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
jwks = jwt.PyJWKClient(f"{INTERNAL}/protocol/openid-connect/certs")
PENDING = {}  # state -> {verifier, nonce, created}; a real deployment keeps this in Redis with a TTL
TOKENS = {}   # session id -> tokens; never sent to the browser


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def pkce_pair():
    verifier = b64url(secrets.token_bytes(32))                      # 43 chars (RFC 7636)
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())  # S256
    return verifier, challenge


@app.get("/")
def index():
    t = TOKENS.get(session.get("sid"))
    if not t:
        return '<p>Not signed in. <a href="/login">Sign in</a> | <a href="/login?idp=partner">Sign in as a partner</a></p>'
    c = t["id_claims"]
    return (f'<p>Signed in as {c.get("preferred_username")} ({c.get("email")}). '
            '<a href="/me">ID token claims</a> | <a href="/api/orders">orders</a> | <a href="/logout">sign out</a></p>')


@app.get("/login")
def login():
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    PENDING[state] = {"verifier": verifier, "nonce": nonce, "created": time.time()}
    params = {
        "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if request.args.get("idp"):
        params["kc_idp_hint"] = request.args["idp"]  # skip Keycloak's login page, go straight to that IdP
    return redirect(f"{PUBLIC}/protocol/openid-connect/auth?{urlencode(params)}")


@app.get("/callback")
def callback():
    if "error" in request.args:
        abort(400, request.args.get("error_description", request.args["error"]))
    pending = PENDING.pop(request.args.get("state", ""), None)
    if not pending or time.time() - pending["created"] > 600:
        abort(400, "unknown or expired state (possible CSRF)")
    r = requests.post(f"{INTERNAL}/protocol/openid-connect/token", timeout=10, data={
        "grant_type": "authorization_code", "code": request.args["code"], "redirect_uri": REDIRECT_URI,
        "code_verifier": pending["verifier"], "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    })
    if r.status_code != 200:
        abort(502, f"token exchange failed: {r.text}")
    tokens = r.json()
    id_claims = jwt.decode(
        tokens["id_token"], jwks.get_signing_key_from_jwt(tokens["id_token"]).key,
        algorithms=["RS256"], audience=CLIENT_ID, issuer=PUBLIC, leeway=30,
    )
    if id_claims.get("nonce") != pending["nonce"]:
        abort(400, "nonce mismatch (possible token replay)")
    sid = secrets.token_urlsafe(32)
    TOKENS[sid] = {**tokens, "id_claims": id_claims}
    session.clear()
    session["sid"] = sid  # a fresh session id after login: no session fixation
    return redirect("/")


@app.get("/me")
def me():
    t = TOKENS.get(session.get("sid")) or abort(401)
    return jsonify(t["id_claims"])


@app.route("/api/orders", methods=["GET", "POST"])
def orders():
    t = TOKENS.get(session.get("sid")) or abort(401)
    r = requests.request(request.method, f"{ORDERS_API}/orders", timeout=10,
                         headers={"Authorization": f"Bearer {t['access_token']}"},
                         json=request.get_json(silent=True) if request.method == "POST" else None)
    return r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")}


@app.get("/logout")
def logout():
    t = TOKENS.pop(session.pop("sid", None), None)
    if not t:
        return redirect("/")
    return redirect(f"{PUBLIC}/protocol/openid-connect/logout?" + urlencode({
        "id_token_hint": t["id_token"], "post_logout_redirect_uri": REDIRECT_URI.rsplit("/", 1)[0] + "/"}))
