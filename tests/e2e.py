"""End-to-end checks against the running lab. A requests.Session plays the browser: it follows
redirects, fills in Keycloak's login form, and auto-posts the SAML form, so each flow runs for
real: LDAP bind, Keycloak sessions, token exchange, JWKS validation, SAML signatures.

    docker compose --profile test run --rm e2e
Exit code 1 if any check fails.
"""
import base64
import html
import http.cookiejar
import json
import re
import sys
import time

import requests
from urllib.parse import urlsplit

KC = "http://localhost:8180"
WEB = "http://localhost:8280"
API = "http://localhost:8380"
KONG = "http://localhost:8480"
SAML = "http://localhost:8580"
RESULTS = []
LEAVER: dict = {}


def browser_like_cookies():
    """Python's cookie jar differs from a browser in ways that break Keycloak logins: it won't send
    Secure cookies to http://localhost (browsers treat localhost as a secure context), and for the
    Version=1 cookies Keycloak sets it applies RFC 2965 domain rules that never match a dotless
    host. Everything in this lab is on localhost (cookies aren't scoped by port), so match on path
    and expiry only, as a browser would here. Patched on the class because requests builds a fresh
    default-policy jar for every request."""
    def return_ok(self, cookie, request):
        path = urlsplit(request.get_full_url()).path or "/"
        return path.startswith(cookie.path) and not cookie.is_expired()

    http.cookiejar.DefaultCookiePolicy.domain_return_ok = lambda self, domain, request: True
    http.cookiejar.DefaultCookiePolicy.return_ok = return_ok


def browser() -> requests.Session:
    return requests.Session()


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def form_action(page: str, contains: str):
    m = re.search(r'action="([^"]*' + re.escape(contains) + r'[^"]*)"', page)
    return html.unescape(m.group(1)) if m else None


def submit_login(s: requests.Session, page: requests.Response, username, password) -> requests.Response:
    action = form_action(page.text, "login-actions/authenticate")
    assert action, f"no login form at {page.url}"
    return s.post(action, data={"username": username, "password": password, "credentialId": ""})


def oidc_login(username, password, idp=None):
    """Sign in to the web app; returns (session, final response)."""
    s = browser()
    page = s.get(f"{WEB}/login" + (f"?idp={idp}" if idp else ""))
    r = submit_login(s, page, username, password)
    # A brokered first login may show Keycloak's "review profile" page; submit it as is.
    action = form_action(r.text, "first-broker-login")
    if action:
        fields = dict(re.findall(r'name="(\w+)"[^>]*value="([^"]*)"', r.text))
        r = s.post(action, data=fields)
    return s, r


def token(client_id, secret, realm="company"):
    r = requests.post(f"{KC}/realms/{realm}/protocol/openid-connect/token",
                      data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret})
    r.raise_for_status()
    return r.json()["access_token"]


def payload(jwt_token):
    part = jwt_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def tamper(jwt_token):
    """Same header and signature, payload changed to claim an extra role: the signature no longer matches."""
    h, p, sig = jwt_token.split(".")
    claims = payload(jwt_token)
    claims.setdefault("realm_access", {}).setdefault("roles", []).append("orders-admin")
    p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{h}.{p2}.{sig}"


def alg_none(jwt_token):
    h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    return f"{h}.{jwt_token.split('.')[1]}."


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def main():
    browser_like_cookies()
    # 1. OIDC Authorization Code + PKCE, users from LDAP, roles from LDAP groups
    s, r = oidc_login("alice", "alice-password")
    check("alice (LDAP) signs in to the web app via OIDC code + PKCE", r.url == f"{WEB}/" and "Signed in as alice" in r.text, r.url)
    me = s.get(f"{WEB}/me").json()
    check("ID token carries LDAP attributes", me.get("email") == "alice@company.local" and me.get("family_name") == "Admin", me.get("email"))
    app_cookies = [c for c in s.cookies if not c.path.startswith("/realms/")]  # not Keycloak's own SSO cookies
    check("browser holds no tokens, only a small session-id cookie",
          app_cookies and all(len(c.value) < 200 for c in app_cookies), [(c.name, len(c.value)) for c in app_cookies])
    check("alice (orders-admin) can read orders", s.get(f"{WEB}/api/orders").status_code == 200)
    check("alice (orders-admin) can create orders", s.post(f"{WEB}/api/orders", json={"item": "monitor"}).status_code == 201)

    s, r = oidc_login("bob", "bob-password")
    check("bob (orders-reader) can read orders", s.get(f"{WEB}/api/orders").status_code == 200)
    code = s.post(f"{WEB}/api/orders", json={"item": "x"}).status_code
    check("bob (orders-reader) cannot create orders", code == 403, code)

    s, r = oidc_login("carol", "carol-password")
    code = s.get(f"{WEB}/api/orders").status_code
    check("carol (in no group) signs in but is denied orders", "Signed in as carol" in r.text and code == 403, code)

    s, r = oidc_login("alice", "wrong-password")
    check("wrong LDAP password is rejected", "Invalid username or password" in r.text and not r.url.startswith(WEB))
    s, r = oidc_login("mallory", "anything")
    check("user who isn't in LDAP is rejected", "Invalid username or password" in r.text)

    # 2. Client credentials (service to service, no user)
    machine = token("machine-client", "machine-client-secret")
    claims = payload(machine)
    check("machine client gets a token with aud=orders-api", "orders-api" in (claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]))
    check("machine client can read orders", requests.get(f"{API}/orders", headers=bearer(machine)).status_code == 200)
    code = requests.post(f"{API}/orders", json={"item": "x"}, headers=bearer(machine)).status_code
    check("machine client cannot create orders", code == 403, code)

    # 3. The API validates tokens itself
    code = requests.get(f"{API}/orders").status_code
    check("API: no token -> 401", code == 401, code)
    code = requests.get(f"{API}/orders", headers=bearer(tamper(machine))).status_code
    check("API: tampered payload (role added) -> 401", code == 401, code)
    code = requests.get(f"{API}/orders", headers=bearer(alg_none(machine))).status_code
    check("API: alg=none token -> 401", code == 401, code)
    master = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"}).json()["access_token"]
    r = requests.get(f"{API}/orders", headers=bearer(master))
    check("API: valid token from another realm (issuer) -> 401", r.status_code == 401, r.json().get("detail"))

    # 4. Kong at the edge
    code = requests.get(f"{KONG}/api/orders").status_code
    check("Kong: no token -> 401 at the gateway", code == 401, code)
    code = requests.get(f"{KONG}/api/orders", headers=bearer(machine)).status_code
    check("Kong: valid token -> forwarded -> 200", code == 200, code)
    code = requests.get(f"{KONG}/api/orders", headers=bearer(tamper(machine))).status_code
    check("Kong: tampered token -> 401 at the gateway", code == 401, code)
    code = requests.get(f"{KONG}/api/orders", headers=bearer(master)).status_code
    check("Kong: token from an unknown issuer -> 401 at the gateway", code == 401, code)
    code = requests.post(f"{KONG}/api/orders", json={"item": "x"}, headers=bearer(machine)).status_code
    check("Kong passes authorisation to the API: machine POST -> 403", code == 403, code)

    # 5. Identity brokering: a partner company's IdP
    s, r = oidc_login("dave", "dave-password", idp="partner")
    check("dave (partner IdP) signs in via brokering", "Signed in as dave" in r.text, r.url)
    check("partner user gets orders-reader from the IdP mapper", s.get(f"{WEB}/api/orders").status_code == 200)
    code = s.post(f"{WEB}/api/orders", json={"item": "x"}).status_code
    check("partner user cannot create orders", code == 403, code)

    # 6. SAML 2.0
    s = browser()
    page = s.get(f"{SAML}/login")
    r = submit_login(s, page, "alice", "alice-password")
    acs = form_action(r.text, "/saml/acs")
    fields = dict(re.findall(r'name="(SAMLResponse|RelayState)"\s+value="([^"]*)"', r.text))
    check("Keycloak POSTs a SAMLResponse to the SP's ACS", acs == f"{SAML}/saml/acs" and "SAMLResponse" in fields, acs)
    genuine = fields.get("SAMLResponse", "")
    xml = base64.b64decode(genuine).decode()
    forged = base64.b64encode(xml.replace(">orders-reader<", ">orders-superuser<").encode()).decode()
    code = s.post(acs, data={**fields, "SAMLResponse": forged}, allow_redirects=False).status_code
    check("SAML: modified assertion -> rejected", code == 403, code)
    code = s.post(acs, data=fields, allow_redirects=False).status_code
    who = s.get(f"{SAML}/whoami").json() if code == 302 else {}
    check("SAML: genuine assertion -> signed in with LDAP roles",
          who.get("user") == "alice" and who.get("roles") == ["orders-admin", "orders-reader"], who)
    code = requests.post(acs, data=fields, allow_redirects=False).status_code
    check("SAML: replaying the same response -> rejected", code == 403, code)

    # 7. A leaver: alice's sessions are revoked in the IdP (what offboarding or "sign out everywhere" does) while
    #    her browser session in the web app still holds an access token. Reads use local JWT checks only, so they
    #    keep working until the token expires; writes are introspected, so they stop at once.
    s, r = oidc_login("alice", "alice-password")
    check("leaver drill: alice signed in and can create", s.post(f"{WEB}/api/orders", json={"item": "pre"}).status_code == 201)
    admin = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"}).json()["access_token"]
    users = requests.get(f"{KC}/admin/realms/company/users", params={"username": "alice", "exact": "true"},
                         headers=bearer(admin)).json()
    exp = s.get(f"{WEB}/me").json().get("exp")
    requests.post(f"{KC}/admin/realms/company/users/{users[0]['id']}/logout", headers=bearer(admin)).raise_for_status()
    revoked_at = time.time()
    read = s.get(f"{WEB}/api/orders").status_code
    write = s.post(f"{WEB}/api/orders", json={"item": "after"}).status_code
    gap = round(exp - revoked_at) if exp else None
    check("leaver drill: write after revocation -> 401 at once (introspection)", write == 401, write)
    check("leaver drill: read after revocation still 200 (local JWT, the documented gap)", read == 200,
          f"{read}; token valid for {gap} s more")
    LEAVER.update({"read_after_revocation": read, "write_after_revocation": write, "stale_read_window_s": gap})

    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    print("leaver drill: " + json.dumps(LEAVER))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
