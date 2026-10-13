# identity-federation-lab

One user directory, one identity provider, and every common way an application or API trusts it,
running in Docker Compose with an end-to-end test that exercises each flow for real:

- **OpenLDAP** holds the users and groups. Nobody is created in Keycloak.
- **Keycloak 26** federates LDAP: logins are checked with an LDAP bind, and LDAP groups become roles.
- A **web app** signs users in with **OIDC Authorization Code + PKCE**, written by hand: state,
  nonce, PKCE, ID-token validation, and tokens kept server-side.
- An **orders API** validates JWTs against the issuer's JWKS (signature, `iss`, `aud`, `exp`) and
  authorises by role.
- **Kong 3.9** checks tokens at the edge and rate-limits.
- A **batch job** uses the **client credentials** grant, so there's no user.
- A **SAML 2.0** app signs in through the same realm. Its response validation (signature,
  audience, recipient, InResponseTo, time window, replay, signature wrapping) is written out.
- A **partner company's IdP** is brokered over OIDC. Partner staff sign in with their own
  accounts and get read-only access.

It's a personal project rebuilding, in the open, the kind of identity federation I collaborated on
in production (Keycloak integrated with LDAP, OAuth2/OIDC and SAML). It isn't code from a former
employer.

## Result
`docker compose --profile test run --rm e2e` (2026-10-13, local; CI runs it on every push): **29/29 checks pass**.

| Flow | Checked |
|---|---|
| OIDC + LDAP | alice, bob and carol (LDAP only) sign in; ID token carries LDAP attributes; browser holds only a 106-byte session cookie; a wrong password and an unknown user are refused |
| Roles from LDAP groups | admin can create, reader can only read (403 on create), user in no group gets 403 |
| Client credentials | token has `aud=orders-api`; read allowed, create 403 |
| API token validation | no token, tampered payload, `alg=none`, valid token from another realm: all 401 |
| Kong | no token / tampered / unknown issuer stopped at the gateway (401); a valid token forwarded; the API still enforces roles behind it |
| Brokering | dave from the partner IdP signs in, gets `orders-reader` from the IdP mapper, can't create |
| SAML | Keycloak POSTs a signed assertion; a modified assertion is rejected; the genuine one signs alice in with her LDAP roles; replaying it is rejected |

Plus 22 offline unit tests (`tests/unit`) of the API's token checks (wrong key, audience, issuer,
expiry, leeway, `alg=none`, HS256 confusion) and the SAML validator (forged, wrong signer, unsigned,
signature wrapping, wrong audience, expired, unsolicited, replayed, XXE).

## Run it
```bash
docker compose up -d --build --wait          # ~1 min; Keycloak imports both realms on first start
docker compose --profile test run --rm e2e   # the end-to-end checks
pip install -r requirements-dev.txt && python -m pytest -q tests/unit
```
Click through it in a browser:

| URL | What | Sign in as |
|---|---|---|
| http://localhost:8280 | OIDC web app ("Sign in as a partner" for brokering) | `alice` / `alice-password` (admin), `bob` / `bob-password` (reader), `carol` / `carol-password` (no roles), partner: `dave` / `dave-password` |
| http://localhost:8580 | SAML app | same LDAP users |
| http://localhost:8180 | Keycloak admin console | `admin` / `admin` |
| http://localhost:8480/api/orders | Orders API through Kong | `Authorization: Bearer <token>` |
| http://localhost:8380/docs | Orders API directly | |

```bash
# A machine token, then the API through Kong:
TOKEN=$(curl -s -d grant_type=client_credentials -d client_id=machine-client -d client_secret=machine-client-secret \
  http://localhost:8180/realms/company/protocol/openid-connect/token | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8480/api/orders
```

## Layout
| Path | What's in it |
|---|---|
| [`ldap/bootstrap.ldif`](ldap/bootstrap.ldif) | Users and groups (`orders-admin`, `orders-reader`) |
| [`keycloak/company-realm.json`](keycloak/company-realm.json) | LDAP federation + mappers, clients (OIDC, client credentials, SAML), audience mappers, the partner IdP and its role mapper |
| [`keycloak/partner-realm.json`](keycloak/partner-realm.json) | The partner company's IdP |
| [`services/web-app`](services/web-app/app.py) | OIDC relying party, backend-for-frontend |
| [`services/orders-api`](services/orders-api/app.py) | Resource server: JWKS validation and role checks |
| [`services/saml-app`](services/saml-app/app.py) | SAML service provider |
| [`services/kong-config`](services/kong-config/render.py) | Renders Kong's declarative config with the realm's public key |
| [`tests/e2e.py`](tests/e2e.py) | The end-to-end checks (a scripted browser) |
| [`docs/design.md`](docs/design.md) | Trust model, decisions and alternatives, what production changes |
| [`docs/runbook.md`](docs/runbook.md) | Troubleshooting SSO by Keycloak event code, and key rotation |

## Limits (it's a lab)
Plain HTTP on localhost, Keycloak in dev mode with its embedded database, secrets in the realm file,
in-memory sessions in the apps (one worker each), LDAP without TLS. [`docs/design.md`](docs/design.md)
lists what a real deployment changes.
