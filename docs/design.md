# Design notes

## The pieces and who trusts whom
```
                       ┌──────────── company Keycloak realm ────────────┐
 OpenLDAP ── bind ───► │ LDAP user federation (READ_ONLY, groups→roles) │ ◄── OIDC broker ── partner realm (its own users)
 (users, groups)       │ clients: web-app, machine-client, SAML SP      │
                       └───┬───────────────┬───────────────┬────────────┘
             OIDC code+PKCE│  client creds │  SAML 2.0     │ JWKS (public keys)
                           ▼               ▼               ▼
                       web-app (BFF)   batch job       saml-app            Kong (edge: signature, exp, rate limit)
                           └──── access token ────► orders-api ◄──────────┘ (API: signature, iss, aud, exp, roles)
```
- **LDAP stays the source of truth.** Keycloak never stores a password: it checks each login with
  an LDAP bind. `READ_ONLY` edit mode means nothing in Keycloak can change the directory. Group
  membership becomes realm roles through the `role-ldap-mapper`, so access is granted by adding
  someone to an LDAP group, the way the directory team already works.
- **One realm, many protocols.** The OIDC app, the client-credentials job and the SAML app all
  get identity from the same realm, so a user disabled in LDAP is locked out of all of them.
- **Brokering instead of copying accounts.** Partner staff sign in at their own IdP. Keycloak
  creates a linked, local shadow user on first login (`first broker login` flow) and an IdP mapper
  grants partners `orders-reader` only. No partner passwords ever reach us.

## Decisions
| Decision | Why | Alternative |
|---|---|---|
| Authorization Code + PKCE with a confidential client, tokens kept server-side (BFF) | Tokens never reach the browser, so XSS can't exfiltrate them; PKCE stops a stolen code being redeemed | SPA holding tokens in memory (public client + PKCE): simpler hosting, larger XSS blast radius |
| `state` and `nonce` checked by hand | `state` = CSRF protection for the callback; `nonce` = the ID token was minted for this login (no replay) | An OIDC library does the same; written out here to show the checks |
| Short access tokens (5 min) | A leaked token is useful only briefly; there's no revocation check on each call | Token introspection on each call (revocable, but a network call per request) |
| The API validates every token itself, even behind Kong | Defence in depth: the gateway can be misconfigured or bypassed inside the network | Trust the gateway and pass identity in headers: only if the API is unreachable except via the gateway (mTLS / network policy) |
| `aud=orders-api` via an audience mapper | A token issued for another service in the same realm can't be replayed against this API | Separate realms per API: heavy |
| Pin `RS256` in the verifier | Blocks `alg=none` and HS256 algorithm-confusion attacks | |
| Kong checks signature + expiry only; roles in the API | Coarse authentication at the edge stops junk early; fine-grained authorisation belongs with the business logic | Kong OIDC plugin (Enterprise) or OPA at the gateway |
| SAML: verify the assertion signature, then read only the signed element; one assertion only | Prevents XML signature wrapping, the most common real SAML vulnerability | A maintained library (python3-saml, pysaml2): what you'd use in production |
| Frontend vs back-channel URLs (`localhost:8180` vs `keycloak:8080`) | Browsers and containers reach Keycloak by different names; `KC_HOSTNAME` pins the issuer so tokens validate everywhere | One hostname for everything (needs DNS/hosts entries) |

## What a real deployment changes
- TLS everywhere, `sslRequired: external`, Keycloak in production mode with Postgres and 2+ nodes
  (Infinispan for sessions), realm config from GitOps (keycloak-config-cli or the Terraform provider)
  instead of a one-time import.
- LDAPS with the directory's CA, a dedicated read-only bind account, `cachePolicy` tuned, periodic
  sync for deletions.
- Secrets from a vault, never in the realm file. Client authentication with `private_key_jwt`
  instead of shared secrets.
- Session store in Redis for the web app (it holds state in memory, so it runs as one worker here).
- Kong: the realm key re-rendered on rotation (see the runbook) or an OIDC-capable plugin that reads
  the JWKS directly.
- MFA (TOTP / WebAuthn) as a conditional step in the browser flow, for admins first.
