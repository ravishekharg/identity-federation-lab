# Runbook: identity problems and how to find them

Most SSO failures are one of a handful of causes. Start with Keycloak's events: every failed
login logs a `type="LOGIN_ERROR"` line with an `error=` code.
```bash
docker compose logs keycloak | grep -E 'LOGIN_ERROR|IDENTITY_PROVIDER|WARN|ERROR'
```

| Symptom | `error=` / message | Cause | Fix |
|---|---|---|---|
| "Invalid parameter: redirect_uri" page | `invalid_redirect_uri` | The app's redirect URI isn't in the client's list (scheme, port and trailing slash all count) | Add the exact URI to `redirectUris`; avoid `*` wildcards in production |
| Login page reloads with "Cookie not found" | `cookie_not_found` | The browser didn't return Keycloak's `AUTH_SESSION_ID`: third-party cookie blocking, a proxy stripping cookies, http on a non-localhost host (cookies are `Secure; SameSite=None`) | Serve Keycloak over HTTPS on a hostname; check the proxy forwards `Cookie`/`Set-Cookie`. (This lab's e2e test hit this: Python's cookie jar needed browser-like rules.) |
| Every LDAP user fails with "Invalid username or password" | `invalid_user_credentials` + `User returned from LDAP has null username` | LDAP attribute mappers missing or wrong (a realm import with explicit sub-components doesn't create the defaults) | Add the `uid→username` mapper (and email/name). Test with *User federation → Test connection / Test authentication* |
| LDAP users can't log in, Keycloak logs `Connection refused` / timeout | `invalid_user_credentials` | Directory unreachable, wrong bind DN/password, LDAPS certificate not trusted | `ldapsearch -x -H ldap://ldap -D <bindDn> -w <pw> -b <usersDn>` from the Keycloak network |
| User logs in but gets 403 | (none: login succeeded) | Not in the LDAP group, or the token lacks the role: decode it (`realm_access.roles`) | Add the user to the LDAP group; check the `role-ldap-mapper`'s groups DN and membership attribute |
| API returns 401 "untrusted issuer" | API log | Token `iss` differs from what the API expects: Keycloak reached via another hostname, or `KC_HOSTNAME` unset behind a proxy | Set `KC_HOSTNAME` (and `--proxy-headers xforwarded`) so the issuer is stable |
| API returns 401 "token not issued for this API" | API log | Token lacks `aud=orders-api` | Add an audience mapper (or client scope) to the calling client |
| API returns 401 "token expired" soon after login | API log | Clock skew between hosts, or the token really expired and the app doesn't refresh | NTP on all hosts; the API allows 30 s leeway; the app should use the refresh token |
| Broker login fails, "Unexpected error when authenticating with identity provider" | `identity_provider_login_failure` | Wrong client secret/redirect URI at the partner, partner issuer/JWKS mismatch, or a broken IdP mapper (this lab: a wrong mapper type id caused a NullPointerException) | Keycloak's log has the exception; check the IdP's token URL is reachable from Keycloak (back channel) |
| SAML SP rejects with "signature check failed" | SP log | IdP signing key rotated, SP still has the old certificate | Refetch the IdP metadata (the SP caches the cert); in production, publish the new key before activating it |
| SAML SP rejects with "Recipient is not this ACS" / audience | SP log | Client ID (entity ID) or ACS URL mismatch between SP and IdP | Make the Keycloak client ID equal the SP's entity ID; set the ACS URL on the client |

## Rotating the realm signing key without downtime
1. Add a new RSA key provider with a higher priority. Keycloak signs new tokens with it and keeps
   publishing both public keys in the JWKS.
2. Resource servers that use the JWKS (orders-api, the web app) pick it up automatically: an
   unknown `kid` triggers a refetch.
3. Kong has a static key: rerun `docker compose run --rm kong-config` and `docker compose exec kong kong reload`.
   Limitation of the OSS jwt plugin: it matches one key per issuer (`key` is unique), so there's no
   overlap; tokens signed with the old key fail at Kong from the switch until they expire (5 min
   here). If that matters, use a JWKS-aware gateway plugin.
4. After the longest token lifetime has passed, make the old key passive, then delete it.
