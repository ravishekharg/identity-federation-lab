"""A SAML 2.0 service provider written out step by step (the kind of legacy app that only speaks
SAML), signing users in through the same Keycloak realm, and so through the same LDAP directory.

  /login      SP-initiated: an AuthnRequest, deflated + base64 (HTTP-Redirect binding)
  /saml/acs   the IdP POSTs a SAMLResponse here (HTTP-POST binding). We accept it only if:
                - the Assertion's XML signature verifies against the IdP's certificate, and we
                  read attributes ONLY from the element the signature covers (defeats XML
                  signature wrapping, where an attacker adds a second, unsigned assertion)
                - Status is Success, Destination/Recipient is our ACS URL, Audience is us
                - InResponseTo matches a request we sent (no unsolicited responses)
                - now is within NotBefore/NotOnOrAfter (with a little clock skew)
                - this assertion ID hasn't been used before (no replay)
  /whoami     the signed-in user and their roles (from the LDAP groups, via the Role attribute)
"""
import base64
import os
import secrets
import time
import uuid
import zlib
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from flask import Flask, abort, jsonify, redirect, request, session
from lxml import etree
from signxml import XMLVerifier

ENTITY_ID = os.environ.get("SP_ENTITY_ID", "http://localhost:8580/saml/metadata")
ACS_URL = os.environ.get("SP_ACS_URL", "http://localhost:8580/saml/acs")
IDP_SSO_URL = os.environ.get("IDP_SSO_URL", "http://localhost:8180/realms/company/protocol/saml")
IDP_METADATA_URL = os.environ.get("IDP_METADATA_URL", "http://keycloak:8080/realms/company/protocol/saml/descriptor")
SKEW = 60  # seconds

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}
PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)  # no XXE

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
REQUESTS = {}  # AuthnRequest ID -> time sent
USED = {}      # Assertion ID -> expiry, for replay detection
_idp_cert = None


class Rejected(Exception):
    pass


def idp_certificate() -> str:
    """The IdP's signing certificate, from its metadata (fetched once; refetch on rotation)."""
    global _idp_cert
    if _idp_cert is None:
        md = etree.fromstring(requests.get(IDP_METADATA_URL, timeout=10).content, PARSER)
        b64 = md.find(".//md:IDPSSODescriptor//ds:X509Certificate", NS).text.strip()
        _idp_cert = "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n"
    return _idp_cert


def authn_request(request_id: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{request_id}" '
        f'Version="2.0" IssueInstant="{now}" Destination="{IDP_SSO_URL}" AssertionConsumerServiceURL="{ACS_URL}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f"<saml:Issuer>{ENTITY_ID}</saml:Issuer>"
        f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>'
        f"</samlp:AuthnRequest>"
    )


def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def validate_response(saml_response_b64: str, cert: str, now: float = None) -> dict:
    """Return {user, roles, attributes} or raise Rejected. Pure apart from REQUESTS/USED."""
    now = time.time() if now is None else now
    try:
        root = etree.fromstring(base64.b64decode(saml_response_b64), PARSER)
    except Exception:
        raise Rejected("not a SAML response")
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise Rejected("not a SAML response")
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != "urn:oasis:names:tc:SAML:2.0:status:Success":
        raise Rejected("IdP returned a non-success status")
    if root.get("Destination") not in (None, ACS_URL):
        raise Rejected("Destination is not this ACS")
    if len(root.findall(".//saml:Assertion", NS)) != 1:
        raise Rejected("expected exactly one assertion")

    try:
        verified = XMLVerifier().verify(root, x509_cert=cert)
    except Exception as e:
        raise Rejected(f"signature check failed: {e.__class__.__name__}")
    assertion = verified.signed_xml  # from here on, read only what the signature covers
    if assertion.tag != f"{{{NS['saml']}}}Assertion":
        raise Rejected("the signature does not cover the assertion")

    in_response_to = root.get("InResponseTo")
    if in_response_to not in REQUESTS:
        raise Rejected("InResponseTo does not match a request we sent")

    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise Rejected("no Conditions")
    if now + SKEW < parse_time(conditions.get("NotBefore", "1970-01-01T00:00:00Z")):
        raise Rejected("assertion not yet valid")
    not_on_or_after = parse_time(conditions.get("NotOnOrAfter"))
    if now - SKEW >= not_on_or_after:
        raise Rejected("assertion expired")
    audiences = [a.text for a in conditions.findall("saml:AudienceRestriction/saml:Audience", NS)]
    if ENTITY_ID not in audiences:
        raise Rejected("assertion is for a different audience")

    scd = assertion.find("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NS)
    if scd is None or scd.get("Recipient") != ACS_URL:
        raise Rejected("Recipient is not this ACS")
    if scd.get("InResponseTo") not in (None, in_response_to):
        raise Rejected("SubjectConfirmation InResponseTo mismatch")
    if scd.get("NotOnOrAfter") and now - SKEW >= parse_time(scd.get("NotOnOrAfter")):
        raise Rejected("subject confirmation expired")

    assertion_id = assertion.get("ID")
    for k in [k for k, exp in USED.items() if exp < now]:
        del USED[k]
    if assertion_id in USED:
        raise Rejected("assertion replayed")
    USED[assertion_id] = not_on_or_after + SKEW
    REQUESTS.pop(in_response_to, None)

    attributes = {}
    for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        attributes.setdefault(attr.get("Name"), []).extend(v.text for v in attr.findall("saml:AttributeValue", NS))
    return {
        "user": assertion.find("saml:Subject/saml:NameID", NS).text,
        "roles": sorted(r for r in attributes.get("Role", []) if r.startswith("orders-")),
        "attributes": attributes,
    }


@app.get("/")
def index():
    if "user" not in session:
        return '<p>Not signed in. <a href="/login">Sign in with SAML</a></p>'
    return f'<p>Signed in as {session["user"]}, roles {session["roles"]}. <a href="/whoami">details</a></p>'


@app.get("/saml/metadata")
def metadata():
    xml = (
        f'<md:EntityDescriptor xmlns:md="{NS["md"]}" entityID="{ENTITY_ID}"><md:SPSSODescriptor '
        f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true">'
        f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{ACS_URL}" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>'
    )
    return xml, 200, {"Content-Type": "application/samlmetadata+xml"}


@app.get("/login")
def login():
    request_id = "_" + uuid.uuid4().hex
    REQUESTS[request_id] = time.time()
    deflater = zlib.compressobj(wbits=-15)  # raw DEFLATE, as the Redirect binding requires
    encoded = base64.b64encode(deflater.compress(authn_request(request_id).encode()) + deflater.flush()).decode()
    return redirect(f"{IDP_SSO_URL}?" + urlencode({"SAMLRequest": encoded, "RelayState": "/"}))


@app.post("/saml/acs")
def acs():
    try:
        result = validate_response(request.form.get("SAMLResponse", ""), idp_certificate())
    except Rejected as e:
        abort(403, str(e))
    session.clear()
    session.update(user=result["user"], roles=result["roles"], email=(result["attributes"].get("email") or [None])[0])
    return redirect(request.form.get("RelayState") or "/")


@app.get("/whoami")
def whoami():
    if "user" not in session:
        abort(401)
    return jsonify(user=session["user"], roles=session["roles"], email=session.get("email"))
