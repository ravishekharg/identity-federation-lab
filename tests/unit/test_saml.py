"""The SAML SP's response validation, offline: responses are built and signed here with a
throwaway IdP key and certificate, then forged in the ways real attacks do."""
import base64
import copy
import datetime
import importlib.util
import pathlib
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner

spec = importlib.util.spec_from_file_location("saml_app", pathlib.Path(__file__).parents[2] / "services/saml-app/app.py")
sp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sp)
NS = sp.NS


def keypair(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM).decode())


IDP_KEY, IDP_CERT = keypair("idp")
EVIL_KEY, EVIL_CERT = keypair("evil")


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def assertion_xml(request_id, user="alice", roles=("orders-reader",), audience=sp.ENTITY_ID, lifetime=300, aid="_a1"):
    now = time.time()
    values = "".join(f"<saml:AttributeValue>{r}</saml:AttributeValue>" for r in roles)
    return (
        f'<saml:Assertion xmlns:saml="{NS["saml"]}" ID="{aid}" Version="2.0" IssueInstant="{iso(now)}">'
        f"<saml:Issuer>http://idp</saml:Issuer>"
        f"<saml:Subject><saml:NameID>{user}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
        f'<saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{sp.ACS_URL}" NotOnOrAfter="{iso(now + lifetime)}"/>'
        f"</saml:SubjectConfirmation></saml:Subject>"
        f'<saml:Conditions NotBefore="{iso(now - 5)}" NotOnOrAfter="{iso(now + lifetime)}">'
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
        f'<saml:AttributeStatement><saml:Attribute Name="Role">{values}</saml:Attribute></saml:AttributeStatement>'
        f"</saml:Assertion>"
    )


def signed_assertion(key=IDP_KEY, cert=IDP_CERT, **kw):
    assertion = etree.fromstring(assertion_xml(**kw))
    return XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                     c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
        assertion, key=key, cert=cert, reference_uri="#" + assertion.get("ID"))


def response(assertions, request_id):
    root = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="_r1" Version="2.0" '
        f'IssueInstant="{iso(time.time())}" Destination="{sp.ACS_URL}" InResponseTo="{request_id}">'
        f'<saml:Issuer>http://idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f"</samlp:Response>")
    for a in assertions:
        root.append(a)
    return base64.b64encode(etree.tostring(root)).decode()


@pytest.fixture
def rid():
    sp.REQUESTS.clear()
    sp.USED.clear()
    sp.REQUESTS["_req1"] = time.time()
    return "_req1"


def test_valid_response(rid):
    result = sp.validate_response(response([signed_assertion(request_id=rid)], rid), IDP_CERT)
    assert result["user"] == "alice" and result["roles"] == ["orders-reader"]


def test_modified_attribute_breaks_signature(rid):
    xml = base64.b64decode(response([signed_assertion(request_id=rid)], rid)).replace(b">orders-reader<", b">orders-admin<")
    with pytest.raises(sp.Rejected, match="signature"):
        sp.validate_response(base64.b64encode(xml).decode(), IDP_CERT)


def test_signed_by_someone_else(rid):
    with pytest.raises(sp.Rejected, match="signature"):
        sp.validate_response(response([signed_assertion(key=EVIL_KEY, cert=EVIL_CERT, request_id=rid)], rid), IDP_CERT)


def test_unsigned_assertion(rid):
    with pytest.raises(sp.Rejected, match="signature"):
        sp.validate_response(response([etree.fromstring(assertion_xml(rid))], rid), IDP_CERT)


def test_signature_wrapping(rid):
    """XSW: keep the genuine signed assertion (so a naive 'is there a valid signature?' check
    passes) and add an unsigned one claiming admin, hoping the app reads the wrong one."""
    genuine = signed_assertion(request_id=rid, user="bob")
    evil = etree.fromstring(assertion_xml(rid, user="bob", roles=("orders-admin",), aid="_evil"))
    with pytest.raises(sp.Rejected, match="exactly one assertion"):
        sp.validate_response(response([evil, genuine], rid), IDP_CERT)


def test_wrong_audience(rid):
    with pytest.raises(sp.Rejected, match="audience"):
        sp.validate_response(response([signed_assertion(request_id=rid, audience="http://other-sp")], rid), IDP_CERT)


def test_expired(rid):
    with pytest.raises(sp.Rejected, match="expired"):
        sp.validate_response(response([signed_assertion(request_id=rid)], rid), IDP_CERT, now=time.time() + 3600)


def test_unsolicited_response(rid):
    with pytest.raises(sp.Rejected, match="InResponseTo"):
        sp.validate_response(response([signed_assertion(request_id="_never_sent")], "_never_sent"), IDP_CERT)


def test_replay(rid):
    saml_response = response([signed_assertion(request_id=rid)], rid)
    sp.validate_response(saml_response, IDP_CERT)
    sp.REQUESTS[rid] = time.time()  # even if the request id were still pending, the assertion id is spent
    with pytest.raises(sp.Rejected, match="replayed"):
        sp.validate_response(saml_response, IDP_CERT)


def test_not_xml(rid):
    with pytest.raises(sp.Rejected):
        sp.validate_response(base64.b64encode(b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>").decode(), IDP_CERT)
