"""Test tokens on SoftHSM, a PKCS#11 module that keeps its tokens in files.

Token "agent" (PIN 1234):
    01  RSA 2048 key + certificate
    02  EC P-256 key + certificate
    03  certificate only, no private key
    04  RSA key + a certificate of another key (a broken token)
Token "spare" (PIN 1234): one RSA key + certificate, for the wrong-PIN test.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pkcs11
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from pkcs11 import Attribute
from pkcs11.util.ec import decode_ec_private_key
from pkcs11.util.rsa import decode_rsa_private_key
from pkcs11.util.x509 import decode_x509_certificate

PIN = "1234"

_LIBRARIES = (
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
)


@dataclass
class SoftHsm:
    library: str
    certificates: dict[str, x509.Certificate]  # "<token>:<hex id>" -> certificate


@pytest.fixture(scope="session")
def softhsm(tmp_path_factory: pytest.TempPathFactory) -> SoftHsm:
    library = os.environ.get("SOFTHSM2_LIB") or next((p for p in _LIBRARIES if Path(p).exists()), None)
    util = shutil.which("softhsm2-util")
    if library is None or util is None:
        pytest.skip("SoftHSM is not installed (brew install softhsm, or apt install softhsm2).")

    root = tmp_path_factory.mktemp("softhsm")
    (root / "tokens").mkdir()
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {root / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)  # read by SoftHSM when the library loads
    for label in ("agent", "spare"):
        subprocess.run([util, "--init-token", "--free", "--label", label, "--pin", PIN, "--so-pin", "5678"], check=True, capture_output=True)

    lib = pkcs11.lib(library)
    certificates = {}
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    with lib.get_token(token_label="agent").open(rw=True, user_pin=PIN) as session:
        certificates["agent:01"] = _put(session, b"\x01", rsa_key, _certificate(rsa_key, "Agent RSA"))
        certificates["agent:02"] = _put(session, b"\x02", ec_key, _certificate(ec_key, "Agent EC"))
        certificates["agent:03"] = _put(session, b"\x03", None, _certificate(rsa_key, "Certificate only"))
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificates["agent:04"] = _put(session, b"\x04", other, _certificate(rsa_key, "Wrong pair"))
    spare_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with lib.get_token(token_label="spare").open(rw=True, user_pin=PIN) as session:
        certificates["spare:01"] = _put(session, b"\x01", spare_key, _certificate(spare_key, "Spare"))

    return SoftHsm(library, certificates)


def _certificate(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, name: str) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name), x509.NameAttribute(NameOID.COUNTRY_NAME, "EG")])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def _put(session: pkcs11.Session, key_id: bytes, key: object, cert: x509.Certificate) -> x509.Certificate:
    common = {Attribute.ID: key_id, Attribute.TOKEN: True, Attribute.LABEL: cert.subject.rfc4514_string()}
    if isinstance(key, rsa.RSAPrivateKey):
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        attributes = decode_rsa_private_key(der)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        attributes = decode_ec_private_key(der)
    else:
        attributes = None
    if attributes is not None:
        attributes.update({**common, Attribute.SIGN: True, Attribute.PRIVATE: True, Attribute.SENSITIVE: True})
        session.create_object(attributes)
    session.create_object({**decode_x509_certificate(cert.public_bytes(serialization.Encoding.DER)), **common})
    return cert
