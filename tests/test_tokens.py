from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from conftest import PIN, SoftHsm
from signing_agent.config import TokenConfig
from signing_agent.tokens import Token, TokenError

DATA = b"the DER of the signed attributes, or any bytes"


def token(softhsm: SoftHsm, label: str = "agent", pin: str = PIN) -> Token:
    return Token(TokenConfig(name=label, library=softhsm.library, label=label, serial=None, pin=pin))


def test_lists_the_certificates_and_which_ones_can_sign(softhsm: SoftHsm) -> None:
    found = {c.id: c for c in token(softhsm).certificates()}

    assert sorted(found) == ["agent:01", "agent:02", "agent:03", "agent:04"]
    assert found["agent:01"].key_type == "rsa" and found["agent:01"].has_private_key
    assert found["agent:02"].key_type == "ec"
    assert not found["agent:03"].has_private_key
    assert found["agent:01"].subject == "C=EG,CN=Agent RSA"
    assert found["agent:01"].to_json()["algorithms"] == ["rsa-sha256"]
    assert found["agent:03"].to_json()["algorithms"] == []
    assert found["agent:01"].pem.startswith("-----BEGIN CERTIFICATE-----")


def test_rsa_signature_is_pkcs1_v15_over_sha256(softhsm: SoftHsm) -> None:
    signature, cert = token(softhsm).sign(bytes.fromhex("01"), "rsa-sha256", DATA)

    softhsm.certificates["agent:01"].public_key().verify(signature, DATA, padding.PKCS1v15(), hashes.SHA256())
    assert cert.id == "agent:01" and len(signature) == 256


def test_ecdsa_signature_is_der_over_sha256(softhsm: SoftHsm) -> None:
    signature, _ = token(softhsm).sign(bytes.fromhex("02"), "ecdsa-sha256", DATA)

    softhsm.certificates["agent:02"].public_key().verify(signature, DATA, ec.ECDSA(hashes.SHA256()))
    decode_dss_signature(signature)  # DER SEQUENCE { r, s }, as OpenSSL and the PHP KeySource expect


def test_the_algorithm_must_match_the_key(softhsm: SoftHsm) -> None:
    with pytest.raises(TokenError) as e:
        token(softhsm).sign(bytes.fromhex("02"), "rsa-sha256", DATA)
    assert e.value.code == "wrong_algorithm" and e.value.status == 400


def test_unknown_algorithm(softhsm: SoftHsm) -> None:
    with pytest.raises(TokenError) as e:
        token(softhsm).sign(bytes.fromhex("01"), "rsa-sha1", DATA)
    assert e.value.code == "unknown_algorithm"


@pytest.mark.parametrize("key_id", ["03", "99"])
def test_a_certificate_without_a_key_or_missing_cannot_sign(softhsm: SoftHsm, key_id: str) -> None:
    with pytest.raises(TokenError) as e:
        token(softhsm).sign(bytes.fromhex(key_id), "rsa-sha256", DATA)
    assert e.value.code == "certificate_not_found" and e.value.status == 404


def test_a_key_that_does_not_match_its_certificate_is_caught(softhsm: SoftHsm) -> None:
    with pytest.raises(TokenError) as e:
        token(softhsm).sign(bytes.fromhex("04"), "rsa-sha256", DATA)
    assert e.value.code == "key_certificate_mismatch"


def test_a_wrong_pin_disables_the_token_so_it_is_not_tried_again(softhsm: SoftHsm) -> None:
    spare = token(softhsm, "spare", pin="0000")
    with pytest.raises(TokenError) as e:
        spare.certificates()
    assert e.value.code == "pin_incorrect" and "0000" not in str(e.value)

    calls = []
    spare._load_library = lambda path: calls.append(path)  # type: ignore[assignment]
    with pytest.raises(TokenError) as e:
        spare.sign(bytes.fromhex("01"), "rsa-sha256", DATA)
    assert e.value.code == "pin_incorrect" and calls == []


def test_a_missing_token_is_reported(softhsm: SoftHsm) -> None:
    with pytest.raises(TokenError) as e:
        token(softhsm, "not-plugged-in").certificates()
    assert e.value.code == "token_not_present" and e.value.status == 503
