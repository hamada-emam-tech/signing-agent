"""Simulated USB tokens: SoftHSM behind a wrapper that acts like a vendor's PKCS#11 driver.

Real tokens differ from SoftHSM. Some only offer raw CKM_RSA_PKCS, people pull them out and
plug them back, PINs get locked by the token's own tool, and the library path is often wrong.
These tests drive the agent through each of those cases.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pkcs11 import Mechanism
from pkcs11 import exceptions as p11
from pkcs11.types import SignMixin

from conftest import PIN, SoftHsm
from signing_agent.config import TokenConfig
from signing_agent.tokens import Token, TokenError

DATA = b"signed attributes of an ETA document"


class VendorLibrary:
    """Loads SoftHSM, then changes what the token says and does, like a vendor driver would."""

    def __init__(self, path: str, mechanisms: set[Mechanism] | None = None) -> None:
        self.real = pkcs11.lib(path)
        self.mechanisms = mechanisms  # None: what SoftHSM offers
        self.fail_open: list[Exception] = []  # raised by the next open() calls, one each
        self.fail_sign: list[Exception] = []
        self.opens = 0
        self.reinitialized = 0
        self.used: list[Mechanism] = []

    def __call__(self, path: str) -> VendorLibrary:
        return self

    def reinitialize(self) -> None:
        self.reinitialized += 1

    def get_token(self, **query: Any) -> VendorToken:
        return VendorToken(self, self.real.get_token(**query))


class VendorToken:
    def __init__(self, library: VendorLibrary, real: pkcs11.Token) -> None:
        self.library = library
        self.real = real

    def open(self, **kwargs: Any) -> Any:
        self.library.opens += 1
        if self.library.fail_open:
            raise self.library.fail_open.pop(0)
        return VendorSession(self.library, self.real.open(**kwargs))


class VendorSession:
    def __init__(self, library: VendorLibrary, real: pkcs11.Session) -> None:
        self.library = library
        self.real = real

    def __enter__(self) -> VendorSession:
        self.real.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self.real.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)

    @property
    def token(self) -> Any:
        library = self.library
        slot = self.real.token.slot

        class Slot:
            def get_mechanisms(self) -> set[Mechanism]:
                offered = set(slot.get_mechanisms())
                return offered if library.mechanisms is None else offered & library.mechanisms

        class TokenView:
            pass

        view = TokenView()
        view.slot = Slot()  # type: ignore[attr-defined]
        return view

    def get_key(self, **kwargs: Any) -> VendorKey:
        return VendorKey(self.library, self.real.get_key(**kwargs))


class VendorKey(SignMixin):
    def __init__(self, library: VendorLibrary, real: Any) -> None:
        self.library = library
        self.real = real
        self.key_type = real.key_type

    def sign(self, data: Any, **kwargs: Any) -> bytes:
        mechanism = kwargs["mechanism"]
        if self.library.mechanisms is not None and mechanism not in self.library.mechanisms:
            raise p11.MechanismInvalid()
        if self.library.fail_sign:
            raise self.library.fail_sign.pop(0)
        self.library.used.append(mechanism)
        signed: bytes = self.real.sign(data, **kwargs)
        return signed


def vendor_token(library: VendorLibrary, softhsm: SoftHsm, label: str = "agent") -> Token:
    return Token(TokenConfig(name=label, library=softhsm.library, label=label, serial=None, pin=PIN), load_library=library)


def verify_rsa(softhsm: SoftHsm, signature: bytes, certificate: str = "agent:01") -> None:
    softhsm.certificates[certificate].public_key().verify(signature, DATA, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[call-arg, union-attr]


def test_a_token_that_only_offers_raw_rsa_signs_through_digest_info(softhsm: SoftHsm) -> None:
    library = VendorLibrary(softhsm.library, mechanisms={Mechanism.RSA_PKCS, Mechanism.ECDSA})

    signature, _ = vendor_token(library, softhsm).sign(b"\x01", "rsa-sha256", DATA)

    assert library.used == [Mechanism.RSA_PKCS]
    verify_rsa(softhsm, signature)


def test_a_token_with_sha256_rsa_pkcs_uses_it(softhsm: SoftHsm) -> None:
    library = VendorLibrary(softhsm.library)

    signature, _ = vendor_token(library, softhsm).sign(b"\x01", "rsa-sha256", DATA)

    assert library.used == [Mechanism.SHA256_RSA_PKCS]
    verify_rsa(softhsm, signature)


def test_ecdsa_uses_plain_ecdsa_even_when_the_token_has_no_ecdsa_sha256(softhsm: SoftHsm) -> None:
    library = VendorLibrary(softhsm.library, mechanisms={Mechanism.RSA_PKCS, Mechanism.ECDSA})

    vendor_token(library, softhsm).sign(b"\x02", "ecdsa-sha256", DATA)

    assert library.used == [Mechanism.ECDSA]


def test_a_token_pulled_out_is_reported_and_found_again_when_plugged_back(softhsm: SoftHsm) -> None:
    library = VendorLibrary(softhsm.library)
    library.fail_open.append(p11.TokenNotPresent())
    agent = vendor_token(library, softhsm)

    with pytest.raises(TokenError) as error:
        agent.sign(b"\x01", "rsa-sha256", DATA)
    assert (error.value.code, error.value.status) == ("token_not_present", 503)
    assert library.reinitialized == 1

    signature, _ = agent.sign(b"\x01", "rsa-sha256", DATA)
    verify_rsa(softhsm, signature)


def test_a_token_pulled_out_while_signing_is_reported(softhsm: SoftHsm) -> None:
    library = VendorLibrary(softhsm.library)
    library.fail_sign.append(p11.DeviceRemoved())
    agent = vendor_token(library, softhsm)

    with pytest.raises(TokenError) as error:
        agent.sign(b"\x01", "rsa-sha256", DATA)
    assert error.value.code == "token_not_present"

    assert agent.sign(b"\x01", "rsa-sha256", DATA)[0]


@pytest.mark.parametrize(("failure", "code"), [(p11.PinLocked(), "pin_locked"), (p11.PinExpired(), "pin_expired")])
def test_a_locked_or_expired_pin_disables_the_token_without_more_tries(softhsm: SoftHsm, failure: Exception, code: str) -> None:
    library = VendorLibrary(softhsm.library)
    library.fail_open.append(failure)
    agent = vendor_token(library, softhsm)

    for _ in range(3):
        with pytest.raises(TokenError) as error:
            agent.certificates()
        assert (error.value.code, error.value.status) == (code, 503)

    assert library.opens == 1


def test_another_token_failure_is_named_without_details(softhsm: SoftHsm) -> None:
    library = VendorLibrary(softhsm.library)
    library.fail_sign.append(p11.FunctionFailed())

    with pytest.raises(TokenError) as error:
        vendor_token(library, softhsm).sign(b"\x01", "rsa-sha256", DATA)

    assert (error.value.code, error.value.status, str(error.value)) == ("token_error", 502, 'Token "agent" failed: FunctionFailed.')


def test_a_wrong_library_path_is_named(tmp_path: Any) -> None:
    missing = str(tmp_path / "vendor-pkcs11.so")

    with pytest.raises(TokenError) as error:
        Token(TokenConfig(name="main", library=missing, label=None, serial=None, pin=PIN)).certificates()

    assert (error.value.code, error.value.status) == ("library_not_found", 503)
    assert missing in str(error.value)
