"""One PKCS#11 token (a USB token or an HSM slot): list its certificates and sign bytes with its keys.

Every operation opens its own session and logs in, under a lock, so only one operation runs on a
token at a time and nothing is shared between requests. A wrong PIN disables the token until the
agent restarts: most USB tokens lock themselves after a few wrong PINs, and the agent must never
use up those tries by itself.
"""

from __future__ import annotations

import contextlib
import hashlib
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from dataclasses import dataclass

import pkcs11
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11 import exceptions as p11
from pkcs11.types import SignMixin
from pkcs11.util.ec import encode_ecdsa_signature

from signing_agent.config import TokenConfig

ALGORITHMS = ("rsa-sha256", "ecdsa-sha256")

# DER prefix of DigestInfo(sha256), for tokens that only do raw CKM_RSA_PKCS (RFC 8017, section 9.2).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class TokenError(Exception):
    """A refused or failed operation. `code` is stable for clients; the message never holds a PIN."""

    def __init__(self, code: str, message: str, status: int = 500) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Certificate:
    id: str  # "<token name>:<CKA_ID in hex>"
    token: str
    label: str
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    key_type: str  # "rsa" or "ec"
    has_private_key: bool
    pem: str

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.id,
            "token": self.token,
            "label": self.label,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key_type": self.key_type,
            "can_sign": self.has_private_key,
            "algorithms": [a for a in ALGORITHMS if a.startswith(self.key_type)] if self.has_private_key else [],
            "pem": self.pem,
        }


class Token:
    def __init__(self, config: TokenConfig, load_library: Callable[[str], Any] = pkcs11.lib) -> None:
        self.name = config.name
        self._config = config
        self._load_library = load_library
        self._lock = threading.Lock()
        self._disabled: TokenError | None = None

    def certificates(self) -> list[Certificate]:
        with self._session() as session:
            private_ids = {key[Attribute.ID] for key in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY})}
            found = []
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                key_id = bytes(obj[Attribute.ID])
                cert = x509.load_der_x509_certificate(bytes(obj[Attribute.VALUE]))
                found.append(self._describe(key_id, str(obj[Attribute.LABEL]), cert, key_id in private_ids))
        return sorted(found, key=lambda c: c.id)  # PKCS#11 gives no order; keep the output stable

    def sign(self, key_id: bytes, algorithm: str, data: bytes) -> tuple[bytes, Certificate]:
        """Signs SHA-256 of `data`. RSA gives PKCS#1 v1.5; ECDSA gives DER, as OpenSSL does."""
        if algorithm not in ALGORITHMS:
            raise TokenError("unknown_algorithm", f"Algorithm must be one of: {', '.join(ALGORITHMS)}.", 400)

        with self._session() as session:
            cert_obj = self._one(session, ObjectClass.CERTIFICATE, key_id, "certificate")
            key = self._private_key(session, key_id)
            cert = x509.load_der_x509_certificate(bytes(cert_obj[Attribute.VALUE]))
            described = self._describe(key_id, str(cert_obj[Attribute.LABEL]), cert, True)

            if algorithm == "rsa-sha256":
                if key.key_type != KeyType.RSA:
                    raise TokenError("wrong_algorithm", f"Certificate {described.id} has an {described.key_type.upper()} key: use ecdsa-sha256.", 400)
                if Mechanism.SHA256_RSA_PKCS in self._mechanisms(session):
                    signature = key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
                else:
                    signature = key.sign(_SHA256_DIGEST_INFO + hashlib.sha256(data).digest(), mechanism=Mechanism.RSA_PKCS)
            else:
                if key.key_type != KeyType.EC:
                    raise TokenError("wrong_algorithm", f"Certificate {described.id} has an RSA key: use rsa-sha256.", 400)
                # Hash here and use plain CKM_ECDSA: every EC token supports it, not all support ECDSA_SHA256.
                signature = encode_ecdsa_signature(key.sign(hashlib.sha256(data).digest(), mechanism=Mechanism.ECDSA))

        # A key and a certificate that share an ID but do not belong together would make
        # signatures nobody can verify. Check before anything leaves the agent.
        _verify(cert, bytes(signature), data)
        return bytes(signature), described

    @contextmanager
    def _session(self) -> Iterator[pkcs11.Session]:
        with self._lock:
            if self._disabled is not None:
                raise TokenError(self._disabled.code, str(self._disabled), self._disabled.status)
            try:
                with self._find().open(user_pin=self._config.pin) as session:
                    yield session
            except (p11.PinIncorrect, p11.PinInvalid, p11.PinLenRange):
                self._disabled = TokenError(
                    "pin_incorrect",
                    f'Token "{self.name}" refused the PIN. It is disabled until the agent restarts, '
                    "so the agent cannot lock the token with more tries. Fix the PIN, then restart.",
                    503,
                )
                raise self._disabled from None
            except (p11.PinLocked, p11.PinExpired) as e:
                state = "locked" if isinstance(e, p11.PinLocked) else "expired"
                message = f'Token "{self.name}": the PIN is {state}. Unlock or change it with the token\'s own tool, then restart.'
                self._disabled = TokenError("pin_" + state, message, 503)
                raise self._disabled from None
            except (p11.TokenNotPresent, p11.DeviceRemoved, p11.SessionClosed, p11.SessionHandleInvalid):
                self._reinitialize()
                raise TokenError("token_not_present", f'Token "{self.name}" is not connected. Plug it in and try again.', 503) from None
            except p11.PKCS11Error as e:
                raise TokenError("token_error", f'Token "{self.name}" failed: {type(e).__name__}.', 502) from None

    def _find(self) -> pkcs11.Token:
        try:
            library = self._load_library(self._config.library)
        except p11.PKCS11Error:  # python-pkcs11 raises it when the file cannot be loaded
            raise TokenError(
                "library_not_found",
                f'Token "{self.name}": cannot load the PKCS#11 library {self._config.library}. Use the path from the token vendor\'s driver.',
                503,
            ) from None
        query: dict[str, str | bytes] = {}
        if self._config.label is not None:
            query["token_label"] = self._config.label
        if self._config.serial is not None:
            query["token_serial"] = self._config.serial.encode()
        try:
            if query:
                found: pkcs11.Token = library.get_token(**query)
                return found
            tokens = list(library.get_tokens())
        except p11.NoSuchToken:
            self._reinitialize()
            raise TokenError("token_not_present", f'Token "{self.name}" is not connected. Plug it in and try again.', 503) from None
        except p11.MultipleTokensReturned:
            raise TokenError("token_ambiguous", f'Token "{self.name}": more than one token matches. Set its label or serial.', 500) from None
        if len(tokens) != 1:
            raise TokenError(
                "token_ambiguous" if tokens else "token_not_present",
                f'Token "{self.name}": {len(tokens)} tokens found. Set label or serial in the config.' if tokens
                else f'Token "{self.name}" is not connected. Plug it in and try again.',
                503,
            )
        only: pkcs11.Token = tokens[0]
        return only

    def _reinitialize(self) -> None:
        """Re-reads the slots, so a token plugged in again is found on the next request."""
        # Best effort: if it fails, the next request reports the real error.
        with contextlib.suppress(Exception):
            self._load_library(self._config.library).reinitialize()

    def _private_key(self, session: pkcs11.Session, key_id: bytes) -> SignMixin:
        try:
            key = session.get_key(object_class=ObjectClass.PRIVATE_KEY, id=key_id)
        except (p11.NoSuchKey, p11.MultipleObjectsReturned) as e:
            problem = "has no private key" if isinstance(e, p11.NoSuchKey) else "matches more than one private key"
            raise TokenError("certificate_not_found", f"Certificate {self.name}:{key_id.hex()} {problem} on the token.", 404) from None
        if not isinstance(key, SignMixin):
            raise TokenError("key_cannot_sign", f"The key of certificate {self.name}:{key_id.hex()} is not allowed to sign (CKA_SIGN is false).", 400)
        return key

    def _one(self, session: pkcs11.Session, object_class: ObjectClass, key_id: bytes, what: str) -> pkcs11.Object:
        found = list(session.get_objects({Attribute.CLASS: object_class, Attribute.ID: key_id}))
        if len(found) != 1:
            raise TokenError(
                "certificate_not_found",
                f"Certificate {self.name}:{key_id.hex()} " + (f"has no {what} on the token." if not found else f"matches {len(found)} {what} objects."),
                404,
            )
        return found[0]

    @staticmethod
    def _mechanisms(session: pkcs11.Session) -> set[Mechanism]:
        return set(session.token.slot.get_mechanisms())

    def _describe(self, key_id: bytes, label: str, cert: x509.Certificate, has_private_key: bool) -> Certificate:
        public_key = cert.public_key()
        return Certificate(
            id=f"{self.name}:{key_id.hex()}",
            token=self.name,
            label=label,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            key_type="ec" if isinstance(public_key, ec.EllipticCurvePublicKey) else "rsa",
            has_private_key=has_private_key,
            pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        )


def _verify(cert: x509.Certificate, signature: bytes, data: bytes) -> None:
    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise InvalidSignature
    except InvalidSignature:
        raise TokenError(
            "key_certificate_mismatch",
            "The signature does not match the certificate with the same ID. Check the objects on the token.",
            500,
        ) from None
