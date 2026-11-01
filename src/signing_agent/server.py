"""The local HTTP API.

    GET  /health        no API key; says the agent runs
    GET  /certificates  the certificates on every configured token
    POST /sign          {"certificate": "<id>", "algorithm": "rsa-sha256", "data": "<base64>"}

Every request other than /health and CORS preflight needs `Authorization: Bearer <api key>`.
A request from a browser must come from an allowed origin. The Host header must name this
agent, so a hostile web page cannot reach it through DNS rebinding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from signing_agent import __version__
from signing_agent.audit import AuditLog
from signing_agent.config import Config
from signing_agent.tokens import Token, TokenError

log = logging.getLogger("signing_agent")


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: Config, tokens: dict[str, Token], audit: AuditLog) -> None:
        super().__init__((config.host, config.port), Handler)
        self.config = config
        self.tokens = tokens
        self.audit = audit
        port = self.server_address[1]
        names = ("127.0.0.1", "localhost", "[::1]", config.host, *config.allowed_hosts)
        self.allowed_hosts = {(n if n.startswith("[") or ":" not in n else f"[{n}]").lower() + f":{port}" for n in names}
        if config.tls_cert is not None and config.tls_key is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(config.tls_cert, config.tls_key)
            self.socket = context.wrap_socket(self.socket, server_side=True)


class RequestError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class Handler(BaseHTTPRequestHandler):
    server: AgentServer
    server_version = "signing-agent"
    sys_version = ""

    def do_OPTIONS(self) -> None:  # noqa: N802 - the name http.server expects
        self._handle(preflight=True)

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def _handle(self, preflight: bool = False) -> None:
        self._origin_allowed: str | None = None
        self._signing: dict[str, object] = {}
        try:
            self._check_host()
            self._check_origin()
            if preflight:
                self._send(204, None)
                return
            route = (self.command, self.path)
            if route == ("GET", "/health"):
                self._send(200, {"status": "ok", "version": __version__})
                return
            if self.path not in ("/certificates", "/sign"):
                raise RequestError(404, "not_found", f"No endpoint {self.path}.")
            self._check_api_key()
            if route == ("GET", "/certificates"):
                self._send(200, self._certificates())
            elif route == ("POST", "/sign"):
                self._send(200, self._sign())
            else:
                raise RequestError(405, "method_not_allowed", f"{self.command} is not allowed on {self.path}.")
        except RequestError as e:
            if self.path == "/sign":
                self._audit(result="refused", error=e.code)
            self._send(e.status, {"error": {"code": e.code, "message": str(e)}})
        except Exception:  # noqa: BLE001 - never leak a stack trace to the client
            log.exception("Unexpected error on %s %s", self.command, self.path)
            self._send(500, {"error": {"code": "internal_error", "message": "The agent failed. See its log."}})

    def _check_host(self) -> None:
        host = (self.headers.get("Host") or "").lower()
        if host not in self.server.allowed_hosts:
            raise RequestError(403, "host_not_allowed", "This Host is not allowed. Add it to server.allowed_hosts.")

    def _check_origin(self) -> None:
        origin = self.headers.get("Origin")
        if origin is None:
            return  # not a browser: the API key decides
        if origin not in self.server.config.allowed_origins:
            raise RequestError(403, "origin_not_allowed", "This origin is not allowed. Add it to server.allowed_origins.")
        self._origin_allowed = origin

    def _check_api_key(self) -> None:
        header = self.headers.get("Authorization") or ""
        scheme, _, given = header.partition(" ")
        expected = self.server.config.api_key
        if scheme.lower() != "bearer" or not hmac.compare_digest(given.strip().encode(), expected.encode()):
            raise RequestError(401, "unauthorized", "Send the API key as: Authorization: Bearer <key>.")

    def _certificates(self) -> dict[str, object]:
        certificates, errors = [], []
        for token in self.server.tokens.values():
            try:
                certificates += [c.to_json() for c in token.certificates()]
            except TokenError as e:
                errors.append({"token": token.name, "code": e.code, "message": str(e)})
        return {"certificates": certificates, "errors": errors}

    def _sign(self) -> dict[str, object]:
        request = self._json_body()
        certificate = request.get("certificate")
        algorithm = request.get("algorithm")
        data_b64 = request.get("data")
        if not isinstance(certificate, str) or not isinstance(algorithm, str) or not isinstance(data_b64, str):
            raise RequestError(400, "bad_request", 'Send {"certificate": "<id>", "algorithm": "rsa-sha256", "data": "<base64>"}.')
        token_name, _, key_hex = certificate.partition(":")
        token = self.server.tokens.get(token_name)
        try:
            key_id = bytes.fromhex(key_hex)
            data = base64.b64decode(data_b64, validate=True)
        except (ValueError, binascii.Error):
            raise RequestError(400, "bad_request", "certificate must be an ID from /certificates and data must be base64.") from None
        if token is None or not key_id:
            raise RequestError(404, "certificate_not_found", f"No certificate {certificate}. List them with GET /certificates.")
        self._signing = {"certificate": certificate, "algorithm": algorithm, "data_sha256": hashlib.sha256(data).hexdigest(), "data_length": len(data)}

        try:
            signature, cert = token.sign(key_id, algorithm, data)
        except TokenError as e:
            raise RequestError(e.status, e.code, str(e)) from None
        self._audit(result="signed", subject=cert.subject, serial_number=cert.serial_number)
        return {"signature": base64.b64encode(signature).decode(), "certificate": cert.id, "algorithm": algorithm}

    def _json_body(self) -> dict[str, object]:
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            raise RequestError(411, "length_required", "Send Content-Length; chunked bodies are not accepted.")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            raise RequestError(415, "unsupported_media_type", "Send Content-Type: application/json.")
        try:
            length = int(self.headers.get("Content-Length") or "")
        except ValueError:
            raise RequestError(411, "length_required", "Send Content-Length.") from None
        if length < 0 or length > self.server.config.max_body:
            raise RequestError(413, "too_large", f"The body is larger than {self.server.config.max_body} bytes.")
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise RequestError(400, "bad_request", "The body is not valid JSON.") from None
        if not isinstance(body, dict):
            raise RequestError(400, "bad_request", "The body must be a JSON object.")
        return body

    def _audit(self, **fields: object) -> None:
        self.server.audit.record(
            client=self.client_address[0],
            origin=self.headers.get("Origin"),
            **self._signing,
            **fields,
        )

    def _send(self, status: int, body: dict[str, object] | None) -> None:
        payload = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        if self._origin_allowed is not None:
            self.send_header("Access-Control-Allow-Origin", self._origin_allowed)
            self.send_header("Access-Control-Allow-Methods", "GET, POST")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server's signature
        log.info("%s %s", self.client_address[0], format % args)
