from __future__ import annotations

import base64
import hashlib
import http.client
import json
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from conftest import PIN, SoftHsm
from signing_agent.audit import AuditLog
from signing_agent.config import load
from signing_agent.server import AgentServer
from signing_agent.tokens import Token

API_KEY = "test-api-key-0123456789-abcdefghijklmnop"
ORIGIN = "https://erp.example.com"
DATA = b"bytes to sign"


class Agent:
    def __init__(self, port: int, audit_log: Path) -> None:
        self.port = port
        self.audit_log = audit_log

    def request(
        self, method: str, path: str, body: object = None, headers: dict[str, str] | None = None, key: str | None = API_KEY
    ) -> tuple[int, dict, http.client.HTTPResponse]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        sent = {"Content-Type": "application/json"} if body is not None else {}
        if key is not None:
            sent["Authorization"] = f"Bearer {key}"
        sent.update(headers or {})
        payload = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        connection.request(method, path, body=payload, headers=sent)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, (json.loads(raw) if raw else {}), response

    def sign(self, certificate: str, algorithm: str = "rsa-sha256", data: bytes = DATA, **kwargs: object) -> tuple[int, dict, http.client.HTTPResponse]:
        return self.request("POST", "/sign", {"certificate": certificate, "algorithm": algorithm, "data": base64.b64encode(data).decode()}, **kwargs)  # type: ignore[arg-type]

    def audit(self) -> list[dict]:
        return [json.loads(line) for line in self.audit_log.read_text().splitlines()]


@pytest.fixture
def agent(softhsm: SoftHsm, tmp_path: Path) -> Iterator[Agent]:
    pin = tmp_path / "agent.pin"
    pin.write_text(PIN)
    pin.chmod(0o600)
    (tmp_path / "agent.toml").write_text(f"""
[server]
port = 0
api_key_env = "AGENT_KEY"
allowed_origins = ["{ORIGIN}"]

[[token]]
name = "agent"
library = "{softhsm.library}"
label = "agent"
pin_file = "agent.pin"
""")
    config = load(tmp_path / "agent.toml", env={"AGENT_KEY": API_KEY})
    audit = AuditLog(config.audit_log)
    server = AgentServer(config, {t.name: Token(t) for t in config.tokens}, audit)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield Agent(server.server_address[1], config.audit_log)
    server.shutdown()
    server.server_close()
    audit.close()


def test_health_needs_no_key(agent: Agent) -> None:
    status, body, _ = agent.request("GET", "/health", key=None)
    assert status == 200 and body["status"] == "ok"


def test_certificates(agent: Agent) -> None:
    status, body, response = agent.request("GET", "/certificates")

    assert status == 200 and body["errors"] == []
    assert [c["id"] for c in body["certificates"]] == ["agent:01", "agent:02", "agent:03", "agent:04"]
    assert response.getheader("Cache-Control") == "no-store"


def test_sign_rsa(agent: Agent, softhsm: SoftHsm) -> None:
    status, body, _ = agent.sign("agent:01")

    assert status == 200 and body["certificate"] == "agent:01"
    softhsm.certificates["agent:01"].public_key().verify(base64.b64decode(body["signature"]), DATA, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.parametrize("key", [None, "wrong-key", API_KEY + "x"])
def test_every_endpoint_but_health_needs_the_api_key(agent: Agent, key: str | None) -> None:
    for method, path in (("GET", "/certificates"), ("POST", "/sign")):
        status, body, response = agent.request(method, path, {} if method == "POST" else None, key=key)
        assert status == 401 and body["error"]["code"] == "unauthorized"
        assert response.getheader("WWW-Authenticate") == "Bearer"


def test_a_browser_from_an_allowed_origin_gets_cors_headers(agent: Agent) -> None:
    status, _, response = agent.request("OPTIONS", "/sign", key=None, headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
    assert status == 204
    assert response.getheader("Access-Control-Allow-Origin") == ORIGIN
    assert response.getheader("Access-Control-Allow-Headers") == "Authorization, Content-Type"

    status, _, response = agent.sign("agent:01", headers={"Origin": ORIGIN})
    assert status == 200 and response.getheader("Access-Control-Allow-Origin") == ORIGIN


def test_any_other_origin_is_refused_and_never_gets_a_wildcard(agent: Agent) -> None:
    for method in ("OPTIONS", "GET"):
        status, body, response = agent.request(method, "/certificates", key=API_KEY, headers={"Origin": "https://evil.example"})
        assert status == 403 and body["error"]["code"] == "origin_not_allowed"
        assert response.getheader("Access-Control-Allow-Origin") is None


def test_a_foreign_host_header_is_refused(agent: Agent) -> None:
    # A page on evil.example that re-points its DNS name to 127.0.0.1 still sends Host: evil.example.
    status, body, _ = agent.request("GET", "/certificates", headers={"Host": f"evil.example:{agent.port}"})
    assert status == 403 and body["error"]["code"] == "host_not_allowed"
    assert agent.request("GET", "/health", key=None, headers={"Host": f"localhost:{agent.port}"})[0] == 200


@pytest.mark.parametrize(
    ("certificate", "algorithm", "status", "code"),
    [
        ("agent:02", "rsa-sha256", 400, "wrong_algorithm"),
        ("agent:01", "md5", 400, "unknown_algorithm"),
        ("agent:03", "rsa-sha256", 404, "certificate_not_found"),
        ("other:01", "rsa-sha256", 404, "certificate_not_found"),
        ("agent:zz", "rsa-sha256", 400, "bad_request"),
        ("agent:04", "rsa-sha256", 500, "key_certificate_mismatch"),
    ],
)
def test_sign_errors(agent: Agent, certificate: str, algorithm: str, status: int, code: str) -> None:
    got, body, _ = agent.sign(certificate, algorithm)
    assert (got, body["error"]["code"]) == (status, code)


def test_bad_bodies(agent: Agent) -> None:
    assert agent.request("POST", "/sign", b"not json")[1]["error"]["code"] == "bad_request"
    assert agent.request("POST", "/sign", {"certificate": "agent:01", "algorithm": "rsa-sha256", "data": "%%%"})[1]["error"]["code"] == "bad_request"
    assert agent.request("POST", "/sign", b"{}", headers={"Content-Type": "text/plain"})[0] == 415
    assert agent.request("POST", "/sign", b"{}", headers={"Content-Length": str(1024 * 1024 + 1)})[0] == 413


def test_unknown_paths_and_methods(agent: Agent) -> None:
    assert agent.request("GET", "/keys")[0] == 404
    assert agent.request("GET", "/sign")[0] == 405


def test_many_requests_at_once_take_turns_on_the_token(agent: Agent, softhsm: SoftHsm) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: agent.sign("agent:01", data=f"invoice {i}".encode()), range(24)))

    public_key = softhsm.certificates["agent:01"].public_key()
    for i, (status, body, _) in enumerate(results):
        assert status == 200
        public_key.verify(base64.b64decode(body["signature"]), f"invoice {i}".encode(), padding.PKCS1v15(), hashes.SHA256())


def test_the_audit_log_records_each_signing_without_secrets_or_data(agent: Agent) -> None:
    agent.sign("agent:01", headers={"Origin": ORIGIN})
    agent.sign("agent:02", "rsa-sha256")
    agent.sign("agent:01", key="wrong-key")

    signed, refused, unauthorized = agent.audit()
    assert signed["result"] == "signed" and signed["certificate"] == "agent:01" and signed["origin"] == ORIGIN
    assert signed["data_sha256"] == hashlib.sha256(DATA).hexdigest() and signed["data_length"] == len(DATA)
    assert signed["subject"] == "C=EG,CN=Agent RSA"
    assert (refused["result"], refused["error"]) == ("refused", "wrong_algorithm")
    assert (unauthorized["result"], unauthorized["error"]) == ("refused", "unauthorized")

    fields = {"time", "client", "origin", "certificate", "algorithm", "data_sha256", "data_length", "result", "error", "subject", "serial_number"}
    assert all(set(entry) <= fields for entry in agent.audit())
    log = agent.audit_log.read_text()
    assert API_KEY not in log and base64.b64encode(DATA).decode() not in log
    assert oct(agent.audit_log.stat().st_mode & 0o777) == "0o600"
