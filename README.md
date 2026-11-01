# signing-agent

A small local service that signs bytes with a **PKCS#11 USB token or HSM**.
Your application sends bytes over HTTP; the agent signs them on the token and returns the signature. The private key never leaves the token.

It was built for e-invoicing systems that must sign with a hardware token, such as Egypt's ETA, but it signs bytes for any client in any language.

```
your app (PHP, Node, ...)  ──HTTP──▶  signing-agent  ──PKCS#11──▶  USB token / HSM
```

> **Version 0.1.** Tested on SoftHSM 2.7 (a software PKCS#11 token) in CI and end to end with [einvoice-eta](https://github.com/hamada-emam-tech/einvoice-eta). The tests also simulate vendor tokens: a token with only raw `CKM_RSA_PKCS`, a token pulled out and plugged back, a locked or expired PIN, a wrong library path. Not yet tested on a physical USB token: if you run it on one, please report the token model and the result.

## What it does, and what it does not

- It lists the certificates on the token, and signs SHA-256 of the bytes you send: RSA PKCS#1 v1.5 or ECDSA (DER).
- It does not build CAdES, XAdES or PDF signatures, and never reads invoices. Your client library builds the signed structure and asks the agent only for the raw signature. For ETA, [einvoice-eta](https://github.com/hamada-emam-tech/einvoice-eta) builds the CAdES-BES.

## Security

| Rule | How |
|---|---|
| Not reachable from the network by default | Listens on `127.0.0.1`. Any other address requires TLS. |
| Every call is authorised | `Authorization: Bearer <api key>`, at least 32 characters, compared in constant time. |
| Browsers only from your app | Exact origin allowlist. Never `Access-Control-Allow-Origin: *`. |
| No DNS rebinding | The `Host` header must name the agent. |
| Secrets stay local | The PKCS#11 library, the PIN and the API key come from the local config, environment variables or a `chmod 600` file. A request cannot set them, and the config file refuses a literal PIN. |
| The token is not locked by accident | A wrong PIN disables the token in the agent until restart, so it never uses up the token's tries. |
| One operation at a time per token | Each request opens its own session under a lock. |
| A broken token is caught | Each signature is verified against the certificate before it is returned. |
| Audit log | One JSON line per signing request: time, client, origin, certificate, algorithm, SHA-256 and length of the data, result. Never the PIN, the API key or the data. The file is created `0600`. |

## Install

Python 3.11 or newer, and your token's PKCS#11 library (from the token vendor).

```bash
pip install git+https://github.com/hamada-emam-tech/signing-agent
```

## Configure

```bash
cp config.example.toml agent.toml
signing-agent new-api-key            # put it in SIGNING_AGENT_API_KEY
```

```toml
[server]
host = "127.0.0.1"
port = 8765
api_key_env = "SIGNING_AGENT_API_KEY"
allowed_origins = []                 # browser apps only, e.g. ["https://erp.example.com"]

[audit]
path = "signing-agent-audit.log"

[[token]]
name = "main"
library = "/usr/lib/softhsm/libsofthsm2.so"   # Windows: the vendor's .dll
label = "my token"                             # or serial = "..."
pin_env = "SIGNING_AGENT_PIN"                  # or pin_file; or leave both out to be asked at start
```

Several `[[token]]` sections are allowed. Certificate IDs are `<token name>:<key ID in hex>`.

## Run

```bash
signing-agent certificates -c agent.toml    # check the token and find the certificate ID
signing-agent serve -c agent.toml
```

## API

`GET /health` (no API key)

```json
{"status": "ok", "version": "0.1.0"}
```

`GET /certificates`

```json
{
  "certificates": [{
    "id": "main:01", "token": "main", "label": "...",
    "subject": "C=EG,CN=...", "issuer": "...", "serial_number": "...",
    "not_before": "...", "not_after": "...",
    "key_type": "rsa", "can_sign": true, "algorithms": ["rsa-sha256"],
    "pem": "-----BEGIN CERTIFICATE-----..."
  }],
  "errors": []
}
```

`POST /sign` with `Content-Type: application/json`

```json
{"certificate": "main:01", "algorithm": "rsa-sha256", "data": "<base64 of the bytes>"}
```

```json
{"signature": "<base64>", "certificate": "main:01", "algorithm": "rsa-sha256"}
```

Errors are `{"error": {"code": "...", "message": "..."}}`:

| HTTP | code |
|---|---|
| 400 | `bad_request`, `unknown_algorithm`, `wrong_algorithm`, `key_cannot_sign` |
| 401 | `unauthorized` |
| 403 | `origin_not_allowed`, `host_not_allowed` |
| 404 | `certificate_not_found` |
| 413 | `too_large` (default limit 1 MiB) |
| 500 | `key_certificate_mismatch` |
| 502 | `token_error` (the token failed; the PKCS#11 error name is in the message) |
| 503 | `token_not_present`, `library_not_found`, `pin_incorrect`, `pin_locked`, `pin_expired` |

## With PHP

```bash
composer require hamada-emam-tech/einvoice-eta hamada-emam-tech/einvoice-keysource-agent
```

```php
use HamadaEmamTech\Einvoice\KeySource\Agent\AgentKey;

$key = AgentKey::connect('http://127.0.0.1:8765', getenv('SIGNING_AGENT_API_KEY'), 'main:01');
```

## Develop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
brew install softhsm          # or: apt install softhsm2
.venv/bin/pytest && .venv/bin/ruff check src tests && .venv/bin/mypy src
```

The tests create SoftHSM tokens with RSA and EC keys, plus a certificate with no key and a key with the wrong certificate. `tests/test_vendor_tokens.py` wraps SoftHSM to act like vendor drivers (fewer mechanisms, unplugging, locked PINs).

## License

MIT
