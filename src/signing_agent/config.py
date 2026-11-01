"""Reads the agent's TOML config file.

Secrets (the API key and each token PIN) never sit in the config file itself. They come from
an environment variable, a file only the agent's user can read, or a prompt at start-up.
Nothing in a request can change the config.
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORT = 8765
MIN_API_KEY_LENGTH = 32
DEFAULT_MAX_BODY = 1024 * 1024  # 1 MiB: an invoice's signed attributes are a few hundred bytes

_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


class ConfigError(Exception):
    """The config is missing, unreadable or unsafe. The message says what to fix."""


@dataclass(frozen=True)
class TokenConfig:
    name: str
    library: str
    label: str | None
    serial: str | None
    pin: str = field(repr=False)


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    api_key: str = field(repr=False)
    allowed_origins: tuple[str, ...]
    allowed_hosts: tuple[str, ...]  # extra names for the Host header; loopback names are always allowed
    tokens: tuple[TokenConfig, ...]
    audit_log: Path
    tls_cert: Path | None = None
    tls_key: Path | None = None
    max_body: int = DEFAULT_MAX_BODY


def load(
    path: str | Path,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> Config:
    """Reads and checks the config. `prompt` asks for a secret that has no env var or file."""
    path = Path(path)
    env = os.environ if env is None else env
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"No config file at {path}.") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path} is not valid TOML: {e}") from None
    base = path.parent

    server = _table(data, "server")
    host = str(server.get("host", "127.0.0.1"))
    port = server.get("port", DEFAULT_PORT)
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ConfigError("server.port must be a number from 0 to 65535.")

    tls_cert = _path(server.get("tls_cert"), base)
    tls_key = _path(server.get("tls_key"), base)
    if (tls_cert is None) != (tls_key is None):
        raise ConfigError("Set both server.tls_cert and server.tls_key, or neither.")
    if not _is_loopback(host) and tls_cert is None:
        raise ConfigError(
            f"server.host {host} is reachable from other machines. "
            "Set server.tls_cert and server.tls_key, or listen on 127.0.0.1."
        )

    api_key = _secret(server, "api_key", "server", base, env, prompt)
    if len(api_key) < MIN_API_KEY_LENGTH:
        raise ConfigError(
            f"The API key must have at least {MIN_API_KEY_LENGTH} characters. "
            "Make one with: signing-agent new-api-key"
        )

    origins = server.get("allowed_origins", [])
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        raise ConfigError("server.allowed_origins must be a list of origins.")
    for origin in origins:
        if not _ORIGIN.match(origin):
            raise ConfigError(
                f'server.allowed_origins: "{origin}" is not an origin. '
                'Write it as "https://erp.example.com" (no "*", no path, no trailing slash).'
            )

    hosts = server.get("allowed_hosts", [])
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        raise ConfigError("server.allowed_hosts must be a list of host names.")

    max_body = server.get("max_body", DEFAULT_MAX_BODY)
    if not isinstance(max_body, int) or max_body <= 0:
        raise ConfigError("server.max_body must be a positive number of bytes.")

    tokens = data.get("token", [])
    if not isinstance(tokens, list) or not tokens:
        raise ConfigError("Add at least one [[token]] section.")
    token_configs = tuple(_token(t, i, base, env, prompt) for i, t in enumerate(tokens))
    names = [t.name for t in token_configs]
    if len(set(names)) != len(names):
        raise ConfigError("Each [[token]] needs its own name.")

    audit = _table(data, "audit")
    audit_log = _path(audit.get("path", "signing-agent-audit.log"), base)
    assert audit_log is not None

    return Config(
        host=host,
        port=port,
        api_key=api_key,
        allowed_origins=tuple(origins),
        allowed_hosts=tuple(hosts),
        tokens=token_configs,
        audit_log=audit_log,
        tls_cert=tls_cert,
        tls_key=tls_key,
        max_body=max_body,
    )


def _token(data: object, index: int, base: Path, env: Mapping[str, str], prompt: Callable[[str], str] | None) -> TokenConfig:
    where = f"[[token]] number {index + 1}"
    if not isinstance(data, dict):
        raise ConfigError(f"{where} must be a table.")
    name = str(data.get("name", ""))
    if not _NAME.match(name):
        raise ConfigError(f"{where}: name must be 1 to 32 letters, digits, - or _.")
    library = data.get("library")
    if not isinstance(library, str) or not library:
        raise ConfigError(f'Token "{name}": set library, the path of the PKCS#11 module (.so, .dylib or .dll).')
    label = data.get("label")
    serial = data.get("serial")

    return TokenConfig(
        name=name,
        library=str(_path(library, base)),
        label=str(label) if label is not None else None,
        serial=str(serial) if serial is not None else None,
        pin=_secret(data, "pin", f'token "{name}"', base, env, prompt),
    )


def _secret(
    table: Mapping[str, object],
    key: str,
    where: str,
    base: Path,
    env: Mapping[str, str],
    prompt: Callable[[str], str] | None,
) -> str:
    """A secret from `<key>_env`, `<key>_file` or the prompt. A literal `<key> = "..."` is refused."""
    if key in table:
        raise ConfigError(
            f'{where}: do not write the {key} in the config file. '
            f"Use {key}_env (an environment variable) or {key}_file (a file only this user can read)."
        )
    if f"{key}_env" in table:
        name = str(table[f"{key}_env"])
        value = env.get(name, "")
        if not value:
            raise ConfigError(f"{where}: the environment variable {name} is not set.")
        return value
    if f"{key}_file" in table:
        path = _path(table[f"{key}_file"], base)
        assert path is not None
        return _read_secret_file(path, where)
    if prompt is not None:
        value = prompt(f"{where} {key.replace('_', ' ')}: ")
        if value:
            return value
    raise ConfigError(f"{where}: set {key}_env or {key}_file.")


def _read_secret_file(path: Path, where: str) -> str:
    try:
        mode = path.stat().st_mode
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        raise ConfigError(f"{where}: cannot read {path}.") from None
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{where}: {path} can be read by other users. Run: chmod 600 {path}")
    if not value:
        raise ConfigError(f"{where}: {path} is empty.")
    return value


def _table(data: Mapping[str, object], name: str) -> Mapping[str, object]:
    table = data.get(name, {})
    if not isinstance(table, dict):
        raise ConfigError(f"[{name}] must be a table.")
    return table


def _path(value: object, base: Path) -> Path | None:
    if value is None:
        return None
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else base / path


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
