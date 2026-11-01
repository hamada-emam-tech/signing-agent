from __future__ import annotations

import os
from pathlib import Path

import pytest

from signing_agent.config import ConfigError, load

KEY = "k" * 40


def write(tmp_path: Path, server: str = "", token: str = 'pin_env = "PIN"') -> Path:
    path = tmp_path / "agent.toml"
    path.write_text(f"""
[server]
api_key_env = "KEY"
{server}

[[token]]
name = "main"
library = "/lib/p11.so"
{token}
""")
    return path


ENV = {"KEY": KEY, "PIN": "1234"}


def test_defaults(tmp_path: Path) -> None:
    config = load(write(tmp_path), env=ENV)

    assert (config.host, config.port) == ("127.0.0.1", 8765)
    assert config.tokens[0].pin == "1234" and config.api_key == KEY
    assert config.audit_log == tmp_path / "signing-agent-audit.log"
    assert "1234" not in repr(config) and KEY not in repr(config)


def test_listening_beyond_this_machine_needs_tls(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="tls_cert"):
        load(write(tmp_path, 'host = "0.0.0.0"'), env=ENV)
    config = load(write(tmp_path, 'host = "0.0.0.0"\ntls_cert = "c.pem"\ntls_key = "k.pem"'), env=ENV)
    assert config.tls_cert == tmp_path / "c.pem"


@pytest.mark.parametrize("origin", ["*", "https://erp.example.com/", "erp.example.com", "https://*.example.com"])
def test_origins_must_be_exact(tmp_path: Path, origin: str) -> None:
    with pytest.raises(ConfigError, match="not an origin"):
        load(write(tmp_path, f'allowed_origins = ["{origin}"]'), env=ENV)


def test_secrets_are_never_written_in_the_config(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="do not write the pin"):
        load(write(tmp_path, token='pin = "1234"'), env=ENV)
    with pytest.raises(ConfigError, match="do not write the api_key"):
        load(write(tmp_path, f'api_key = "{KEY}"'), env=ENV)


def test_the_api_key_must_be_long(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="at least 32"):
        load(write(tmp_path), env={**ENV, "KEY": "short"})


def test_a_missing_env_var_is_named(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="PIN is not set"):
        load(write(tmp_path), env={"KEY": KEY})


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_a_pin_file_must_be_private(tmp_path: Path) -> None:
    pin = tmp_path / "token.pin"
    pin.write_text("1234\n")
    pin.chmod(0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        load(write(tmp_path, token='pin_file = "token.pin"'), env=ENV)
    pin.chmod(0o600)
    assert load(write(tmp_path, token='pin_file = "token.pin"'), env=ENV).tokens[0].pin == "1234"


def test_the_pin_can_be_asked_at_start(tmp_path: Path) -> None:
    config = load(write(tmp_path, token=""), env=ENV, prompt=lambda question: "4321")
    assert config.tokens[0].pin == "4321"
