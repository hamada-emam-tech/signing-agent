"""The `signing-agent` command.

    signing-agent new-api-key                  print a new random API key
    signing-agent certificates -c agent.toml   list the certificates on the configured tokens
    signing-agent serve -c agent.toml          run the agent
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import secrets
import sys

from signing_agent import __version__
from signing_agent.audit import AuditLog
from signing_agent.config import Config, ConfigError, load
from signing_agent.server import AgentServer
from signing_agent.tokens import Token, TokenError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="signing-agent", description="Sign bytes with a PKCS#11 USB token or HSM.")
    parser.add_argument("--version", action="version", version=f"signing-agent {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("new-api-key", help="print a new random API key")
    for name, help_text in (("certificates", "list the certificates on the tokens"), ("serve", "run the agent")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("-c", "--config", default="agent.toml", help="the config file (default: agent.toml)")
    args = parser.parse_args(argv)

    if args.command == "new-api-key":
        print(secrets.token_urlsafe(32))
        return 0

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load(args.config, prompt=getpass.getpass if sys.stdin.isatty() else None)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    tokens = {t.name: Token(t) for t in config.tokens}

    if args.command == "certificates":
        return _print_certificates(tokens)
    return _serve(config, tokens)


def _print_certificates(tokens: dict[str, Token]) -> int:
    failed = False
    for token in tokens.values():
        try:
            for cert in token.certificates():
                info = cert.to_json()
                del info["pem"]
                print(json.dumps(info, indent=2))
        except TokenError as e:
            print(f"{token.name}: {e}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


def _serve(config: Config, tokens: dict[str, Token]) -> int:
    audit = AuditLog(config.audit_log)
    server = AgentServer(config, tokens, audit)
    scheme = "https" if config.tls_cert is not None else "http"
    logging.getLogger("signing_agent").info(
        "signing-agent %s on %s://%s:%d, tokens: %s, audit log: %s",
        __version__, scheme, config.host, server.server_address[1], ", ".join(tokens), config.audit_log,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        audit.close()
    return 0
