"""
MCP Action Firewall — CLI entry point.

Usage::

    # Wrap any MCP server with the firewall:
    mcp-action-firewall --target "uvx mcp-server-stripe --api-key sk_test_..."

    # With per-server rules:
    mcp-action-firewall --target "uvx mcp-server-stripe" --name stripe

    # Custom config:
    mcp-action-firewall --target "npx mcp-server-aws" --config ./my_config.json

This process acts as a transparent MCP server for the AI agent:
    • The agent connects to THIS process's stdin/stdout.
    • This process spawns the *real* MCP server as a subprocess.
    • All JSON-RPC traffic is proxied, with ``tools/call`` requests
      inspected and potentially blocked by the firewall policy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
from importlib.resources import files as pkg_files

from mcp_action_firewall.policy import PolicyEngine
from mcp_action_firewall.proxy import FirewallProxy
from mcp_action_firewall.state import PendingActionStore

# -----------------------------------------------------------------------
# Logging — goes to stderr so it doesn't pollute the JSON-RPC stdout
# -----------------------------------------------------------------------

LOG_FORMAT = "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s"


def _configure_logging(verbose: bool) -> None:
    """Set up logging to stderr."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.root.addHandler(handler)
    logging.root.setLevel(level)


# -----------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-action-firewall",
        description=(
            "MCP Action Firewall — a transparent proxy that intercepts "
            "dangerous MCP tool calls and requires OTP-based user approval."
        ),
    )
    parser.add_argument(
        "--target",
        default=None,
        help=(
            "The shell command to launch the real MCP server. "
            "Example: 'uvx mcp-server-stripe --api-key sk_test_...'"
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "Path to firewall_config.json. "
            "Defaults to the bundled config shipped with the package."
        ),
    )
    parser.add_argument(
        "--name",
        default=None,
        help=(
            "Server name for per-server rule overrides in the config. "
            "If omitted, only global rules are applied."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help=(
            "Generate a starter firewall_config.json in the current "
            "directory and exit. Customize it for your needs."
        ),
    )
    return parser


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def _resolve_config_path(user_path: str | None) -> str:
    """Return the absolute path to the firewall config file.

    Resolution order:
        1. Explicit ``--config`` flag.
        2. ``firewall_config.json`` in the current working directory.
        3. Bundled default config shipped with the package.
    """
    if user_path:
        return os.path.abspath(user_path)

    # Check current working directory first
    cwd_config = os.path.join(os.getcwd(), "firewall_config.json")
    if os.path.isfile(cwd_config):
        return cwd_config

    # Fall back to the bundled default inside the package
    bundled = pkg_files("mcp_action_firewall").joinpath("default_config.json")
    return str(bundled)


def _handle_generate_config() -> None:
    """Write a starter firewall_config.json to the current directory."""
    output_path = os.path.join(os.getcwd(), "firewall_config.json")

    if os.path.exists(output_path):
        print(f"❌ {output_path} already exists. Remove it first.")
        sys.exit(1)

    # Read the bundled default and pretty-print it
    bundled = pkg_files("mcp_action_firewall").joinpath("default_config.json")
    with open(str(bundled), "r", encoding="utf-8") as f:
        config = json.load(f)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    print(f"✅ Generated {output_path}")
    print("   Edit this file to customize your firewall rules.")
    print("   The firewall will auto-detect it in the current directory.")


def main() -> None:
    """Entry point for the MCP Action Firewall."""
    parser = build_parser()
    args = parser.parse_args()

    # Handle --generate-config before anything else
    if args.generate_config:
        _handle_generate_config()
        return

    # --target is required for normal operation
    if not args.target:
        parser.error("--target is required (or use --generate-config)")

    _configure_logging(args.verbose)

    logger = logging.getLogger("firewall")
    logger.info("🔥 MCP Action Firewall starting")
    logger.info("   Target : %s", args.target)
    logger.info("   Config : %s", args.config or "(default)")
    logger.info("   Server : %s", args.name or "(global only)")

    config_path = _resolve_config_path(args.config)
    policy_engine = PolicyEngine(config_path, server_name=args.name)
    pending_store = PendingActionStore(max_attempts=policy_engine.otp_attempt_count)

    proxy = FirewallProxy(
        target_command=args.target,
        policy_engine=policy_engine,
        pending_store=pending_store,
    )

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user — shutting down")
    except Exception:
        logger.exception("Fatal error in firewall proxy")
        sys.exit(1)


if __name__ == "__main__":
    main()
