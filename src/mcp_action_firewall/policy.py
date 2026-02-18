"""
Policy engine for the MCP Action Firewall.

Evaluates whether a tool call should be allowed through or blocked
for OTP-based user approval, using rules from ``firewall_config.json``.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class PolicyDecision(Enum):
    """Result of evaluating a tool name against the firewall policy."""

    ALLOW = "allow"
    BLOCK = "block"


class PolicyEngine:
    """Rule-based policy engine with unified multi-server config support.

    The config file uses this structure::

        {
          "global": {
            "allow_prefixes": ["get_", ...],
            "block_keywords": ["delete", ...],
            "default_action": "block"
          },
          "servers": {
            "stripe": {
              "allow_prefixes": [],
              "block_keywords": ["refund"],
              "default_action": "block"
            }
          }
        }

    When a ``server_name`` is provided, its rules are *merged* into the
    global rules (lists are extended, ``default_action`` is overridden).
    """

    def __init__(
        self,
        config_path: str,
        server_name: Optional[str] = None,
    ) -> None:
        """Initialize the policy engine.

        Args:
            config_path: Path to the ``firewall_config.json`` file.
            server_name: Optional key into the ``servers`` section for
                per-server rule overrides.

        Raises:
            FileNotFoundError: If the config file does not exist.
            ValueError: If the config file is not valid JSON or has a
                bad structure.
        """
        raw_config = self._load_config(config_path)
        self._allow_prefixes, self._block_keywords, self._default_action = (
            self._merge_rules(raw_config, server_name)
        )

        logger.info(
            "PolicyEngine initialized (server=%s) – "
            "allow_prefixes=%s, block_keywords=%s, default=%s",
            server_name or "global-only",
            self._allow_prefixes,
            self._block_keywords,
            self._default_action,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, tool_name: str) -> PolicyDecision:
        """Decide whether a tool call is allowed or blocked.

        Evaluation order:
            1. If ``tool_name`` starts with any allow prefix → ALLOW.
            2. If ``tool_name`` contains any block keyword → BLOCK.
            3. Fallback to ``default_action``.

        Args:
            tool_name: The MCP tool name (e.g. ``"stripe_refund"``).

        Returns:
            :attr:`PolicyDecision.ALLOW` or :attr:`PolicyDecision.BLOCK`.
        """
        if not tool_name:
            logger.warning("Empty tool_name received — blocking by default")
            return PolicyDecision.BLOCK

        normalized = tool_name.lower()

        # 1. Allow-list check (prefix match)
        for prefix in self._allow_prefixes:
            if normalized.startswith(prefix):
                logger.debug("ALLOW %s (matched prefix '%s')", tool_name, prefix)
                return PolicyDecision.ALLOW

        # 2. Block-list check (substring match)
        for keyword in self._block_keywords:
            if keyword in normalized:
                logger.debug(
                    "BLOCK %s (matched keyword '%s')", tool_name, keyword
                )
                return PolicyDecision.BLOCK

        # 3. Fallback
        decision = PolicyDecision(self._default_action)
        logger.debug("DEFAULT %s → %s", tool_name, decision.value)
        return decision

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_config(config_path: str) -> dict[str, Any]:
        """Load and validate the JSON config file."""
        path = Path(config_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"Firewall config not found: {path.resolve()}"
            )

        try:
            with path.open("r", encoding="utf-8") as fp:
                config = json.load(fp)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in firewall config: {exc}"
            ) from exc

        if "global" not in config:
            raise ValueError(
                "Firewall config must contain a 'global' section"
            )

        return config

    @staticmethod
    def _merge_rules(
        config: dict[str, Any],
        server_name: Optional[str],
    ) -> tuple[list[str], list[str], str]:
        """Merge global rules with optional per-server overrides.

        Returns:
            Tuple of (allow_prefixes, block_keywords, default_action).
        """
        global_cfg = config["global"]
        allow_prefixes: list[str] = list(global_cfg.get("allow_prefixes", []))
        block_keywords: list[str] = list(global_cfg.get("block_keywords", []))
        default_action: str = global_cfg.get("default_action", "block")

        if server_name:
            server_cfg = config.get("servers", {}).get(server_name)
            if server_cfg:
                # Extend lists (don't replace)
                allow_prefixes.extend(server_cfg.get("allow_prefixes", []))
                block_keywords.extend(server_cfg.get("block_keywords", []))
                # Override default_action if specified
                if "default_action" in server_cfg:
                    default_action = server_cfg["default_action"]
                logger.info(
                    "Merged server-specific rules for '%s'", server_name
                )
            else:
                logger.warning(
                    "Server '%s' not found in config — using global rules only",
                    server_name,
                )

        # Normalize to lowercase and deduplicate
        allow_prefixes = list(dict.fromkeys(p.lower() for p in allow_prefixes))
        block_keywords = list(dict.fromkeys(k.lower() for k in block_keywords))

        # Validate default_action
        valid_actions = {d.value for d in PolicyDecision}
        if default_action not in valid_actions:
            raise ValueError(
                f"Invalid default_action '{default_action}'. "
                f"Must be one of: {valid_actions}"
            )

        return allow_prefixes, block_keywords, default_action
