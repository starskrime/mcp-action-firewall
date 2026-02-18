"""Unit tests for :mod:`policy` — PolicyEngine."""

import json
import os
import tempfile

import pytest

from mcp_action_firewall.policy import PolicyDecision, PolicyEngine


def _write_config(config: dict, path: str | None = None) -> str:
    """Write a config dict to a temp JSON file and return its path."""
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f)
    return path


# -----------------------------------------------------------------------
# Default global config used across tests
# -----------------------------------------------------------------------

GLOBAL_CONFIG = {
    "global": {
        "allow_prefixes": ["get_", "list_", "read_", "fetch_"],
        "block_keywords": ["delete", "update", "create", "pay", "send"],
        "default_action": "block",
    },
    "servers": {
        "stripe": {
            "allow_prefixes": [],
            "block_keywords": ["refund", "charge"],
            "default_action": "block",
        },
        "database": {
            "allow_prefixes": ["select_"],
            "block_keywords": ["drop", "truncate"],
            "default_action": "block",
        },
    },
}


class TestPolicyEngineGlobalRules:
    """Test evaluation using only global rules."""

    @pytest.fixture()
    def engine(self, tmp_path: object) -> PolicyEngine:
        path = _write_config(GLOBAL_CONFIG)
        return PolicyEngine(config_path=path, server_name=None)

    @pytest.mark.parametrize(
        "tool_name",
        ["get_balance", "list_users", "read_file", "fetch_records"],
    )
    def test_allow_prefix_match(self, engine: PolicyEngine, tool_name: str) -> None:
        assert engine.evaluate(tool_name) == PolicyDecision.ALLOW

    @pytest.mark.parametrize(
        "tool_name",
        ["delete_user", "update_record", "create_payment", "pay_user", "send_email"],
    )
    def test_block_keyword_match(self, engine: PolicyEngine, tool_name: str) -> None:
        assert engine.evaluate(tool_name) == PolicyDecision.BLOCK

    def test_unknown_tool_falls_to_default(self, engine: PolicyEngine) -> None:
        # "do_something" doesn't match any rule → default is "block"
        assert engine.evaluate("do_something") == PolicyDecision.BLOCK

    def test_case_insensitive(self, engine: PolicyEngine) -> None:
        assert engine.evaluate("GET_balance") == PolicyDecision.ALLOW
        assert engine.evaluate("DELETE_user") == PolicyDecision.BLOCK

    def test_empty_tool_name_blocked(self, engine: PolicyEngine) -> None:
        assert engine.evaluate("") == PolicyDecision.BLOCK


class TestPolicyEngineServerOverrides:
    """Test that per-server rules extend global rules."""

    def test_stripe_inherits_global_block_keywords(self) -> None:
        path = _write_config(GLOBAL_CONFIG)
        engine = PolicyEngine(config_path=path, server_name="stripe")

        # Global keyword "delete" should still work
        assert engine.evaluate("delete_user") == PolicyDecision.BLOCK

        # Stripe-specific keyword "refund" should also work
        assert engine.evaluate("stripe_refund") == PolicyDecision.BLOCK
        assert engine.evaluate("charge_card") == PolicyDecision.BLOCK

    def test_database_adds_select_prefix(self) -> None:
        path = _write_config(GLOBAL_CONFIG)
        engine = PolicyEngine(config_path=path, server_name="database")

        # "select_" is added by the database override
        assert engine.evaluate("select_all") == PolicyDecision.ALLOW

        # Global allows still work
        assert engine.evaluate("get_schema") == PolicyDecision.ALLOW

        # Database-specific blocks
        assert engine.evaluate("drop_table") == PolicyDecision.BLOCK
        assert engine.evaluate("truncate_table") == PolicyDecision.BLOCK

    def test_unknown_server_uses_global_only(self) -> None:
        path = _write_config(GLOBAL_CONFIG)
        engine = PolicyEngine(config_path=path, server_name="nonexistent")

        # Should behave identically to global-only
        assert engine.evaluate("get_balance") == PolicyDecision.ALLOW
        assert engine.evaluate("delete_user") == PolicyDecision.BLOCK


class TestPolicyEngineDefaultAction:
    """Test that default_action is respected."""

    def test_default_allow(self) -> None:
        config = {
            "global": {
                "allow_prefixes": [],
                "block_keywords": [],
                "default_action": "allow",
            }
        }
        path = _write_config(config)
        engine = PolicyEngine(config_path=path)
        assert engine.evaluate("anything") == PolicyDecision.ALLOW

    def test_server_overrides_default_action(self) -> None:
        config = {
            "global": {
                "allow_prefixes": [],
                "block_keywords": [],
                "default_action": "block",
            },
            "servers": {
                "lenient": {
                    "default_action": "allow",
                }
            },
        }
        path = _write_config(config)
        engine = PolicyEngine(config_path=path, server_name="lenient")
        assert engine.evaluate("unknown_tool") == PolicyDecision.ALLOW


class TestPolicyEngineConfigErrors:
    """Test error handling for bad configs."""

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            PolicyEngine(config_path="/nonexistent/config.json")

    def test_invalid_json_raises(self) -> None:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, b"not json {{{")
        os.close(fd)
        with pytest.raises(ValueError, match="Invalid JSON"):
            PolicyEngine(config_path=path)

    def test_missing_global_section_raises(self) -> None:
        path = _write_config({"servers": {}})
        with pytest.raises(ValueError, match="global"):
            PolicyEngine(config_path=path)

    def test_invalid_default_action_raises(self) -> None:
        config = {
            "global": {
                "allow_prefixes": [],
                "block_keywords": [],
                "default_action": "yolo",
            }
        }
        path = _write_config(config)
        with pytest.raises(ValueError, match="Invalid default_action"):
            PolicyEngine(config_path=path)
