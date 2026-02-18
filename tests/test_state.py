"""Unit tests for :mod:`state` — PendingActionStore."""

import time

import pytest

from mcp_action_firewall.state import PendingActionStore


class TestPendingActionStoreCreate:
    """Tests for OTP creation."""

    def test_create_returns_4_digit_otp(self) -> None:
        store = PendingActionStore()
        otp = store.create("delete_user", {"id": 1})
        assert len(otp) == 4
        assert otp.isdigit()

    def test_create_increments_pending_count(self) -> None:
        store = PendingActionStore()
        assert store.pending_count == 0
        store.create("delete_user", {"id": 1})
        assert store.pending_count == 1
        store.create("drop_table", {"table": "users"})
        assert store.pending_count == 2

    def test_create_generates_unique_otps(self) -> None:
        store = PendingActionStore()
        otps = {store.create(f"tool_{i}", {}) for i in range(50)}
        assert len(otps) == 50, "Expected 50 unique OTPs"

    def test_create_rejects_empty_tool_name(self) -> None:
        store = PendingActionStore()
        with pytest.raises(ValueError, match="non-empty"):
            store.create("", {"id": 1})


class TestPendingActionStoreValidate:
    """Tests for OTP validation."""

    def test_validate_returns_action_for_valid_otp(self) -> None:
        store = PendingActionStore()
        otp = store.create("delete_user", {"id": 42})
        action = store.validate(otp)

        assert action is not None
        assert action.tool_name == "delete_user"
        assert action.arguments == {"id": 42}
        assert action.otp == otp

    def test_validate_removes_action_single_use(self) -> None:
        store = PendingActionStore()
        otp = store.create("delete_user", {"id": 42})

        first = store.validate(otp)
        assert first is not None

        second = store.validate(otp)
        assert second is None, "OTP should be single-use"

    def test_validate_returns_none_for_invalid_otp(self) -> None:
        store = PendingActionStore()
        store.create("delete_user", {"id": 1})
        assert store.validate("0000") is None or store.validate("9999") is None

    def test_validate_returns_none_for_empty_otp(self) -> None:
        store = PendingActionStore()
        assert store.validate("") is None
        assert store.validate(None) is None  # type: ignore[arg-type]


class TestPendingActionStoreExpiry:
    """Tests for TTL-based expiration."""

    def test_expired_entries_are_cleaned_up(self) -> None:
        store = PendingActionStore(ttl_seconds=0)  # expire immediately
        otp = store.create("delete_user", {"id": 1})

        # Give a tiny amount of time to ensure expiry
        time.sleep(0.01)

        assert store.validate(otp) is None
        assert store.pending_count == 0

    def test_non_expired_entries_survive_cleanup(self) -> None:
        store = PendingActionStore(ttl_seconds=300)
        otp = store.create("delete_user", {"id": 1})
        removed = store.cleanup_expired()

        assert removed == 0
        assert store.pending_count == 1
        assert store.validate(otp) is not None
