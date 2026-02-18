"""
In-memory pending-action store for the MCP Action Firewall.

Maps one-time-password (OTP) codes to blocked tool calls so they
can be resumed after explicit user approval.
"""

from __future__ import annotations

import random
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PendingAction:
    """Mutable record of a blocked tool call awaiting user confirmation."""

    tool_name: str
    arguments: dict[str, Any]
    otp: str
    created_at: float = field(default_factory=time.time)
    attempt_count: int = 0  # number of failed validation attempts


class PendingActionStore:
    """Thread-safe store that maps OTP codes to pending tool-call actions.

    Typical lifecycle:
        1. ``otp = store.create("delete_user", {"id": 42})``
        2. OTP is shown to the user via the agent chat.
        3. ``action = store.validate(otp)``  — removes it from the store.
        4. If the OTP is wrong, ``validate`` returns ``None``.
           After ``max_attempts`` failures the entry is permanently removed.
    """

    _OTP_LENGTH: int = 4
    _DEFAULT_TTL_SECONDS: int = 300  # 5 minutes

    def __init__(
        self,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        max_attempts: int = 1,
    ) -> None:
        self._store: dict[str, PendingAction] = {}
        self._lock = threading.Lock()
        self._ttl_seconds = ttl_seconds
        self._max_attempts = max_attempts

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Store a pending action and return the generated OTP.

        Args:
            tool_name: Name of the tool that was blocked.
            arguments: Original arguments dict for the tool call.

        Returns:
            A unique 4-digit OTP string (e.g. ``"8821"``).
        """
        if not tool_name:
            raise ValueError("tool_name must be a non-empty string")

        otp = self._generate_unique_otp()
        action = PendingAction(
            tool_name=tool_name,
            arguments=arguments,
            otp=otp,
        )
        with self._lock:
            self._store[otp] = action
        return otp

    def validate(self, otp: str) -> Optional[PendingAction]:
        """Validate an OTP and return the pending action if it exists.

        The action is **removed** from the store on successful validation
        so that each OTP can only be used once.

        If the OTP is wrong, the attempt counter is incremented.
        Once ``max_attempts`` is reached, the entry is permanently removed
        (locked out).

        Args:
            otp: The code provided by the user.

        Returns:
            The :class:`PendingAction` if the OTP is valid, else ``None``.
        """
        if not otp:
            return None

        with self._lock:
            self._cleanup_expired_locked()

            action = self._store.get(otp)
            if action is not None:
                # Valid OTP — consume and return
                del self._store[otp]
                return action

            # Wrong OTP — increment attempt count on any matching entry
            # and lock out if limit reached
            for stored_otp, stored_action in list(self._store.items()):
                stored_action.attempt_count += 1
                if stored_action.attempt_count >= self._max_attempts:
                    del self._store[stored_otp]
                    return None  # locked out

            return None

    def cleanup_expired(self) -> int:
        """Remove entries older than the configured TTL.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            return self._cleanup_expired_locked()

    @property
    def pending_count(self) -> int:
        """Number of currently pending actions (excluding expired)."""
        with self._lock:
            self._cleanup_expired_locked()
            return len(self._store)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_unique_otp(self) -> str:
        """Generate a 4-digit OTP that doesn't collide with existing ones."""
        with self._lock:
            for _ in range(100):  # guard against infinite loop
                otp = "".join(
                    random.choices(string.digits, k=self._OTP_LENGTH)
                )
                if otp not in self._store:
                    return otp
            raise RuntimeError(
                "Failed to generate a unique OTP after 100 attempts. "
                "Too many pending actions."
            )

    def _cleanup_expired_locked(self) -> int:
        """Remove expired entries.  Caller MUST hold ``self._lock``."""
        now = time.time()
        expired_keys = [
            key
            for key, action in self._store.items()
            if (now - action.created_at) > self._ttl_seconds
        ]
        for key in expired_keys:
            del self._store[key]
        return len(expired_keys)
