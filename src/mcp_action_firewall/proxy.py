"""
JSON-RPC stdio proxy for the MCP Action Firewall.

Sits between an AI agent's MCP client and the real target MCP server,
intercepting ``tools/call`` requests and applying the firewall policy.

Protocol notes:
    MCP uses JSON-RPC 2.0 over stdio.  Each message is a single JSON
    object delimited by newlines.  This proxy reads lines from its own
    stdin (the agent side), inspects them, and either:
      • Forwards them to the target subprocess's stdin, or
      • Intercepts them and returns a synthetic response.

    Responses from the target subprocess's stdout are relayed back to
    the agent (our stdout), with ``tools/list`` responses augmented to
    include the ``firewall_confirm`` virtual tool.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any, Optional

from mcp_action_firewall.policy import PolicyDecision, PolicyEngine
from mcp_action_firewall.state import PendingActionStore

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

FIREWALL_CONFIRM_TOOL_NAME = "firewall_confirm"

FIREWALL_CONFIRM_TOOL_SCHEMA: dict[str, Any] = {
    "name": FIREWALL_CONFIRM_TOOL_NAME,
    "description": (
        "Call this tool ONLY when the user provides the correct 4-digit "
        "approval code to confirm a paused action."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "otp": {
                "type": "string",
                "description": "The 4-digit code provided by the user.",
            }
        },
        "required": ["otp"],
    },
}


class FirewallProxy:
    """Async JSON-RPC proxy that enforces tool-call security policies.

    The proxy manages two data streams:

    * **Agent → Target** (``stdin`` of this process → ``stdin`` of the
      subprocess).  Tool calls are inspected here.
    * **Target → Agent** (``stdout`` of the subprocess → ``stdout`` of
      this process).  ``tools/list`` responses are augmented here.
    """

    def __init__(
        self,
        target_command: str,
        policy_engine: PolicyEngine,
        pending_store: PendingActionStore,
    ) -> None:
        self._target_command = target_command
        self._policy = policy_engine
        self._store = pending_store


        # Subprocess handles — set during run()
        self._process: Optional[asyncio.subprocess.Process] = None

        # Map request IDs to detect which responses are for tools/list
        self._pending_requests: dict[int | str, str] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the target subprocess and begin proxying messages."""
        logger.info("Spawning target: %s", self._target_command)

        self._process = await asyncio.create_subprocess_shell(
            self._target_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Run both directions concurrently
        agent_to_target = asyncio.create_task(
            self._handle_agent_to_target(), name="agent→target"
        )
        target_to_agent = asyncio.create_task(
            self._handle_target_to_agent(), name="target→agent"
        )
        stderr_logger = asyncio.create_task(
            self._log_target_stderr(), name="target-stderr"
        )

        try:
            done, pending = await asyncio.wait(
                [agent_to_target, target_to_agent, stderr_logger],
                return_when=asyncio.FIRST_COMPLETED,
            )
            # If any task finishes, cancel the others
            for task in pending:
                task.cancel()
            # Propagate exceptions from completed tasks
            for task in done:
                if task.exception():
                    raise task.exception()  # type: ignore[misc]
        finally:
            await self._shutdown_target()

    # ------------------------------------------------------------------
    # Agent → Target direction
    # ------------------------------------------------------------------

    async def _handle_agent_to_target(self) -> None:
        """Read JSON-RPC messages from our stdin and process them.

        Uses a thread to perform blocking reads from ``sys.stdin.buffer``
        because async ``connect_read_pipe`` is unreliable when this
        process is itself spawned as a subprocess.
        """
        loop = asyncio.get_running_loop()

        while True:
            # Blocking readline in a thread — returns b"" on EOF
            line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
            if not line:
                logger.info("Agent stdin closed — shutting down")
                break

            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                message = json.loads(line_str)
            except json.JSONDecodeError:
                logger.warning("Non-JSON line from agent: %s", line_str[:200])
                # Forward as-is (could be a protocol header)
                await self._send_to_target(line_str)
                continue

            await self._process_agent_message(message)

    async def _process_agent_message(self, message: dict[str, Any]) -> None:
        """Inspect and route a single JSON-RPC message from the agent."""
        method = message.get("method")
        request_id = message.get("id")

        # Track tools/list requests so we can augment the response
        if method == "tools/list" and request_id is not None:
            self._pending_requests[request_id] = "tools/list"
            await self._send_to_target(json.dumps(message))
            return

        # Intercept tools/call requests
        if method == "tools/call":
            await self._handle_tool_call(message)
            return

        # Everything else passes through transparently
        if method and request_id is not None:
            self._pending_requests[request_id] = method
        await self._send_to_target(json.dumps(message))

    async def _handle_tool_call(self, message: dict[str, Any]) -> None:
        """Apply policy to a ``tools/call`` request."""
        request_id = message.get("id")
        params = message.get("params", {})
        tool_name: str = params.get("name", "")
        arguments: dict[str, Any] = params.get("arguments", {})

        # Handle our virtual firewall_confirm tool locally
        if tool_name == FIREWALL_CONFIRM_TOOL_NAME:
            response = await self._handle_firewall_confirm(
                request_id, arguments
            )
            # response is None when a valid OTP replays the call —
            # the real result will arrive through _handle_target_to_agent
            if response is not None:
                await self._send_to_agent(json.dumps(response))
            return

        # Evaluate the policy
        decision = self._policy.evaluate(tool_name)

        if decision == PolicyDecision.ALLOW:
            logger.info("✅ ALLOW: %s", tool_name)
            await self._send_to_target(json.dumps(message))
            return

        # BLOCK — generate OTP and return soft-rejection
        logger.warning("🛑 BLOCK: %s — generating OTP", tool_name)
        otp = self._store.create(tool_name, arguments)
        response = self._build_soft_rejection(request_id, tool_name, arguments, otp)
        await self._send_to_agent(json.dumps(response))

    async def _handle_firewall_confirm(
        self, request_id: Any, arguments: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """Process a ``firewall_confirm`` call.

        If the OTP is valid, replay the original tool call against the
        target server and return ``None`` (the real response arrives via
        the target→agent stream).
        """
        otp = arguments.get("otp", "")

        if not otp:
            return self._build_error_response(
                request_id,
                "Missing 'otp' argument. Ask the user for the code.",
            )

        action = self._store.validate(otp)
        if action is None:
            return self._build_error_response(
                request_id,
                "Invalid or expired code. Do not guess. Ask the user.",
            )

        logger.info(
            "✅ OTP %s confirmed — replaying %s", otp, action.tool_name
        )

        # Replay the original call against the real target
        replay_message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": action.tool_name,
                "arguments": action.arguments,
            },
        }
        await self._send_to_target(json.dumps(replay_message))

        # The real response will flow back through _handle_target_to_agent
        return None

    # ------------------------------------------------------------------
    # Target → Agent direction
    # ------------------------------------------------------------------

    async def _handle_target_to_agent(self) -> None:
        """Read responses from the target's stdout and relay to agent."""
        assert self._process is not None
        assert self._process.stdout is not None

        while True:
            line = await self._process.stdout.readline()
            if not line:
                logger.info("Target stdout closed")
                break

            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                message = json.loads(line_str)
            except json.JSONDecodeError:
                # Forward non-JSON lines as-is
                await self._send_to_agent(line_str)
                continue

            # Check if this is a response to a tools/list request
            response_id = message.get("id")
            if response_id is not None:
                original_method = self._pending_requests.pop(
                    response_id, None
                )
                if original_method == "tools/list":
                    message = self._augment_tools_list(message)

            await self._send_to_agent(json.dumps(message))

    def _augment_tools_list(
        self, response: dict[str, Any]
    ) -> dict[str, Any]:
        """Inject ``firewall_confirm`` into a ``tools/list`` response."""
        result = response.get("result", {})
        tools = result.get("tools", [])

        # Avoid duplicates if already present
        existing_names = {t.get("name") for t in tools}
        if FIREWALL_CONFIRM_TOOL_NAME not in existing_names:
            tools.append(FIREWALL_CONFIRM_TOOL_SCHEMA)
            logger.debug("Injected %s into tools/list", FIREWALL_CONFIRM_TOOL_NAME)

        result["tools"] = tools
        response["result"] = result
        return response

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    async def _send_to_target(self, data: str) -> None:
        """Write a line to the target subprocess's stdin."""
        assert self._process is not None
        assert self._process.stdin is not None
        self._process.stdin.write((data + "\n").encode("utf-8"))
        await self._process.stdin.drain()

    async def _send_to_agent(self, data: str) -> None:
        """Write a line to our stdout (the agent reads this).

        Uses ``os.write`` on fd 1 for truly unbuffered output,
        wrapped in ``run_in_executor`` to keep the event loop free.
        """
        payload = (data + "\n").encode("utf-8")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, os.write, 1, payload)

    async def _log_target_stderr(self) -> None:
        """Relay target's stderr to our logger so errors are visible."""
        assert self._process is not None
        assert self._process.stderr is not None
        while True:
            line = await self._process.stderr.readline()
            if not line:
                break
            logger.debug(
                "[target stderr] %s",
                line.decode("utf-8", errors="replace").strip(),
            )

    async def _shutdown_target(self) -> None:
        """Gracefully terminate the target subprocess."""
        if self._process is None:
            return
        if self._process.returncode is not None:
            return

        logger.info("Terminating target subprocess...")
        self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Target did not exit in 5s — killing")
            self._process.kill()
            await self._process.wait()

    # ------------------------------------------------------------------
    # Response builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_soft_rejection(
        request_id: Any,
        tool_name: str,
        arguments: dict[str, Any],
        otp: str,
    ) -> dict[str, Any]:
        """Build the structured PAUSED response that instructs the AI agent
        to ask the user for the OTP approval code.

        Arguments are included in the prompt so the human can verify
        exactly what will be executed before typing the code.
        """
        # Format arguments as a readable summary for the user
        args_summary = (
            json.dumps(arguments, indent=2) if arguments else "(no arguments)"
        )

        rejection_payload = {
            "status": "PAUSED_FOR_APPROVAL",
            "message": (
                f"⚠️ The action '{tool_name}' is HIGH RISK and has been "
                f"locked by the Action Firewall."
            ),
            "action": {
                "tool": tool_name,
                "arguments": arguments,
            },
            "instruction": (
                f"To unlock this action, you MUST ask the user for "
                f"authorization.\n\n"
                f"1. Show the user the following and ask for approval:\n"
                f"   Tool: **{tool_name}**\n"
                f"   Arguments:\n{args_summary}\n\n"
                f"2. Tell the user: 'Please reply with approval code: "
                f"**{otp}**' to allow this action, or say no to cancel.\n"
                f"3. STOP and wait for their reply.\n"
                f"4. When they reply with '{otp}', call the "
                f"'{FIREWALL_CONFIRM_TOOL_NAME}' tool with that code.\n"
                f"5. If they say no or give a different code, do NOT retry."
            ),
        }
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(rejection_payload, indent=2),
                    }
                ],
            },
        }

    @staticmethod
    def _build_error_response(
        request_id: Any, message: str
    ) -> dict[str, Any]:
        """Build a tool-result error response."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"❌ FIREWALL ERROR: {message}",
                    }
                ],
                "isError": True,
            },
        }
