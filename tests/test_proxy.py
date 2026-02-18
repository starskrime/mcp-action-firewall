"""
Integration test for the proxy layer.

Creates a minimal mock MCP server and verifies the firewall intercepts
dangerous calls, allows safe calls, and handles OTP confirmation.
"""

import asyncio
import json
import os
import re
import shlex
import sys
import tempfile

import pytest

# -----------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

# -----------------------------------------------------------------------
# Mock MCP server script (written to a temp file at test time)
# -----------------------------------------------------------------------

MOCK_SERVER_SCRIPT = r'''
"""Minimal MCP server that echoes tool calls back as results."""
import json
import sys

TOOLS = [
    {
        "name": "get_balance",
        "description": "Get account balance",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "delete_user",
        "description": "Delete a user",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"]
        }
    },
]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue

    method = msg.get("method")
    rid = msg.get("id")

    if method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-server", "version": "0.1.0"}
            }
        }
    elif method == "tools/list":
        resp = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    elif method == "tools/call":
        params = msg.get("params", {})
        resp = {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "content": [
                    {"type": "text", "text": f"Executed {params.get('name')} with {params.get('arguments', {})}"}
                ]
            }
        }
    elif method == "notifications/initialized":
        continue
    else:
        resp = {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {}
        }

    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
'''


@pytest.fixture()
def config_path() -> str:
    """Write a test firewall config and return its path."""
    config = {
        "global": {
            "allow_prefixes": ["get_", "list_"],
            "block_keywords": ["delete", "update"],
            "default_action": "block",
        }
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(config).encode())
    os.close(fd)
    return path


@pytest.fixture()
def mock_server_path() -> str:
    """Write the mock server script and return its path."""
    fd, path = tempfile.mkstemp(suffix=".py")
    os.write(fd, MOCK_SERVER_SCRIPT.encode())
    os.close(fd)
    return path


async def _spawn_firewall(
    config_path: str, mock_server_path: str
) -> asyncio.subprocess.Process:
    """Spawn the firewall proxy as a subprocess using ``python -m``.

    Uses ``shlex.quote`` on paths to handle spaces in directory names
    (e.g. ``MCP Action Firewall``).
    """
    env = os.environ.copy()
    # src/ layout — ensure the package is importable
    env["PYTHONPATH"] = (
        os.path.join(PROJECT_ROOT, "src")
        + os.pathsep
        + env.get("PYTHONPATH", "")
    )

    # The --target value is a shell command, so paths must be quoted
    target_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(mock_server_path)}"

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m", "mcp_action_firewall",
        "--target", target_cmd,
        "--config", config_path,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    return proc


async def _send_and_receive(
    proc: asyncio.subprocess.Process,
    message: dict,
    timeout: float = 10.0,
) -> dict:
    """Send a JSON-RPC message to the proxy and read one response."""
    assert proc.stdin is not None
    assert proc.stdout is not None

    payload = json.dumps(message) + "\n"
    proc.stdin.write(payload.encode())
    await proc.stdin.drain()

    line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
    decoded = line.decode().strip()
    if not decoded:
        # Try to get stderr for diagnostics
        assert proc.stderr is not None
        stderr_data = await asyncio.wait_for(
            proc.stderr.read(4096), timeout=2.0
        )
        raise RuntimeError(
            f"Empty response from firewall. stderr: {stderr_data.decode()}"
        )
    return json.loads(decoded)


@pytest.mark.asyncio
async def test_safe_tool_passes_through(
    config_path: str, mock_server_path: str
) -> None:
    """A tool matching an allow prefix should be forwarded to the target."""
    proc = await _spawn_firewall(config_path, mock_server_path)

    try:
        # Send initialize first (most MCP servers expect this)
        resp = await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1"},
            }
        })
        assert resp["id"] == 1

        # Safe tool call
        resp = await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_balance", "arguments": {}}
        })
        assert resp["id"] == 2
        assert "Executed get_balance" in resp["result"]["content"][0]["text"]
    finally:
        proc.terminate()
        await proc.wait()


@pytest.mark.asyncio
async def test_dangerous_tool_is_blocked_and_otp_confirms(
    config_path: str, mock_server_path: str
) -> None:
    """A blocked tool should return a structured PAUSED_FOR_APPROVAL response,
    and OTP confirmation should replay the original call."""
    proc = await _spawn_firewall(config_path, mock_server_path)

    try:
        # Initialize
        await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1"},
            }
        })

        # Dangerous tool call → should be blocked
        resp = await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "delete_user", "arguments": {"id": 42}}
        })
        assert resp["id"] == 2
        text = resp["result"]["content"][0]["text"]

        # The response should be a structured JSON payload
        rejection = json.loads(text)
        assert rejection["status"] == "PAUSED_FOR_APPROVAL"
        assert "delete_user" in rejection["message"]
        assert "instruction" in rejection

        # Extract the OTP from the instruction
        otp_match = re.search(r"\b(\d{4})\b", rejection["instruction"])
        assert otp_match is not None, f"No OTP found in: {rejection['instruction']}"
        otp = otp_match.group(1)

        # Confirm with the OTP
        resp = await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "firewall_confirm", "arguments": {"otp": otp}}
        })

        # The response should be the REAL result from the mock server
        assert resp["id"] == 3
        result_text = resp["result"]["content"][0]["text"]
        assert "Executed delete_user" in result_text
        assert "42" in result_text
    finally:
        proc.terminate()
        await proc.wait()


@pytest.mark.asyncio
async def test_tools_list_includes_firewall_confirm(
    config_path: str, mock_server_path: str
) -> None:
    """The tools/list response should include the firewall_confirm tool."""
    proc = await _spawn_firewall(config_path, mock_server_path)

    try:
        # Initialize
        await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1"},
            }
        })

        # List tools
        resp = await _send_and_receive(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        })

        tool_names = [t["name"] for t in resp["result"]["tools"]]
        assert "firewall_confirm" in tool_names
        assert "get_balance" in tool_names
        assert "delete_user" in tool_names
    finally:
        proc.terminate()
        await proc.wait()
