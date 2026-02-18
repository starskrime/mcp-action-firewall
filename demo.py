#!/usr/bin/env python3
"""
Interactive demo of the MCP Action Firewall.

This script acts as a simple "AI agent" — it spawns the firewall
(wrapping a mock MCP server) and sends tool calls so you can see
the OTP approval flow in real time.

Usage:
    uv run python demo.py
"""

import asyncio
import json
import os
import re
import shlex
import sys
import tempfile
import textwrap

# ── Colors ──────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}\n")


def step(n: int, text: str) -> None:
    print(f"\n{BOLD}{YELLOW}  Step {n}: {text}{RESET}\n")


def show_sent(msg: dict) -> None:
    print(f"  {DIM}→ Sending:{RESET}")
    formatted = json.dumps(msg, indent=4)
    for line in formatted.splitlines():
        print(f"    {DIM}{line}{RESET}")


def show_received(msg: dict, label: str = "Response") -> None:
    formatted = json.dumps(msg, indent=4)
    for line in formatted.splitlines():
        print(f"    {line}")


# ── Mock server (same one used in tests) ──────────────────────────

MOCK_SERVER = textwrap.dedent('''\
    import json, sys
    TOOLS = [
        {"name": "get_balance", "description": "Get account balance",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "delete_user", "description": "Delete a user",
         "inputSchema": {"type": "object",
                         "properties": {"id": {"type": "integer"}},
                         "required": ["id"]}},
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
            resp = {"jsonrpc": "2.0", "id": rid,
                    "result": {"protocolVersion": "2024-11-05",
                               "capabilities": {"tools": {"listChanged": False}},
                               "serverInfo": {"name": "mock-server", "version": "0.1.0"}}}
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            params = msg.get("params", {})
            resp = {"jsonrpc": "2.0", "id": rid,
                    "result": {"content": [{"type": "text",
                               "text": f"✅ Executed {params.get('name')} with {params.get('arguments', {})}"}]}}
        elif method == "notifications/initialized":
            continue
        else:
            resp = {"jsonrpc": "2.0", "id": rid, "result": {}}
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
''')


async def send(proc: asyncio.subprocess.Process, msg: dict) -> dict:
    """Send a JSON-RPC message and read one response."""
    assert proc.stdin and proc.stdout
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=10)
    return json.loads(line.decode().strip())


async def main() -> None:
    banner("🔥 MCP Action Firewall — Interactive Demo")
    print("  This demo simulates an AI agent talking to the firewall.")
    print("  You'll see safe calls pass through and dangerous calls")
    print("  get blocked until YOU approve them with an OTP code.\n")

    # Write temp files
    fd, mock_path = tempfile.mkstemp(suffix=".py")
    os.write(fd, MOCK_SERVER.encode())
    os.close(fd)

    config = {
        "global": {
            "allow_prefixes": ["get_", "list_"],
            "block_keywords": ["delete", "update", "drop"],
            "default_action": "block",
        }
    }
    fd, config_path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(config).encode())
    os.close(fd)

    # Spawn firewall
    project_root = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(project_root, "src") + os.pathsep + env.get("PYTHONPATH", "")

    target_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(mock_path)}"
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "mcp_action_firewall",
        "--target", target_cmd,
        "--config", config_path,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    try:
        # ── Step 1: Initialize ──────────────────────────────────
        step(1, "Initialize the MCP connection")
        init_msg = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "demo-agent", "version": "0.1"},
            }
        }
        show_sent(init_msg)
        resp = await send(proc, init_msg)
        print(f"\n  {GREEN}✅ Connected to: {resp['result']['serverInfo']['name']}{RESET}")

        # ── Step 2: List tools ──────────────────────────────────
        step(2, "List available tools (firewall_confirm is injected)")
        list_msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        show_sent(list_msg)
        resp = await send(proc, list_msg)
        tools = resp["result"]["tools"]
        print(f"\n  {GREEN}Available tools:{RESET}")
        for t in tools:
            icon = "🛡️" if t["name"] == "firewall_confirm" else "🔧"
            print(f"    {icon} {BOLD}{t['name']}{RESET} — {t.get('description', '')}")

        # ── Step 3: Safe call ───────────────────────────────────
        step(3, "Call a safe tool: get_balance (matches allow prefix 'get_')")
        safe_msg = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "get_balance", "arguments": {}}
        }
        show_sent(safe_msg)
        resp = await send(proc, safe_msg)
        result_text = resp["result"]["content"][0]["text"]
        print(f"\n  {GREEN}✅ ALLOWED — {result_text}{RESET}")

        # ── Step 4: Dangerous call ──────────────────────────────
        step(4, "Call a dangerous tool: delete_user (contains block keyword 'delete')")
        danger_msg = {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "delete_user", "arguments": {"id": 42}}
        }
        show_sent(danger_msg)
        resp = await send(proc, danger_msg)
        rejection_text = resp["result"]["content"][0]["text"]
        rejection = json.loads(rejection_text)

        print(f"\n  {RED}🛑 BLOCKED — {rejection['status']}{RESET}")
        print(f"  {YELLOW}{rejection['message']}{RESET}")
        print()
        print(f"  {DIM}The firewall's instruction to the agent:{RESET}")
        for line in rejection["instruction"].splitlines():
            print(f"    {line}")

        # Extract OTP
        otp_match = re.search(r"\b(\d{4})\b", rejection["instruction"])
        assert otp_match, "No OTP found!"
        otp = otp_match.group(1)

        # ── Step 5: Ask user for OTP ────────────────────────────
        step(5, "YOU are the human! Enter the OTP to approve the action")
        print(f"  The OTP code is: {BOLD}{GREEN}{otp}{RESET}")
        print()

        user_input = input(f"  {BOLD}Enter the code to approve (or anything else to deny): {RESET}")

        if user_input.strip() != otp:
            print(f"\n  {RED}❌ Wrong code! Action denied.{RESET}")
            return

        # ── Step 6: Confirm with OTP ────────────────────────────
        step(6, "Calling firewall_confirm with the approved OTP")
        confirm_msg = {
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "firewall_confirm", "arguments": {"otp": otp}}
        }
        show_sent(confirm_msg)
        resp = await send(proc, confirm_msg)
        result_text = resp["result"]["content"][0]["text"]
        print(f"\n  {GREEN}✅ ACTION EXECUTED — {result_text}{RESET}")

        banner("🎉 Demo Complete!")
        print("  The firewall blocked 'delete_user', you approved it with")
        print("  a one-time code, and the original action was replayed.\n")
        print(f"  {DIM}To use this with a real MCP server, add it to your")
        print(f"  Claude/Cursor config — see README.md for examples.{RESET}\n")

    finally:
        proc.terminate()
        await proc.wait()
        os.unlink(mock_path)
        os.unlink(config_path)


if __name__ == "__main__":
    asyncio.run(main())
