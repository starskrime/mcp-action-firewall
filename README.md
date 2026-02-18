# 🔥 MCP Action Firewall

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggOHoiLz48L3N2Zz4=)](https://modelcontextprotocol.io)

### Works with any MCP-compatible agent

[![Claude](https://img.shields.io/badge/Claude-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://claude.ai)
[![Cursor](https://img.shields.io/badge/Cursor-000000?style=for-the-badge&logo=cursor&logoColor=white)](https://cursor.sh)
[![Windsurf](https://img.shields.io/badge/Windsurf-00C4B3?style=for-the-badge&logo=codeium&logoColor=white)](https://codeium.com/windsurf)
[![OpenAI](https://img.shields.io/badge/OpenAI_Agents-412991?style=for-the-badge&logo=openai&logoColor=white)](https://openai.com)
[![Gemini](https://img.shields.io/badge/Gemini-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)](https://gemini.google.com)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-FF6600?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyYTEwIDEwIDAgMSAwIDAgMjAgMTAgMTAgMCAwIDAgMC0yMHptMCAzYTIgMiAwIDEgMSAwIDQgMiAyIDAgMCAxIDAtNHptLTQgNWEyIDIgMCAxIDEgMCA0IDIgMiAwIDAgMSAwLTR6bTggMGEyIDIgMCAxIDEgMCA0IDIgMiAwIDAgMSAwLTR6bS00IDRhMiAyIDAgMSAxIDAgNCAyIDIgMCAwIDEgMC00eiIvPjwvc3ZnPg==&logoColor=white)](https://github.com/openclaw)

A transparent **MCP proxy** that intercepts dangerous tool calls and requires **OTP-based human approval** before execution. Acts as a circuit breaker between your AI agent and any MCP server.

## How It Works

```
┌──────────┐    stdin/stdout    ┌──────────────────┐    stdin/stdout    ┌──────────────────┐
│ AI Agent │ ◄────────────────► │   MCP Action     │ ◄────────────────► │ Target MCP Server│
│ (Claude) │                    │   Firewall       │                    │ (e.g. Stripe)    │
└──────────┘                    └──────────────────┘                    └──────────────────┘
                                        │
                                   Policy Engine
                                  ┌───────────────┐
                                  │ Allow? Block? │
                                  │ Generate OTP  │
                                  └───────────────┘
```

MCP servers don't run like web servers — there's no background process on a port. Instead, your AI agent (Claude, Cursor, etc.) **spawns the MCP server as a subprocess** and talks to it over stdin/stdout. When the chat ends, the process dies.

The firewall inserts itself into that chain:

```
Without firewall:
  Claude ──spawns──► mcp-server-stripe

With firewall:
  Claude ──spawns──► mcp-action-firewall ──spawns──► mcp-server-stripe
```

So you just **replace the server command** in your MCP client config with the firewall, and tell the firewall what the original command was:

**Before** (direct):
```json
{ "command": "uvx", "args": ["mcp-server-stripe", "--api-key", "sk_test_..."] }
```

**After** (wrapped with firewall):
```json
{ "command": "uv", "args": ["run", "mcp-action-firewall", "--target", "mcp-server-stripe --api-key sk_test_..."] }
```

Then the firewall applies your security policy:

1. ✅ **Safe calls** (e.g. `get_balance`) → forwarded immediately
2. 🛑 **Dangerous calls** (e.g. `delete_user`) → blocked, OTP generated
3. 🔑 Agent asks user for the code → user replies → agent calls `firewall_confirm` → original action executes

## Installation

```bash
pip install mcp-action-firewall
# or
uvx mcp-action-firewall --help
```

## Quick Start — MCP Client Configuration

Add the firewall as a wrapper around any MCP server in your client config:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "uv",
      "args": ["run", "mcp-action-firewall", "--target", "mcp-server-stripe --api-key sk_test_abc123"]
    }
  }
}
```

That's it. Everything after `--target` is the **full shell command** to launch the real MCP server — including its own flags like `--api-key`. The firewall doesn't touch those args, it just spawns the target and sits in front of it.

### More Examples

<details>
<summary>Claude Desktop with per-server rules</summary>

```json
{
  "mcpServers": {
    "stripe": {
      "command": "uv",
      "args": [
        "run", "mcp-action-firewall",
        "--target", "uvx mcp-server-stripe --api-key sk_test_...",
        "--name", "stripe"
      ]
    },
    "database": {
      "command": "uv",
      "args": [
        "run", "mcp-action-firewall",
        "--target", "uvx mcp-server-postgres --connection-string postgresql://...",
        "--name", "database",
        "--config", "/path/to/my/firewall_config.json"
      ]
    }
  }
}
```
</details>

<details>
<summary>Cursor / Other MCP Clients</summary>

```json
{
  "mcpServers": {
    "github": {
      "command": "uvx",
      "args": [
        "mcp-action-firewall",
        "--target", "npx @modelcontextprotocol/server-github"
      ]
    }
  }
}
```
</details>

## The OTP Flow

When the agent tries to call a blocked tool, the firewall returns a structured response:

```json
{
  "status": "PAUSED_FOR_APPROVAL",
  "message": "⚠️ The action 'delete_user' is HIGH RISK and has been locked by the Action Firewall.",
  "action": {
    "tool": "delete_user",
    "arguments": { "id": 42 }
  },
  "instruction": "To unlock this action, you MUST ask the user for authorization.\n\n1. Show the user the following and ask for approval:\n   Tool: **delete_user**\n   Arguments:\n{\"id\": 42}\n\n2. Tell the user: 'Please reply with approval code: **9942**' to allow this action, or say no to cancel.\n3. STOP and wait for their reply.\n4. When they reply with '9942', call the 'firewall_confirm' tool with that code.\n5. If they say no or give a different code, do NOT retry."
}
```

> **Argument visibility guarantee:** The arguments shown to the user are frozen at interception time — they are taken from the original blocked call, not from what the agent passes to `firewall_confirm`. The agent cannot change the arguments after the OTP is issued.

The `firewall_confirm` tool is automatically injected into the server's tool list:

```json
{
  "name": "firewall_confirm",
  "description": "Call this tool ONLY when the user provides the correct 4-digit approval code to confirm a paused action.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "otp": {
        "type": "string",
        "description": "The 4-digit code provided by the user."
      }
    },
    "required": ["otp"]
  }
}
```

## Configuration

The firewall ships with sensible defaults. Override with `--config`:

```json
{
  "global": {
    "allow_prefixes": ["get_", "list_", "read_", "fetch_"],
    "block_keywords": ["delete", "update", "create", "pay", "send", "transfer", "drop", "remove", "refund"],
    "default_action": "block",
    "otp_attempt_count": 1
  },
  "servers": {
    "stripe": {
      "allow_prefixes": [],
      "block_keywords": ["refund", "charge"],
      "default_action": "block"
    },
    "database": {
      "allow_prefixes": ["select_"],
      "block_keywords": ["drop", "truncate", "alter"],
      "default_action": "block"
    }
  }
}
```

**Rule evaluation order:**
1. Tool name starts with an allow prefix → **ALLOW**
2. Tool name contains a block keyword → **BLOCK** (OTP required)
3. No match → fallback to `default_action`

**`otp_attempt_count`** — maximum number of failed OTP attempts before the pending action is permanently locked out. Defaults to `1` (any wrong code cancels the request). Increase for more forgiving UX, keep at `1` for maximum security.

**Per-server rules** extend (not replace) the global rules. Use `--name stripe` to activate server-specific overrides.

## CLI Reference

### `--target` (required)
The full command to launch the real MCP server. This is the server you want to protect:
```bash
mcp-action-firewall --target "mcp-server-stripe --api-key sk_test_abc123"
mcp-action-firewall --target "npx @modelcontextprotocol/server-github"
mcp-action-firewall --target "uvx mcp-server-postgres --connection-string postgresql://localhost/mydb"
```

### `--name` (optional)
Activates per-server rules from your config. Without it, only global rules apply:
```bash
mcp-action-firewall --target "mcp-server-stripe" --name stripe
```

### `--config` (optional)
Custom config file path. Without it, uses `firewall_config.json` in your current directory, or the bundled defaults:
```bash
mcp-action-firewall --target "mcp-server-stripe" --config /path/to/my_rules.json
```

### `-v` / `--verbose` (optional)
Turns on debug logging (written to stderr, won't interfere with MCP traffic):
```bash
mcp-action-firewall --target "mcp-server-stripe" -v
```

## Project Structure

```
src/mcp_action_firewall/
├── __init__.py          # Package version
├── __main__.py          # python -m support
├── server.py            # CLI entry point
├── proxy.py             # JSON-RPC stdio proxy
├── policy.py            # Allow/block rule engine
├── state.py             # OTP store with TTL
└── default_config.json  # Bundled default rules
```
## Try It — Interactive Demo

See the firewall in action without any setup:

```bash
git clone https://github.com/starskrime/mcp-action-firewall.git
cd mcp-action-firewall
uv sync
uv run python demo.py
```

The demo simulates an AI agent and walks you through the full OTP flow:

1. ✅ **Safe call** (`get_balance`) → passes through instantly
2. 🛑 **Dangerous call** (`delete_user`) → blocked, OTP generated
3. 🔑 **You enter the code** → action executes after approval

## Known Limitations

### Argument Inspection

The firewall matches on **tool names only**, not argument values. This means a tool like `get_data({"sql": "DROP TABLE users"})` would pass if `get_` is in your allow list, because the policy engine only sees `get_data`.

**Workaround:** Use explicit tool names in your allow/block lists and set `"default_action": "block"` so unrecognized tools require approval.

> 🚧 **Roadmap:** Argument-level inspection (scanning argument values against `block_keywords`) is planned for a future release.

## Development

```bash
# Install dev dependencies
uv sync

# Run tests
uv run pytest tests/ -v

# Run the firewall locally
uv run mcp-action-firewall --target "your-server-command" -v
```

## License

MIT
