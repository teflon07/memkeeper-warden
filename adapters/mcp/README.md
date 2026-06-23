# warden-mcp

An MCP bridge that exposes the warden capability broker to MCP-capable agents
(Claude Code, Cursor, and others).

## Install

```sh
# From this directory
uvx --from . warden-mcp        # or: pip install . && warden-mcp
```

Requires the `warden` binary on `PATH` (build it from the repo root with
`cargo build --release`).

## Configure (Claude Code / Cursor)

Add an MCP server entry pointing at `warden-mcp`:

```json
{
  "mcpServers": {
    "warden": { "command": "warden-mcp" }
  }
}
```

The bridge connects to a **running warden daemon** over a Unix socket, so install
and load the daemon first (see `adapters/claude-code/README.md`). It connects to
`WARDEN_SOCK` (default `/tmp/warden_daemon.sock`) — the same socket the Claude
Code gate's daemon serves on. Override `WARDEN_SOCK` if you run the daemon
elsewhere:

```json
{
  "mcpServers": {
    "warden": {
      "command": "warden-mcp",
      "env": { "WARDEN_SOCK": "/tmp/warden_daemon.sock" }
    }
  }
}
```

The bridge brokers capability requests against your warden policy and returns
allow/deny decisions; it performs no network or LLM calls.
