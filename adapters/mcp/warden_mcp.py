"""FastMCP bridge to the warden broker socket.

Mirrors scripts/memkeeper_mcp.py: validates input bounds, frames one JSON request
line, sends it over the warden Unix socket, and returns the parsed response.
Every tool call a harness makes is mediated by the broker on the other end.
"""

import json
import os
import socket

from mcp.server.fastmcp import FastMCP

MAX_TARGET_BYTES = 4096
MAX_SKILL_BYTES = 256
KNOWN_CLASSES = {
    "fs:read", "fs:write", "net", "exec",
    "memory:read", "memory:write", "secrets",
}

# Connect to the socket the Claude Code gate's daemon actually serves on. The
# gate and launchd daemon use WARDEN_SOCK -> /tmp/warden_daemon.sock (see
# adapters/claude-code/warden_gate.py); match them so the bridge connects
# out of the box.
WARDEN_SOCK = os.environ.get("WARDEN_SOCK", "/tmp/warden_daemon.sock")

mcp = FastMCP("warden")


def build_request_line(skill: str, capability: str, target: str) -> str:
    """Validate inputs and build one flat JSON request line."""
    if not skill or len(skill.encode()) > MAX_SKILL_BYTES:
        raise ValueError("skill missing or too long")
    if capability not in KNOWN_CLASSES:
        raise ValueError(f"unknown capability class: {capability}")
    if len(target.encode()) > MAX_TARGET_BYTES:
        raise ValueError("target too long")
    return json.dumps({"skill": skill, "capability": capability, "target": target})


def parse_response(line: str) -> dict:
    """Parse a broker response line into a dict."""
    obj = json.loads(line)
    if "decision" not in obj:
        raise ValueError("response missing decision")
    return obj


def _roundtrip(line: str) -> str:
    """Send one request line to the warden socket and read one response line."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(WARDEN_SOCK)
        s.sendall((line + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf.decode().strip()


def _request(skill: str, capability: str, target: str) -> dict:
    line = build_request_line(skill, capability, target)
    return parse_response(_roundtrip(line))


@mcp.tool()
def warden_fs_read(skill: str, path: str) -> dict:
    """Read a file through the broker. Denied unless the skill is granted fs:read for it."""
    return _request(skill, "fs:read", path)


@mcp.tool()
def warden_check(skill: str, capability: str, target: str) -> dict:
    """Ask the broker for an allow/deny decision on any capability+target (no side effect)."""
    return _request(skill, capability, target)


if __name__ == "__main__":
    mcp.run()
