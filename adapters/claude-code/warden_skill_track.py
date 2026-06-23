#!/usr/bin/env python3
"""Track the active Claude Code skill for warden principal attribution.

Registered twice in settings.json:
    PreToolUse(Skill)  -> `warden_skill_track.py push`  (push the invoked skill)
    PostToolUse(Skill) -> `warden_skill_track.py pop`   (pop on completion)

State: $WARDEN_STATE_DIR/active-skill-<session_id>.json  = ["skillA", "skillB"]
The last element is the currently-active skill. Best-effort across nesting and
subagents; never blocks (always exit 0).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

STATE_DIR = Path(os.environ.get("WARDEN_STATE_DIR", str(Path.home() / ".claude" / "hooks" / "state")))


def _stack_path(session_id: str) -> Path:
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_")[:64] or "unknown"
    return STATE_DIR / f"active-skill-{safe}.json"


def _load(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save(path: Path, stack: list[str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(stack))
    tmp.replace(path)


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0
    if payload.get("tool_name") != "Skill":
        return 0
    session_id = payload.get("session_id") or "unknown"
    path = _stack_path(session_id)
    stack = _load(path)

    if action == "push":
        skill = (payload.get("tool_input") or {}).get("skill")
        if skill:
            stack.append(skill)
            _save(path, stack)
    elif action == "pop":
        if stack:
            stack.pop()
            _save(path, stack)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
