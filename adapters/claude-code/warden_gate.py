#!/usr/bin/env python3
"""PreToolUse gate: mediate Claude Code tool calls through the warden broker.

Maps Read/Write/Edit/NotebookEdit to an `fs:read`/`fs:write` request and Bash to
one `exec <program>` request per program in the command line, asks the broker for
a decision (warm daemon first, one-shot CLI fallback), and in enforce mode blocks
a denied call (exit 2). Dry mode logs but never blocks.

The fs class is governed by WARDEN_GATE_MODE; the exec class is governed by its
own WARDEN_EXEC_MODE (dry|enforce|off, default dry) so exec can ride observe-only
while fs enforces.

Hook contract (PreToolUse): stdin = {session_id, tool_name, tool_input, cwd};
exit 0 = allow, exit 2 = block with stderr shown to Claude.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MODE = (os.environ.get("WARDEN_GATE_MODE") or "dry").lower()
# Exec gating ramps independently of fs. Default dry: audit every program but
# never block, so the allowlist can be built from real usage before flipping.
EXEC_MODE = (os.environ.get("WARDEN_EXEC_MODE") or "dry").lower()
# Redirect (fs-via-shell) gating ramps independently too. A program can be
# exec-allowed yet still write a denied path via `cmd > /protected` -- the exec
# gate sees `cmd`, never the file. This closes that fs:write hole. Default dry so
# the fs:write/read allowlist for redirect targets is built from real usage
# before flipping to enforce (WARDEN_GATE_MODE governs the Write/Edit tools; this
# governs the same boundary reached through a shell redirection).
REDIRECT_MODE = (os.environ.get("WARDEN_REDIRECT_MODE") or "dry").lower()
SOCK = os.environ.get("WARDEN_SOCK", "/tmp/warden_daemon.sock")
BIN = os.environ.get(
    "WARDEN_BIN",
    # install.sh installs the binary here; override with WARDEN_BIN if you build
    # elsewhere (e.g. point at target/release/warden in a dev checkout).
    os.path.expanduser("~/.warden/bin/warden"),
)
POLICY = os.environ.get("WARDEN_POLICY", os.path.expanduser("~/.warden/policy.tsv"))
MANIFESTS = os.environ.get("WARDEN_MANIFESTS", os.path.expanduser("~/.warden/manifests"))
AUDIT = os.environ.get("WARDEN_AUDIT", os.path.expanduser("~/.warden/audit.jsonl"))
STATE_DIR = Path(os.environ.get("WARDEN_STATE_DIR", str(Path.home() / ".claude" / "hooks" / "state")))
LOG_FILE = STATE_DIR / "warden-gate.log"
TIMEOUT = 4.0

# tool_name -> (capability class, tool_input key holding the path)
TOOL_MAP = {
    "Read": ("fs:read", "file_path"),
    "Write": ("fs:write", "file_path"),
    "Edit": ("fs:write", "file_path"),
    "NotebookEdit": ("fs:write", "notebook_path"),
}


def _log(entry: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        entry["ts"] = datetime.now(timezone.utc).isoformat()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def _notify(message: str) -> None:
    """Best-effort desktop banner when enforce mode blocks a call. Must never
    affect the gate decision: failures are swallowed and we don't wait on the
    osascript process. WARDEN_GATE_NOTIFY=0 disables."""
    if (os.environ.get("WARDEN_GATE_NOTIFY") or "1").lower() in ("0", "false"):
        return
    try:
        escaped = message.replace("\\", "\\\\").replace('"', '\\"')
        subprocess.Popen(
            ["osascript", "-e",
             f'display notification "{escaped}" with title "Warden blocked"'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _abs(path: str, cwd: str | None) -> str:
    p = Path(path)
    if not p.is_absolute() and cwd:
        p = Path(cwd) / p
    # Lexical normalization only — the broker matches paths lexically and does
    # NOT resolve symlinks (its documented v1 contract). Resolving here (e.g.
    # /tmp -> /private/tmp on macOS) would disagree with the broker and wrongly
    # deny granted paths. os.path.normpath collapses '.'/'..' without touching
    # the filesystem.
    return os.path.normpath(str(p))


def _principal(session_id: str) -> str:
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_")[:64] or "unknown"
    path = STATE_DIR / f"active-skill-{safe}.json"
    try:
        stack = json.loads(path.read_text())
        if isinstance(stack, list) and stack:
            return str(stack[-1])
    except (OSError, json.JSONDecodeError):
        pass
    return "claude-code-main"


def _decide_via_daemon(req_line: str) -> dict | None:
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect(SOCK)
        sock.sendall(req_line.encode())
        data = b""
        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return json.loads(data.split(b"\n")[0])
    except Exception:
        return None
    finally:
        if sock is not None:
            sock.close()


def _decide_via_cli(req_line: str) -> dict | None:
    if not os.path.isfile(BIN):
        return None
    try:
        proc = subprocess.run(
            [BIN, "serve", "--stdio", "--policy", POLICY, "--manifests", MANIFESTS,
             "--audit", AUDIT, "--non-interactive"],
            input=req_line, capture_output=True, text=True, timeout=TIMEOUT + 2,
        )
        if proc.returncode != 0 or not proc.stdout:
            return None
        return json.loads(proc.stdout.splitlines()[0])
    except Exception:
        return None


def decide(principal: str, capability: str, target: str) -> dict | None:
    req_line = json.dumps({
        "skill": principal, "capability": capability,
        "target": target, "decide_only": True,
    }) + "\n"
    return _decide_via_daemon(req_line) or _decide_via_cli(req_line)


# Programs that merely wrap and then exec another program; the program we care
# about is the wrapped one. We skip the wrapper, its option flags, and any
# NAME=value it carries, then take the next bare token.
WRAPPERS = {
    "sudo", "doas", "env", "nohup", "time", "nice", "ionice", "stdbuf",
    "setsid", "command", "builtin", "exec", "xargs",
    "proxychains", "proxychains4", "unbuffer",
}

# Shell reserved words that introduce a command list: skip the keyword, the real
# command follows in the same segment (`while read x`, `if grep -q ...`).
_SKIP_TOKEN = {
    "while", "until", "if", "elif", "then", "else", "do", "done", "fi",
    "esac", "in", "!", "{", "}", "time", "coproc",
}
# Reserved words whose segment is a header with NO command (var/list/pattern);
# the body runs in a later `do ...` / `) ...` segment we handle separately.
# Also pure shell builtins that exec no external program — gating them (or their
# file/arg) is meaningless, and they were the residual audit junk (set/export/
# source/break/etc.); the whole segment yields no gated program.
_SKIP_SEGMENT = {
    "for", "select", "case",
    "set", "export", "unset", "local", "declare", "readonly", "alias",
    "source", ".", ":", "break", "continue", "return", "shift", "read", "trap",
}

# Operator tokens that separate one simple command from the next, so each stage
# of a pipe or &&-chain (and each `;`-joined command) is checked independently.
_SEPARATORS = {";", "&", "|", "||", "&&", ";;", "|&", "(", ")"}

# A token made only of shell operator characters (`>`, `>>`, `2>`, `<<`, `>&`,
# `&>`, `2>&1` fragments, etc.) — a redirection, never a program.
_OPERATOR_ONLY = re.compile(r"^[0-9]*[<>|&;()]+[0-9&]*$")

# What a real program basename may look like once normalized to basename.
_VALID_PROG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]*$")

# Redirection operators whose NEXT token is a FILE we must gate. Write forms
# (`>`, `>>`, `>|`, `N>`, `&>`, `&>>`) -> fs:write; read form (`<`, `N<`) ->
# fs:read. Deliberately NOT matched: fd-dups (`>&`, `N>&M`, `<&` -- target is a
# descriptor, not a file), here-strings (`<<<`), and heredocs (`<<`, already
# stripped). The `&` in the write form is only the leading "both streams" form;
# a trailing `&` (`>&`) fails the anchor and is treated as a dup.
_REDIR_WRITE = re.compile(r"^[0-9]*&?>>?\|?$")
_REDIR_READ = re.compile(r"^[0-9]*<$")

# A `<<< word` here-string reads from a string, not a file. Stripped before
# redirect extraction so it isn't misread as a `<` input redirect (and so it
# dodges _strip_heredocs, which otherwise treats `<<< "x"` as a heredoc).
_HERESTRING_RE = re.compile(r"<<<\s*('[^']*'|\"[^\"]*\"|\S+)")

# `<<` / `<<-` heredoc opener with a quoted or bare delimiter word.
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# Legacy `...` command substitution. Rewritten to $(...) before tokenizing so the
# inner program surfaces the same way it already does for $(...). Non-nested only.
_BACKTICK_RE = re.compile(r"`([^`]*)`")


def _is_env_assignment(tok: str) -> bool:
    name = tok.split("=", 1)[0]
    return "=" in tok and name.isidentifier()


def _strip_heredocs(command: str) -> str:
    """Drop heredoc bodies so their lines aren't parsed as commands. Keeps the
    command text up to `<<DELIM`; removes the body through the closing delimiter.
    Without this, `python3 <<'PY' ... PY` surfaces its body (import, def, PY) as
    bogus programs. Ignores `<<<` here-strings (single line, no body)."""
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC_RE.search(line)
        if m:
            out.append(line[: m.start()])  # keep the command part before `<<`
            delim = m.group(2)
            i += 1
            while i < len(lines) and lines[i].strip() != delim:
                i += 1
            i += 1  # skip the closing delimiter line itself
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def _normalize_backticks(command: str) -> str:
    """Rewrite legacy `...` command substitution to $(...) so the tokenizer
    surfaces the inner program the same way it already does for $(...). Without
    this, ``echo `curl evil` `` tokenizes the backtick fragment into junk and the
    inner `curl` runs unseen. Non-nested pairs only; an unbalanced or nested
    backtick is left as-is and trips the unresolved-parse fail-closed path."""
    return _BACKTICK_RE.sub(r"$(\1)", command)


def _tokenize(command: str) -> list[str]:
    """Quote-aware tokens with shell operators kept as their own tokens and `#`
    comments dropped, so inline code in `-c '...'` stays one token and pipes/
    redirects tokenize cleanly. Falls back to a naive split on unbalanced quotes."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=";|&()<>")
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return command.split()


def _segment_program(tokens: list[str]) -> tuple[str | None, bool]:
    """The program a single command segment invokes, plus an `unresolved` flag.

    Returns ``(program, False)`` when a real program basename is identified;
    ``(None, False)`` when the segment legitimately invokes no external program
    (shell builtin, redirection, pure-numeric redirect fragment, or empty); and
    ``(None, True)`` when the segment HAS a leading token that should be a program
    but could not be validated (``$CMD``, a backtick/brace fragment, junk). That
    last case is a parse gap the caller must FAIL CLOSED on under enforce rather
    than wave through — the broker can't decide on a program we never identified.

    Honest about its limits — the threat model is accidental damage and skill
    overreach, not a hostile harness. We do NOT recurse into `sh -c '...'` or an
    allowlisted interpreter; a command that hides its real program that way gates
    on the visible wrapper (`sh`, `bash`), which is the correct allowlist subject.
    True containment is the deferred sandbox/forwarder path."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        base = os.path.basename(tok)
        if base in _SKIP_SEGMENT:  # `for`/`select`/`case` header, no command here
            return None, False
        if base in _SKIP_TOKEN:  # control keyword; the command follows
            i += 1
            continue
        if _is_env_assignment(tok):  # leading FOO=bar prefix
            i += 1
            continue
        if base == "timeout":  # wraps a program but takes OPTIONS + a DURATION first
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                opt = tokens[i]
                i += 1
                if opt in ("-s", "--signal", "-k", "--kill-after") and i < len(tokens):
                    i += 1  # this option consumes the next token as its argument
            if i < len(tokens):
                i += 1  # skip the DURATION positional; the program follows
            continue
        if base in WRAPPERS:
            i += 1  # skip the wrapper itself
            while i < len(tokens) and (
                tokens[i].startswith("-") or _is_env_assignment(tokens[i])
            ):
                i += 1  # ...and its flags / carried env
            continue
        if _OPERATOR_ONLY.match(tok):  # redirection — skip the operator and target
            i += 2
            continue
        # Normalize to basename so an `exec git` grant matches `git`,
        # `/usr/bin/git`, and `./git` alike.
        if _VALID_PROG.match(base) and not base.isdigit():
            return base, False
        # A bare integer is a redirect/arith fragment leak (`2` from `2>&1`),
        # benign noise — not a program and not a parse gap.
        if base.isdigit():
            return None, False
        # A non-empty leader we could not reduce to a clean program basename
        # ($-indirected, backtick/brace fragment, quote junk). Fail closed.
        return None, True
    return None, False


def _extract_programs(command: str) -> tuple[list[str], int]:
    """Every distinct program a Bash command line invokes (first-seen order), plus
    a count of segments with an UNRESOLVED leader (parse gaps the caller fails
    closed on under enforce).

    Strips heredoc bodies, rewrites backtick substitution, tokenizes quote-aware,
    then splits on operator tokens and gates the leading program of each segment.
    This keeps heredocs, `-c` inline code, comments, and shell keywords from
    surfacing as bogus programs while still checking every pipeline/`&&`/`;` stage
    independently."""
    tokens = _tokenize(_normalize_backticks(_strip_heredocs(command)))
    programs: list[str] = []
    unresolved = 0
    segment: list[str] = []
    for tok in tokens + [";"]:  # sentinel flushes the final segment
        if tok in _SEPARATORS:
            prog, unres = _segment_program(segment)
            if prog and prog not in programs:
                programs.append(prog)
            if unres:
                unresolved += 1
            segment = []
        else:
            segment.append(tok)
    return programs, unresolved


def _extract_redirects(command: str) -> tuple[list[tuple[str, str]], int]:
    """File targets of shell redirections as (capability, raw_target) pairs:
    `> f`/`>> f`/`&> f` -> ('fs:write', f); `< f` -> ('fs:read', f). Skips
    fd-dups (`>&2`, `2>&1`), here-strings (`<<<`), and heredocs (stripped). The
    second value counts write/read redirects whose target is missing or
    indirected ($VAR, brace/backtick) and so cannot be resolved to a concrete
    path -- the caller fails closed on those under enforce, mirroring the exec
    path's unresolved handling. Same tokenizer as _extract_programs so heredocs,
    backticks and quoting are handled identically."""
    tokens = _tokenize(_normalize_backticks(_strip_heredocs(_HERESTRING_RE.sub(" ", command))))
    out: list[tuple[str, str]] = []
    unresolved = 0
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        cap = "fs:write" if _REDIR_WRITE.match(tok) else (
            "fs:read" if _REDIR_READ.match(tok) else None
        )
        if cap is None:
            i += 1
            continue
        tgt = tokens[i + 1] if i + 1 < n else None
        i += 2
        if tgt is None or tgt in _SEPARATORS or _OPERATOR_ONLY.match(tgt):
            unresolved += 1  # malformed redirect: no concrete file target
        elif tgt.startswith("&"):
            continue  # `>& 2` style fd-dup target, not a file
        elif "$" in tgt or "`" in tgt or "{" in tgt:
            unresolved += 1  # $-indirected / brace / subshell path -> fail closed
        else:
            out.append((cap, tgt))
    return out, unresolved


def _gate_exec(command: str, principal: str) -> bool:
    """Ask the broker for an `exec <program>` decision per invoked program.
    Governed by WARDEN_EXEC_MODE: off → pass; dry → audit only; enforce → block.
    Returns True if the call must be blocked (enforce + a denied / unreachable /
    unparseable program)."""
    if EXEC_MODE == "off":
        return False
    programs, unresolved = _extract_programs(command)
    if unresolved:
        # A non-empty segment we could not reduce to a program ($-indirected,
        # backtick/brace junk). Recorded in every mode so the gap is visible;
        # under enforce it fails closed below.
        _log({"principal": principal, "capability": "exec", "target": "",
              "mode": EXEC_MODE, "event": "exec_unresolved",
              "unresolved": unresolved, "command": command[:200]})
    if not programs and not unresolved:
        # Legitimately no external program: pure builtin (`export`, `:`) or a
        # parse shape that reduced cleanly to nothing. Audit and allow.
        _log({"principal": principal, "capability": "exec", "target": "",
              "mode": EXEC_MODE, "event": "exec_no_program",
              "command": command[:200]})
        return False

    denied: list[tuple[str, str]] = []
    unreachable: list[str] = []
    for prog in programs:
        resp = decide(principal, "exec", prog)
        base = {"principal": principal, "capability": "exec",
                "target": prog, "mode": EXEC_MODE}
        if resp is None:
            # Carry the raw command on the blocking records (deny/unreachable)
            # so an audit can reconstruct intent — the program token alone
            # loses context (e.g. `check` from a subcommand, a launchd label,
            # a typo'd path). Allows stay lean and omit it.
            _log({**base, "event": "broker_unreachable", "command": command[:200]})
            unreachable.append(prog)
            continue
        decision = resp.get("decision")
        reason = resp.get("reason", "")
        entry = {**base, "event": "decision", "decision": decision, "reason": reason}
        if decision == "deny":
            entry["command"] = command[:200]
            denied.append((prog, reason))
        _log(entry)

    if EXEC_MODE != "enforce":
        return False  # dry: audit only, never block

    if unresolved:
        # We could not identify the program(s) this command runs, so we never
        # got a broker decision. Fail closed, mirroring broker-unreachable —
        # "couldn't decide" must not silently mean "allow" under enforce.
        print(f"warden: unparseable command segment, failing closed for '{principal}'",
              file=sys.stderr)
        _notify(f"unparseable exec ({principal})")
        return True
    if unreachable:
        names = ", ".join(unreachable)
        print(f"warden: broker unreachable, failing closed for exec {names}",
              file=sys.stderr)
        _notify(f"broker unreachable: exec {unreachable[0]}")
        return True
    if denied:
        names = ", ".join(p for p, _ in denied)
        print(f"warden: blocked exec {names} for '{principal}'", file=sys.stderr)
        _notify(f"exec {names} ({principal})")
        return True
    return False


def _gate_redirects(command: str, principal: str, cwd: str | None) -> bool:
    """Gate the FILE targets of shell redirections as fs:write / fs:read,
    governed by WARDEN_REDIRECT_MODE. This is the same boundary the Write/Edit/
    Read tools cross, reached through a shell redirection instead: `cmd > file`
    is an fs:write to `file` even when `cmd` is exec-allowed. Returns True if the
    call must be blocked (enforce + a denied / unreachable / unresolved target)."""
    if REDIRECT_MODE == "off":
        return False
    redirects, unresolved = _extract_redirects(command)
    if unresolved:
        _log({"principal": principal, "capability": "fs", "target": "",
              "mode": REDIRECT_MODE, "via": "redirect", "event": "redirect_unresolved",
              "unresolved": unresolved, "command": command[:200]})
    denied: list[str] = []
    unreachable: list[str] = []
    for cap, raw in redirects:
        target = _abs(os.path.expanduser(raw), cwd)
        resp = decide(principal, cap, target)
        base = {"principal": principal, "capability": cap, "target": target,
                "mode": REDIRECT_MODE, "via": "redirect"}
        if resp is None:
            _log({**base, "event": "broker_unreachable", "command": command[:200]})
            unreachable.append(f"{cap} {target}")
            continue
        decision = resp.get("decision")
        reason = resp.get("reason", "")
        entry = {**base, "event": "decision", "decision": decision, "reason": reason}
        if decision == "deny":
            entry["command"] = command[:200]
            denied.append(f"{cap} {target}")
        _log(entry)

    if REDIRECT_MODE != "enforce":
        return False  # dry: audit only, never block

    if unresolved:
        print(f"warden: unresolved redirect target, failing closed for '{principal}'",
              file=sys.stderr)
        _notify(f"unresolved redirect ({principal})")
        return True
    if unreachable:
        print(f"warden: broker unreachable, failing closed for {unreachable[0]}",
              file=sys.stderr)
        _notify(f"broker unreachable: {unreachable[0]}")
        return True
    if denied:
        print(f"warden: blocked {', '.join(denied)} for '{principal}'", file=sys.stderr)
        _notify(f"{denied[0]} ({principal})")
        return True
    return False


def _handle_bash(tool_input: dict, principal: str, cwd: str | None = None) -> int:
    """Gate a Bash call on two independent boundaries: the programs it execs
    (WARDEN_EXEC_MODE) and the files it writes/reads via shell redirection
    (WARDEN_REDIRECT_MODE — the fs:write boundary a bare `> file` would otherwise
    slip past). Either boundary blocks (exit 2) under its own enforce; internal
    errors fail closed only if either boundary is enforcing."""
    try:
        if EXEC_MODE == "off" and REDIRECT_MODE == "off":
            return 0
        command = tool_input.get("command")
        if not command or not isinstance(command, str):
            return 0
        block = _gate_exec(command, principal)
        block = _gate_redirects(command, principal, cwd) or block
        return 2 if block else 0
    except Exception:
        # Contain gate bugs to Bash semantics: never brick Bash while observing
        # in dry, but honor fail-closed under either enforcing boundary.
        if EXEC_MODE == "enforce" or REDIRECT_MODE == "enforce":
            print("warden: unexpected gate error, failing closed", file=sys.stderr)
            return 2
        return 0


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0

    tool_name = payload.get("tool_name")
    if tool_name == "Bash":
        principal = _principal(payload.get("session_id") or "unknown")
        return _handle_bash(payload.get("tool_input") or {}, principal, payload.get("cwd"))

    mapping = TOOL_MAP.get(tool_name)
    if not mapping:
        return 0  # untracked tool: pass through
    capability, key = mapping
    tool_input = payload.get("tool_input") or {}
    raw = tool_input.get(key)
    if not raw:
        return 0  # nothing to gate
    target = _abs(raw, payload.get("cwd"))
    principal = _principal(payload.get("session_id") or "unknown")

    resp = decide(principal, capability, target)
    base = {"principal": principal, "capability": capability, "target": target, "mode": MODE}

    if resp is None:
        _log({**base, "event": "broker_unreachable"})
        if MODE == "enforce":
            print(f"warden: broker unreachable, failing closed for {capability} {target}",
                  file=sys.stderr)
            _notify(f"broker unreachable: {capability} {target}")
            return 2
        return 0

    decision = resp.get("decision")
    reason = resp.get("reason", "")
    _log({**base, "event": "decision", "decision": decision, "reason": reason})

    if decision == "deny" and MODE == "enforce":
        print(f"warden: blocked {capability} {target} for '{principal}' ({reason})",
              file=sys.stderr)
        _notify(f"{capability} {target} ({principal})")
        return 2
    return 0  # allow, or dry-mode would-block


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # A hook bug must not brick Claude Code in dry mode, but enforce mode's
        # security contract requires failing closed when we cannot decide. Re-read
        # the env var directly (the module-level MODE may be unset if the error
        # occurred during module initialization).
        if (os.environ.get("WARDEN_GATE_MODE") or "dry").lower() == "enforce":
            print("warden: unexpected gate error, failing closed", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)  # dry mode: never break the tool chain on our account
