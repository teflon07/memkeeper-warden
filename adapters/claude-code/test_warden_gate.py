"""Tests for the warden Claude Code gate. Builds the warden binary once, then
drives warden_gate.py via the one-shot CLI fallback against temp policy/manifest.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "warden_gate.py"
TRACK = HERE / "warden_skill_track.py"
MEMKEEPER = HERE.parent.parent  # memory/memkeeper
BIN = MEMKEEPER / "target" / "debug" / "warden"


def setup_module(_):
    subprocess.run(["cargo", "build", "-p", "warden-cli"], cwd=MEMKEEPER, check=True)


def _env(tmp_path, mode, exec_mode=None, extra_policy=""):
    policy = tmp_path / "policy.tsv"
    policy.write_text(
        "claude-code-main\tfs:read\t/tmp\tallow\n"
        "claude-code-main\tfs:write\t/tmp\tallow\n"
        "warden-selftest\tfs:read\t/tmp/allowed\tallow\n"
        + extra_policy
    )
    manifests = tmp_path / "manifests" / "warden-selftest"
    manifests.mkdir(parents=True)
    (manifests / "SKILL.md").write_text(
        "---\nname: warden-selftest\ncapabilities:\n  - fs:read /tmp/allowed\n---\nbody\n"
    )
    state = tmp_path / "state"
    state.mkdir()
    env = dict(os.environ)
    env.update({
        "WARDEN_GATE_MODE": mode,
        "WARDEN_GATE_NOTIFY": "0",  # tests must not pop real desktop banners
        "WARDEN_SOCK": str(tmp_path / "nonexistent.sock"),  # force CLI fallback
        "WARDEN_BIN": str(BIN),
        "WARDEN_POLICY": str(policy),
        "WARDEN_MANIFESTS": str(tmp_path / "manifests"),
        "WARDEN_AUDIT": str(tmp_path / "audit.jsonl"),
        "WARDEN_STATE_DIR": str(state),
    })
    if exec_mode is not None:
        env["WARDEN_EXEC_MODE"] = exec_mode
    else:
        # Hermetic: "unset" must mean unset in the subprocess, not whatever the
        # maintainer happens to export. Otherwise a shell with WARDEN_EXEC_MODE
        # set leaks in and the "defaults to dry" contract can't be tested.
        env.pop("WARDEN_EXEC_MODE", None)
    return env, state


def _fake_osascript(tmp_path, env):
    """Shadow osascript with a script that logs its args, and enable notify."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "notify.log"
    fake = bindir / "osascript"
    fake.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n')
    fake.chmod(0o755)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["WARDEN_GATE_NOTIFY"] = "1"
    return log


def _wait_for(path, timeout=3.0):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return False


def _run_gate(env, payload):
    return subprocess.run([sys.executable, str(GATE)], input=json.dumps(payload),
                          capture_output=True, text=True, env=env)


def test_untracked_tool_passes(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    r = _run_gate(env, {"tool_name": "Grep", "tool_input": {"pattern": "x"}, "session_id": "s"})
    assert r.returncode == 0


def test_main_loop_allowed_path(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"},
                        "session_id": "s"})
    assert r.returncode == 0


def test_main_loop_denied_path_blocks_in_enforce(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"},
                        "session_id": "s"})
    assert r.returncode == 2
    assert "warden: blocked" in r.stderr


def test_dry_mode_never_blocks(tmp_path):
    env, _ = _env(tmp_path, "dry")
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"},
                        "session_id": "s"})
    assert r.returncode == 0


def test_skill_manifest_blocks_undeclared_write(tmp_path):
    # warden-selftest declares only fs:read /tmp/allowed; a write is undeclared.
    env, state = _env(tmp_path, "enforce")
    subprocess.run([sys.executable, str(TRACK), "push"],
                   input=json.dumps({"tool_name": "Skill",
                                     "tool_input": {"skill": "warden-selftest"},
                                     "session_id": "s"}),
                   text=True, env=env, check=True)
    r = _run_gate(env, {"tool_name": "Write", "tool_input": {"file_path": "/tmp/allowed/x"},
                        "session_id": "s"})
    assert r.returncode == 2
    assert "manifest: undeclared" in r.stderr


def test_broker_unreachable_fails_closed_in_enforce(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    env["WARDEN_BIN"] = "/nonexistent/warden"  # disable CLI fallback too
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"},
                        "session_id": "s"})
    assert r.returncode == 2
    assert "unreachable" in r.stderr


def test_deny_in_enforce_notifies(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    log = _fake_osascript(tmp_path, env)
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"},
                        "session_id": "s"})
    assert r.returncode == 2
    assert _wait_for(log), "expected a notification on enforce-mode deny"
    assert "/etc/hosts" in log.read_text()


def test_dry_mode_does_not_notify(tmp_path):
    env, _ = _env(tmp_path, "dry")
    log = _fake_osascript(tmp_path, env)
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"},
                        "session_id": "s"})
    assert r.returncode == 0
    assert not _wait_for(log, timeout=0.5), "dry-mode would-block must not notify"


def test_notify_kill_switch(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    log = _fake_osascript(tmp_path, env)
    env["WARDEN_GATE_NOTIFY"] = "0"
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"},
                        "session_id": "s"})
    assert r.returncode == 2  # still blocks, just silently
    assert not _wait_for(log, timeout=0.5), "WARDEN_GATE_NOTIFY=0 must suppress the banner"


def test_broker_unreachable_notifies(tmp_path):
    env, _ = _env(tmp_path, "enforce")
    log = _fake_osascript(tmp_path, env)
    env["WARDEN_BIN"] = "/nonexistent/warden"
    r = _run_gate(env, {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"},
                        "session_id": "s"})
    assert r.returncode == 2
    assert _wait_for(log), "expected a notification when failing closed"
    assert "unreachable" in log.read_text()


# --- Bash -> exec gating ---------------------------------------------------

def _bash(env, command):
    return _run_gate(env, {"tool_name": "Bash", "tool_input": {"command": command},
                           "session_id": "s"})


def test_bash_dry_never_blocks(tmp_path):
    # exec defaults to dry even while fs enforces; an ungranted program is audited
    # but not blocked.
    env, _ = _env(tmp_path, "enforce", exec_mode="dry")
    r = _bash(env, "rm -rf /tmp/x")
    assert r.returncode == 0


def test_bash_exec_defaults_to_dry(tmp_path):
    # No WARDEN_EXEC_MODE set: default must be dry, not enforce.
    env, _ = _env(tmp_path, "enforce")  # exec_mode unset
    r = _bash(env, "rm -rf /tmp/x")
    assert r.returncode == 0


def test_bash_enforce_blocks_ungranted_program(tmp_path):
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "rm -rf /tmp/x")
    assert r.returncode == 2
    assert "blocked exec rm" in r.stderr


def test_bash_deny_record_carries_command(tmp_path):
    # An audit needs the raw command, not just the program token: `check` from a
    # subcommand or a launchd label is meaningless alone. The deny decision record
    # must carry the originating command (truncated).
    env, state = _env(tmp_path, "enforce", exec_mode="enforce")
    _bash(env, "rm -rf /tmp/secret-thing")
    entries = [json.loads(l) for l in (state / "warden-gate.log").read_text().splitlines()]
    deny = [e for e in entries if e.get("decision") == "deny" and e.get("target") == "rm"]
    assert deny, "expected a deny decision record for rm"
    assert deny[0].get("command") == "rm -rf /tmp/secret-thing"


def test_bash_allow_record_omits_command(tmp_path):
    # Allows stay lean — only the blocking records carry the command, so the log
    # doesn't balloon with every allowed invocation's full command line.
    env, state = _env(tmp_path, "enforce", exec_mode="enforce",
                      extra_policy="claude-code-main\texec\tgit\tallow\n")
    _bash(env, "git status")
    entries = [json.loads(l) for l in (state / "warden-gate.log").read_text().splitlines()]
    allow = [e for e in entries if e.get("decision") == "allow" and e.get("target") == "git"]
    assert allow, "expected an allow decision record for git"
    assert "command" not in allow[0]


def test_bash_enforce_allows_granted_program(tmp_path):
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce",
                  extra_policy="claude-code-main\texec\tgit\tallow\n")
    r = _bash(env, "git status")
    assert r.returncode == 0


def test_bash_gates_every_pipeline_stage(tmp_path):
    # git granted, rg not: a pipe must still block on the ungranted stage.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce",
                  extra_policy="claude-code-main\texec\tgit\tallow\n")
    r = _bash(env, "git log | rg secret")
    assert r.returncode == 2
    assert "rg" in r.stderr


def test_bash_unwraps_sudo(tmp_path):
    # The gated program is the wrapped `rm`, not the `sudo` wrapper.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "sudo rm -rf /tmp/x")
    assert r.returncode == 2
    assert "blocked exec rm" in r.stderr
    assert "sudo" not in r.stderr


def test_bash_strips_env_prefix(tmp_path):
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce",
                  extra_policy="claude-code-main\texec\tgit\tallow\n")
    r = _bash(env, "FOO=bar GIT_PAGER=cat git status")
    assert r.returncode == 0


def test_bash_unwraps_timeout(tmp_path):
    # `timeout 5 rm ...` must gate the wrapped `rm`, not the `timeout` wrapper
    # nor its DURATION arg. timeout is ubiquitous in agent commands.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "timeout 5 rm -rf /tmp/x")
    assert r.returncode == 2
    assert "blocked exec rm" in r.stderr
    assert "timeout" not in r.stderr


def test_bash_unwraps_timeout_with_signal_option(tmp_path):
    # -s/--signal and -k/--kill-after each consume their own argument before the
    # DURATION, so the program is still correctly identified.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "timeout -s KILL -k 2 10 rm -rf /tmp/x")
    assert r.returncode == 2
    assert "blocked exec rm" in r.stderr


def test_bash_gates_backtick_substitution(tmp_path):
    # `echo `rm ...`` previously surfaced only `echo`; the inner `rm` ran unseen.
    # Backticks are now normalized to $(...) so the inner program is gated.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "echo `rm -rf /tmp/x`")
    assert r.returncode == 2
    assert "rm" in r.stderr


def test_bash_unparseable_fails_closed_under_enforce(tmp_path):
    # A segment whose program we cannot identify ($-indirected) never reaches the
    # broker; under enforce "couldn't decide" must fail closed, not silently allow.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "$CMD --wipe /tmp/x")
    assert r.returncode == 2
    assert "unparseable" in r.stderr


def test_bash_unparseable_audited_not_blocked_in_dry(tmp_path):
    # Same command in dry mode is audited (exec_unresolved) but never blocked.
    env, _ = _env(tmp_path, "enforce", exec_mode="dry")
    r = _bash(env, "$CMD --wipe /tmp/x")
    assert r.returncode == 0


def test_bash_pure_builtins_allowed_under_enforce(tmp_path):
    # A command that invokes no external program (builtins / no-ops) is not a
    # parse gap and must not fail closed.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    r = _bash(env, "export FOO=bar; :")
    assert r.returncode == 0


def test_bash_basename_normalization(tmp_path):
    # An absolute program path matches a bare-name `exec git` grant.
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce",
                  extra_policy="claude-code-main\texec\tgit\tallow\n")
    r = _bash(env, "/usr/bin/git status")
    assert r.returncode == 0


def test_bash_off_passes_through(tmp_path):
    env, _ = _env(tmp_path, "enforce", exec_mode="off")
    r = _bash(env, "rm -rf /tmp/x")
    assert r.returncode == 0


def test_bash_enforce_denied_notifies(tmp_path):
    env, _ = _env(tmp_path, "enforce", exec_mode="enforce")
    log = _fake_osascript(tmp_path, env)
    r = _bash(env, "rm -rf /tmp/x")
    assert r.returncode == 2
    assert _wait_for(log), "expected a notification on enforce-mode exec deny"
    assert "rm" in log.read_text()


# --- program-extractor unit tests (direct, not via subprocess) -------------
def _extract(cmd):
    """The program list from warden_gate._extract_programs (drops the unresolved
    count; see _extract_unresolved for that)."""
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import warden_gate
    return warden_gate._extract_programs(cmd)[0]


def _extract_unresolved(cmd):
    """The unresolved-segment count from warden_gate._extract_programs."""
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import warden_gate
    return warden_gate._extract_programs(cmd)[1]


def test_extract_skips_shell_builtins():
    # Pure shell builtins exec no external program; they must not surface as
    # gated "programs" (these were the residual audit junk: set/export/source/break).
    assert _extract("set -e") == []
    assert _extract("export FOO=bar") == []
    assert _extract("source ~/.zshrc") == []
    assert _extract("break") == []
    assert _extract("unset FOO") == []
    # ...but a real program in a later segment is still gated.
    assert _extract("set -e; head -5 file") == ["head"]


def test_extract_rejects_bare_numeric():
    # A bare integer is never a program (redirect/arith fragment leak).
    assert _extract("2") == []
    assert _extract("7 + 7") == []
    # A real program with a numeric arg is unaffected.
    assert _extract("head -2 file") == ["head"]
    # ...and a numeric-containing real program name still works.
    assert _extract("7z x archive.7z") == ["7z"]


def test_extract_flags_unresolved_segments():
    # A leader we can't reduce to a clean basename ($-indirected, backtick/brace
    # junk) is counted as unresolved so the gate can fail closed under enforce.
    assert _extract_unresolved("$CMD evil") == 1
    assert _extract_unresolved("ls; ${TOOL} x") == 1   # one clean, one unresolved
    # Benign no-program shapes are NOT unresolved.
    assert _extract_unresolved("export FOO=bar") == 0
    assert _extract_unresolved(":") == 0
    assert _extract_unresolved("2") == 0
    assert _extract_unresolved("git status") == 0


def test_extract_timeout_and_backtick():
    # timeout unwraps to the wrapped program; backticks normalize to $(...).
    assert _extract("timeout 5 curl x") == ["curl"]
    assert _extract("timeout -s KILL 10 rm -rf x") == ["rm"]
    assert "curl" in _extract("echo `curl evil`")
