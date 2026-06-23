# Warden — Claude Code gate

This adapter wires Warden into Claude Code as a `PreToolUse` gate. It brokers
`Bash` (exec) and filesystem (`Read`/`Write`/`Edit`/`NotebookEdit`) actions
against your policy and writes every decision to an audit log.

**It ships safe: dry mode by default.** In dry mode the gate *logs* every
decision but never blocks. You build an allowlist from real usage first, then opt
into enforcement. Nothing is gated until you both register the hooks (below) and
flip a mode to `enforce`.

> Reminder: Warden is a guardrail, not a sandbox. See the top-level
> [SECURITY.md](../../SECURITY.md) for the threat model and limitations.

## 1. Prerequisites

- A built `warden` binary (the installer builds it for you).
- Python 3 (for the hook scripts).
- macOS for the bundled launchd daemon. On Linux, run `warden serve …` yourself
  (e.g. under systemd) using the same arguments the plist template shows.

## 2. Install

```sh
adapters/claude-code/install.sh
```

This is idempotent. It:
- builds the release binary and installs it to `~/.warden/bin/warden`,
- seeds `~/.warden/` (creates `policy.tsv` from `policy.starter.tsv` if absent),
- symlinks the hook scripts into `~/.claude/hooks/`,
- renders the launchd plist and loads the `ai.warden.gateway` daemon.

**The installer does NOT touch `settings.json`** — registering the hooks is a
deliberate manual step (next), so the gate never starts firing without your
explicit opt-in.

## 3. Register the hooks in `settings.json`

Add these to `~/.claude/settings.json` (merge into any existing `hooks`). They
start in **dry** mode (no `WARDEN_*_MODE` set → logs only):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Write|Edit|NotebookEdit",
        "hooks": [{ "type": "command", "command": "python3 $HOME/.claude/hooks/warden_gate.py" }]
      },
      {
        "matcher": "Skill",
        "hooks": [{ "type": "command", "command": "python3 $HOME/.claude/hooks/warden_skill_track.py push" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Skill",
        "hooks": [{ "type": "command", "command": "python3 $HOME/.claude/hooks/warden_skill_track.py pop" }]
      }
    ]
  }
}
```

The `Skill` hooks are optional; they attribute decisions to the active skill in
the audit log. Restart Claude Code so it reloads `settings.json`.

## 4. Verify (still in dry mode)

1. Confirm the daemon is up: `launchctl list | grep ai.warden.gateway`.
2. Use Claude Code normally for a bit, then inspect what *would* have happened:

   ```sh
   ~/.warden/bin/warden log analyze          # fs decisions (reads the gate's decision log)
   ~/.warden/bin/warden log analyze --exec   # exec decisions
   ```

   `analyze` reads the gate's decision log (`~/.claude/hooks/state/warden-gate.log`)
   by default — not the broker's raw `~/.warden/audit.jsonl`, which uses a
   different schema. Entries show `mode: dry` and a `would_block` flag for
   anything that *would* be denied. Use this to shape `~/.warden/policy.tsv` until the only would-blocks
   left are things you actually want blocked.

## 5. Enforce

Enforcement is per-class so you can ramp them independently. The cleanest way is
to set the mode inline on the hook command (no shell-profile juggling):

```json
{ "type": "command", "command": "WARDEN_GATE_MODE=enforce WARDEN_EXEC_MODE=enforce python3 $HOME/.claude/hooks/warden_gate.py" }
```

- `WARDEN_GATE_MODE=enforce` blocks denied **filesystem** actions.
- `WARDEN_EXEC_MODE=enforce` blocks denied **exec** (Bash) actions. Leave it at
  `dry` (or omit) to keep observing exec while enforcing fs only.

A blocked call returns a non-zero exit to Claude Code and (on macOS) shows a
desktop notification. Set `WARDEN_GATE_NOTIFY=0` to silence notifications.

## 6. Rollback

Remove the `WARDEN_*_MODE=enforce` prefix from the hook command (back to dry), or
remove the `PreToolUse` `warden_gate.py` entry entirely, then restart Claude
Code. The daemon and policy can stay; with the hook gone, nothing is gated.

## 7. Uninstall

```sh
# 1. Remove the warden hook entries from ~/.claude/settings.json, then:
launchctl bootout "gui/$(id -u)/ai.warden.gateway"
rm -f ~/Library/LaunchAgents/ai.warden.gateway.plist
rm -f ~/.claude/hooks/warden_gate.py ~/.claude/hooks/warden_skill_track.py
rm -rf ~/.warden        # removes policy, manifests, audit log, and the binary
```

## Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `WARDEN_GATE_MODE` | `dry` | `dry` logs fs decisions; `enforce` blocks denials |
| `WARDEN_EXEC_MODE` | `dry` | `off` \| `dry` \| `enforce` for Bash/exec gating |
| `WARDEN_BIN` | `~/.warden/bin/warden` | gate's one-shot fallback binary |
| `WARDEN_SOCK` | `/tmp/warden_daemon.sock` | daemon socket the gate talks to |
| `WARDEN_POLICY` | `~/.warden/policy.tsv` | policy file |
| `WARDEN_MANIFESTS` | `~/.warden/manifests` | skill capability manifests |
| `WARDEN_AUDIT` | `~/.warden/audit.jsonl` | decision audit log |
| `WARDEN_GATE_NOTIFY` | `1` | `0` disables the desktop block notification |
