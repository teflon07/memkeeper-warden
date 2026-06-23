#!/usr/bin/env bash
# Install the warden Claude Code gate: build release binary, seed ~/.warden,
# symlink hooks, load the launchd daemon. Idempotent.
#
# This does NOT register the hooks in ~/.claude/settings.json — that step is
# manual (see the plan / PR), so the gate does not fire until you opt in.
# The gate ships in dry mode (logs, never blocks) until WARDEN_GATE_MODE=enforce.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADAPTER="$REPO/adapters/claude-code"
HOOKS="$HOME/.claude/hooks"
WARDEN="$HOME/.warden"
WARDEN_BIN="$WARDEN/bin/warden"

echo "==> building release binary"
( cd "$REPO" && cargo build -p warden-cli --release )

echo "==> installing binary to $WARDEN_BIN"
# Install to a stable, predictable path so the launchd plist and the gate's
# default WARDEN_BIN both resolve without knowing where the repo was cloned.
mkdir -p "$WARDEN/bin"
cp "$REPO/target/release/warden" "$WARDEN_BIN"

echo "==> seeding ~/.warden"
mkdir -p "$WARDEN/manifests"
[ -f "$WARDEN/policy.tsv" ] || cp "$ADAPTER/policy.starter.tsv" "$WARDEN/policy.tsv"
# Make the e2e fixture skill discoverable to the daemon's manifest loader.
ln -sfn "$ADAPTER/fixtures/skills/warden-selftest" "$WARDEN/manifests/warden-selftest"
# Seed the self-test fixtures at a stable absolute path under ~/.warden. Both the
# starter policy grant and the self-test SKILL.md declare $HOME/.warden/fixtures/
# allowed (expanded at load time), so this location must exist post-install for
# the e2e self-test to pass on any machine, regardless of where the repo lives.
mkdir -p "$WARDEN/fixtures"
rm -rf "$WARDEN/fixtures/allowed"   # idempotent: avoid nesting on re-run
cp -R "$ADAPTER/fixtures/allowed" "$WARDEN/fixtures/allowed"

echo "==> symlinking hooks"
mkdir -p "$HOOKS"
ln -sfn "$ADAPTER/warden_gate.py" "$HOOKS/warden_gate.py"
ln -sfn "$ADAPTER/warden_skill_track.py" "$HOOKS/warden_skill_track.py"

echo "==> rendering + loading launchd daemon"
# launchd does not expand $HOME, so render the template to absolute paths here.
PLIST="$HOME/Library/LaunchAgents/ai.warden.gateway.plist"
sed -e "s#__WARDEN_BIN__#$WARDEN_BIN#g" -e "s#__HOME__#$HOME#g" \
  "$ADAPTER/ai.warden.gateway.plist.template" > "$PLIST"
launchctl bootout "gui/$(id -u)/ai.warden.gateway" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo "==> done. Daemon loaded; hooks symlinked but NOT yet registered in"
echo "    settings.json. Register the PreToolUse/PostToolUse entries manually,"
echo "    then the gate runs in dry mode until WARDEN_GATE_MODE=enforce is set."
