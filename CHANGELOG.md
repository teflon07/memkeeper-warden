# Changelog

All notable changes to Memkeeper: Warden are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Until 1.0, minor
releases may include breaking changes to the policy format and CLI.

## [0.1.1] - 2026-06-30

### Fixed
- **Claude Code adapter**: the gate now brokers the file targets of shell
  redirections as well as the programs a command execs. Previously `cmd > file`
  was exec-gated on `cmd` while the write to `file` slipped past the `fs:write`
  boundary entirely (and `< file` past `fs:read`). Write redirections (`>`, `>>`,
  `&>`) and input redirections (`<`) are now decided as `fs:write` / `fs:read`;
  fd-dups (`2>&1`), here-strings, and heredocs are correctly ignored.

### Added
- **`WARDEN_REDIRECT_MODE`** (default `dry`): redirect-target gating ramps
  independently of the exec gate, so the allowlist can be built from audited
  usage before switching to `enforce`.

## [0.1.0] - 2026-06-23

Initial public release. A capability broker and execution gate for AI coding
agents.

### Added
- **`warden-core`**: capability model (`fs:read`, `fs:write`, `exec`, `net`),
  TSV policy, scope matching with traversal + suffix-spoof defenses, and the
  broker allow/deny decision logic.
- **`warden-cli`** (`warden` binary): evaluate requests against a policy, parse
  capability declarations from skill front-matter, and inspect the audit log.
- **Claude Code adapter** (`adapters/claude-code/`): a `PreToolUse` gate that
  brokers Bash and filesystem actions, with a portable installer and a launchd
  plist template.
- **MCP bridge** (`adapters/mcp/`).
- Dual-licensed **MIT OR Apache-2.0**.

[0.1.1]: https://github.com/teflon07/memkeeper-warden/releases/tag/v0.1.1
[0.1.0]: https://github.com/teflon07/memkeeper-warden/releases/tag/v0.1.0
