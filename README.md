<p align="center">
  <img src="assets/logo.png" alt="warden logo" width="180" height="180" />
</p>

<p align="center"><em>Nothing gets past the gate without a reason. And a receipt.</em></p>

# Memkeeper: Warden

Part of the [Memkeeper](https://github.com/teflon07/memkeeper) family.

A capability broker and execution gate for AI coding agents. Warden decides
whether an agent's requested action (a shell command, a file read/write) is
allowed by a declared, auditable policy, and logs every decision.

- **Capability-scoped.** Actions are matched against typed capabilities — a
  class and a scope separated by a space: `fs:read <path>`, `fs:write <path>`,
  `exec <program>`, `net <host>`. Path/glob scope matching defends against
  traversal and suffix-spoofing.
- **Declarative policy.** A simple TSV policy grants capabilities per caller;
  skills declare the capabilities they need in front-matter.
- **Auditable.** Every allow/deny is appended to an audit log.
- **Local and deterministic.** No network, no LLM in the decision path.

> Status: pre-release (v0.1). The policy format and CLI may change before 1.0.

> ℹ️ **Generated release mirror.** This repo is generated from a private
> development repo and published as releases. The `main` branch may be
> regenerated, so **pin to tagged releases** (or the release artifacts) rather
> than to arbitrary `main` commits — tagged releases are stable. See
> [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute; issues, security
> reports, and design feedback are the best paths today.

## Threat model — what Warden does and does NOT stop

Warden is a **policy gate, not a sandbox.** Its threat model is **accidental
damage and skill/agent overreach** — a tool that wanders outside its lane — **not
a hostile, adversarial harness** actively trying to escape.

What it enforces well: filesystem and network **scope**. Path matching defends
against traversal (`..`) and suffix/sibling-prefix confusion; host matching
defends against DNS suffix spoofing. Decisions are deny-by-default and fail
closed.

A limitation to know: **path matching is lexical.** It normalizes `..` but does
**not** resolve symbolic links (no `realpath`). A symlink that sits inside an
allowed directory but points outside it is followed by the OS, not caught by the
policy. Keep allowed roots free of untrusted symlinks; realpath hardening is a
planned addition.

The other limitation: **the exec gate matches the wrapper program, not its
inner intent.** It decides on the leading program name (`bash`, `python3`,
`find`, `eval`, …). It does **not** parse what that program then does. So
`bash -c '<anything>'`, `find . -exec <anything>`, and `python3 -c '<anything>'`
gate only on `bash`/`find`/`python3` — the inner command is invisible to Warden.
If you grant a program that can run arbitrary subcommands, you have effectively
granted what those subcommands can do. True containment (a sandbox/forwarder) is
a separate, deferred layer. Treat Warden as a guardrail, not a security boundary
against code that is itself permitted to run.

See [SECURITY.md](SECURITY.md) for the full in-scope / out-of-scope breakdown.

> ⚠️ **No warranty — use at your own risk.** Warden is provided "AS IS", without
> warranty of any kind, under the MIT/Apache-2.0 licenses. It is a pre-1.0
> guardrail, **not** a security boundary or sandbox. Do not rely on it as the sole
> control protecting sensitive systems or data; validate it against your own
> threat model before depending on it.

## Workspace layout

| Crate | Role |
|---|---|
| `warden-core` | Capability model, policy, scope matching, broker decision logic |
| `warden-cli` | The `warden` binary: evaluate requests, manage policy, inspect the audit log |

## Prerequisites

- **Rust toolchain** (stable, via [rustup](https://rustup.rs)) — provides `cargo`,
  which builds the CLI. The crates are edition 2021, so Rust 1.56 or newer.
- That's it. Warden is pure Rust with no native-library, network, LLM, or API-key
  dependencies.

## Quickstart

```sh
cargo build --release

# Warden brokers an agent's requests: it reads line-delimited JSON on stdin (or
# a Unix socket) and answers each with an allow/deny decision. With no policy
# loaded it denies by default — send one request to see it work:
echo '{"skill":"demo","capability":"exec","target":"git"}' \
  | ./target/release/warden serve --stdio
# → {"decision":"deny", ...}
```

There is no one-shot evaluate command; warden runs as a broker (`warden serve`)
that an agent talks to. The real entry point is the Claude Code gate below — it
wires warden in and logs every decision it makes, which you can review with
`warden log analyze` (it reads the gate's decision log by default) before you
flip from dry-run to enforce.

## Claude Code gate (integration)

`adapters/claude-code/` wires warden into Claude Code as a `PreToolUse` gate so
Bash and filesystem actions are brokered against your policy. It ships as a
reference integration: `install.sh` derives its paths from the repo location and
fills in the launchd plist template (`ai.warden.gateway.plist.template`). It ships
**dry by default** (logs every decision, blocks nothing) so you build an
allowlist from real usage before enforcing.

**See [`adapters/claude-code/README.md`](adapters/claude-code/README.md) for the
full walkthrough**: install, the exact `settings.json` hook registration, how to
verify in dry mode, flipping to `enforce`, rollback, and uninstall.

An MCP bridge lives in `adapters/mcp/`.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option.

## Contributing

Issues and pull requests are welcome. Contributions require signing the project
[Contributor License Agreement](docs/CLA.md) — the CLA bot prompts you on your
first pull request; you keep the copyright to your contributions. See
[CONTRIBUTING.md](CONTRIBUTING.md).
