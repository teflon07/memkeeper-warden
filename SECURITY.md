# Security Policy

Warden is a security tool, so please read the threat model below before
reporting — it defines what Warden does and does **not** claim to stop.

## Reporting a vulnerability

Report security issues **privately** — do not open a public issue for a suspected
vulnerability or bypass.

Use GitHub's private vulnerability reporting: on this repository, go to the
**Security** tab → **Report a vulnerability**. This opens a private advisory
visible only to the maintainers.

If you cannot use GitHub's reporting flow, email **security@memkeeper.ai**
instead.

Please include:
- a description of the issue and its impact,
- a proof-of-concept bypass if applicable (the exact command/policy/input),
- affected version / commit and the gate mode (`dry` vs `enforce`).

We aim to acknowledge within **7 days** and to provide a remediation timeline
after triage. Please allow a coordinated-disclosure window before public
discussion.

## Supported versions

Warden is pre-1.0 and under active development. Fixes land on the latest release
and `main`.

## Threat model — what Warden does and does NOT stop

Warden's threat model is **accidental damage and skill/agent overreach, not a
hostile, adversarial harness**. It is a policy gate, not a sandbox.

**In scope** (please report bypasses of these):
- Path-policy escapes: traversal (`..`), suffix/sibling-prefix confusion, or glob
  over-matching that lets a request reach a path the policy did not grant.
- Network-policy escapes: DNS suffix spoofing or wildcard over-match that allows
  a host the policy did not grant.
- **Fail-open behavior under `enforce`**: any path where an undecided, malformed,
  or broker-unreachable request is *allowed* instead of denied.
- Manifest/declaration bypasses that let an undeclared capability through.

**Out of scope** (known and documented limitations, not vulnerabilities):
- **The exec gate matches the wrapper program, not its inner intent.** It decides
  on the leading program name (`bash`, `python3`, `find`, `eval`, …). It does
  **not** parse what that program then does, so `bash -c '<anything>'`,
  `find . -exec <anything>`, `python3 -c '<anything>'`, and similar gate only on
  the wrapper. Warden is not a containment boundary against a program that is
  itself permitted to run. True containment is a deferred sandbox/forwarder.
- **Symlink resolution.** Path matching is lexical: it normalizes `..` but does
  not resolve symbolic links (no `realpath`). A symlink inside an allowed
  directory that points outside it is not caught. Realpath hardening is planned.
- Anything requiring the attacker to already control the policy file, the
  manifests directory, the audit log, or the host account Warden runs as.

If you are unsure whether something is in scope, report it privately and we will
triage.
