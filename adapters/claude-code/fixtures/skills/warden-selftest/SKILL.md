---
name: warden-selftest
description: End-to-end fixture proving warden mediates a skill's file access against its declared manifest.
capabilities:
  - fs:read $HOME/.warden/fixtures/allowed
---

# warden-selftest

Fixture skill. Declares read access to `fixtures/allowed` only. A write — or a
read outside that path — must be denied as `manifest: undeclared` in enforce mode.
