---
name: Bug report
about: Something does not work as documented
labels: bug
---

<!--
Security problem (a token leaked, a login lost or overwritten)? Do not open
a public issue; report it privately as described in SECURITY.md.
-->

## What happened

<!-- What you did, what you expected, and what happened instead. -->

## Steps to reproduce

1.
2.

## Versions

- `cma --version`:
- macOS version:
- Claude Code version (`claude --version`):
- Claude Desktop version, if the problem involves Desktop:
- How you run cma: the menubar app bundle / a `cargo build` binary

## `cma status --json`

<!--
cma never prints tokens, so this output holds no secret. It does contain
account ids (uuids) and may name accounts by email or alias; replace them
(for example with you@example.com) if you prefer.
-->

```json

```

## Error output

<!--
The full output of the failing command, ideally with --json. Redact emails
if you want. If you paste anything else (logs, files), make sure it holds
no token.
-->

```

```
