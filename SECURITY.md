# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/huynhtuanhuy/claude-multi-auth/security/advisories/new)
(the repository's *Security* tab → *Report a vulnerability*). Do not open a
public issue for a security problem.

Include what you found, how to reproduce it, and which version
(`cma --version`) and macOS version you used. Never include a real token,
refresh token or credential file; describe where one appeared instead.

This is a volunteer project; reports are answered on a best-effort basis.

## Scope

In scope:

- a token, refresh token or credential written to a file, a log, command
  output (human or `--json`), an error message, or a command line, beyond
  what the [security notes](docs/security.md#security-notes) document;
- a way to make cma lose a login, overwrite a newer login with an older
  one, or write outside the locations it documents;
- tokens sent anywhere other than the Anthropic endpoints listed under
  [Usage display](docs/usage.md#usage-display-opt-in),
  or over anything but HTTPS;
- the menubar app's webview or command surface running something it should
  not.

Out of scope:

- other software running as your macOS user reading the Keychain items.
  The threat model does not cover same-user access (see below); Claude Code
  has the same exposure.
- the brief `ps` visibility of large Keychain writes, which is documented;
- files you exported yourself with `cma export`;
- the app not being notarized;
- changes on Anthropic's side to the non-public endpoints cma uses.

## Threat model in short

cma protects against accidental disclosure (files, logs, command output,
backups) and against corrupting your logins. It does **not** protect
against other software running as your user.

Where secrets are kept:

- stored Claude Code logins: Keychain service `claude-multi-auth`;
- backups of overwritten secret values: Keychain service
  `claude-multi-auth-backup`;
- Claude Desktop login values: Keychain service `claude-multi-auth-desktop`;
  Desktop's login storage files for accounts that are not live:
  `~/.claude-multi-auth/desktop/<account uuid>/files/` (0700).

Everything else under `~/.claude-multi-auth` is non-secret metadata. The
full notes, including the `ps` exposure and the network endpoints, are in
[Security notes](docs/security.md#security-notes),
[Usage display](docs/usage.md#usage-display-opt-in) and
[Known limits](docs/security.md#known-limits).
