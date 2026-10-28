# Security notes and known limits

What claude-multi-auth protects, what it exposes, and the limits it accepts.
To report a vulnerability, follow [SECURITY.md](../SECURITY.md). What cma
writes on your Mac is listed in the [README](../README.md#what-it-touches--safety);
the network calls the usage display makes are in
[usage.md](usage.md#usage-display-opt-in).

## Security notes

Threat model: cma protects against accidental disclosure (files, logs,
command output, backups) and against corrupting your logins. It does **not**
protect against other software running as your user.

- **Same-user access.** Stored credentials live in the macOS Keychain, in
  service `claude-multi-auth` (one item per account), next to Claude Code's
  own `Claude Code-credentials`. As with Claude Code itself, any process
  running as your user can read these items through `/usr/bin/security`
  without a prompt.
- **No secrets in files or output.** Tokens are never written to plain files
  or logs, and never appear in human or `--json` output. The only exception
  is `cma export`, which you ask for explicitly and must confirm with
  `--yes`.
- **Secrets travel on stdin.** All Keychain reads and writes go through
  `/usr/bin/security`, the same tool Claude Code uses, so its item stays
  trusted and prompt-free. Secrets reach `security` on stdin (`security -i`).
- **argv fallback, visible in `ps`.** `security -i` has a line limit of
  about 4 KB. An item larger than that is written the way Claude Code
  writes it: as a hex-encoded value on the `security` command line. One
  example is a live login that also carries `mcpOAuth` tokens. For the
  moment that command runs, **the hex payload is visible to other processes
  of your user, for example in `ps`**. Claude Code has the same exposure.
  **Every Claude Desktop switch uses this form**: Desktop's
  `oauth:tokenCacheV2` value, its `config.json.journal` and the backup of
  the `config.json` login values are all larger than the limit, so they are
  briefly visible in `ps` while cma stores or backs them up.
- **Token identity.** Tokens are only sent to Anthropic endpoints, over
  HTTPS, with no redirects and a 5 s timeout. Response bodies that could
  hold tokens are never logged.
- **Login options.** The menubar app's *Add account…* passes the login
  options to `cma login --args-file`, which reads a private (0600) JSON
  file. An alias such as `"; rm -rf ~` is stored literally; it never passes
  through shell text.
- **Webview.** The app's webview has a strict Content Security Policy and
  can call only the app's own commands.
- **No notarization.** The app is ad-hoc signed only (see
  [Gatekeeper](install.md#gatekeeper)).

## Known limits

These are accepted limits of this version.

- **Desktop target:** tested against Claude Desktop 4.29.0; a Desktop
  update that changes where it keeps its login needs a data update in cma.
- **Re-login or forced restore can orphan a grant.** In two cases the
  newer grant stays valid on Anthropic's side but is no longer tracked by
  cma, and the account may need `cma login` again:
  - A crash, or a failed live write, while `cma login` re-logs in the
    *active* account. The next command rolls back and its sync stores the
    old live login again.
  - A forced restore of an older login, followed by a command other than the
    `restore_undo` undo (see [`cma restore`](usage.md#cma-restore-id)).
- **Session detection.** Running sessions are detected by process name
  (`claude`) only. A session started under another name (for example a
  node-based launch, or `exec -a`) is not detected, so no confirmation is
  asked for it.
- **Token POST timeout.** The 5 s timeout also applies to the token refresh
  request. If the server completes a refresh after cma gave up, cma no longer
  holds the rotated token, and the account is marked "needs login".
- **Keychain prompt under Claude Code's lock.** If the Keychain item's access
  list is not "always allow", a Keychain prompt could appear while cma holds
  Claude Code's `.storage-write` lock. If the prompt waits more than ~15 s,
  Claude Code may take the lock over. cma reads the item once outside the
  lock first, so a prompt normally shows there. `cma switch` reports
  `storage_lock_held_ms` and warns `storage_lock_slow` above 5 s.
- **`oauthAccount` may revert.** A running session can rewrite
  `oauthAccount` in `~/.claude.json` from memory after a switch. This only
  affects the displayed name (warning `oauth_account_reverted`).
- **Wait notices in the app.** The app does not show the "waiting for a
  token refresh of …" notice; it goes to stderr, which the app does not
  display.
- **Non-ASCII config dirs.** A `CLAUDE_CONFIG_DIR` with non-ASCII characters
  is refused (`unsupported`).
