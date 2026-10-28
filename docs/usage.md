# Using claude-multi-auth

What each `cma` command and menubar item does, how a switch works, the
opt-in usage display, and backups, restore and recovery. Installing is in
[install.md](install.md); the `--json` contract is in
[json-api.md](json-api.md); what cma does and does not protect against is in
[security.md](security.md).

- [Quick start notes](#quick-start-notes)
- [The menubar app](#the-menubar-app)
- [Commands](#commands)
- [Exit codes](#exit-codes)
- [How switching works](#how-switching-works)
- [Usage display (opt-in)](#usage-display-opt-in)
- [Backups, restore and recovery](#backups-restore-and-recovery)

## Quick start notes

The first commands to run are in the [README](../README.md#quick-start).
Notes on them:

- `cma login` runs `claude auth login` in an isolated config directory, so
  the account Claude Code is using now is not touched.
- Accounts can be named by row number, alias, email, email prefix or key
  prefix (case-insensitive).
- Start a new `claude` session after switching; `/status` shows the new
  account.

## The menubar app

- Each account has a submenu with **Switch CLI**, **Switch Desktop** (or
  **Link Desktop…** when Desktop has not been linked to that account yet) and
  **Switch CLI + Desktop**. The menu also shows which account Claude Desktop
  is signed in as.
- **Session follow (Desktop)** turns the `session_follow` setting on or off
  (see [Session follow](#session-follow-desktop-only)).
- *Add account…* opens Terminal and runs `cma login` there.
- *Settings…* has the accounts, backups, settings, launch-at-login and
  Install CLI ([Install CLI](install.md#the-menubar-app-and-install-cli)).

## Commands

Every command accepts `--json`: it prints exactly one JSON document and never
prompts. The contract (fields, warning and error codes) is in
[json-api.md](json-api.md).

| Command | What it does |
|---|---|
| `cma list [--live]` | List stored accounts with cached usage. `--live` is an interactive view that refreshes usage in the background; Enter switches. |
| `cma status` | Shows the active account, the live login's state, running `claude` sessions, any unfinished operation, and warnings. |
| `cma login [--email E] [--sso] [--console] [--org O] [--alias A]` | Log in a new account (or log an existing one in again) in the browser, without touching the active login. |
| `cma import-current [--alias A]` | Store the account Claude Code is logged in to now. |
| `cma export <dir> [account…] --yes` | Write credential files to a private (0700) directory. **They contain refresh tokens.** |
| `cma import <file\|dir> [--alias A] [--replace]` | Import exported credential files. `--replace` overwrites a different stored login of the same account. |
| `cma switch [account] [--cli\|--desktop\|--both [--strict]] [--force] [--replace-live] [--yes]` | Make Claude Code (default), Claude Desktop, or both use another account. With no account, it shows a picker. Desktop is quit first (`--yes` skips the question) and started again afterwards. `--both` checks everything Desktop needs (and asks every question) before Claude Code changes, and puts Claude Code back if the Desktop half still fails. |
| `cma remove <account>… [--force]` / `cma remove --all [--force]` | Forget accounts. Their credentials stay in a backup. `--force` is needed to remove the active account. |
| `cma alias set <account> <alias>` / `cma alias clear <account>` | Name an account. An alias cannot be a number. |
| `cma usage [account]` | Fetch usage once (see [Usage display](#usage-display-opt-in)). |
| `cma config get [key]` / `cma config set <key> <value>` | Settings: `live_usage`, `live_interval_secs` (≥ 10), `refresh_grace_secs` (default 300), `default_target`, `session_follow`. |
| `cma backups` | List backups. |
| `cma restore <id> [--force [--yes]]` | Undo what one operation wrote, from its backup. |
| `cma resolve-journal [--yes]` | Accept the current state after an operation that could not be rolled back. |
| `cma clean [--keep N]` | Delete old backups (default: keep 10). |
| `cma desktop import-current [--alias A] [--yes]` | Link the account Claude Desktop is signed in to now. |
| `cma desktop link <account> [--yes] [--replace-live]` | Store Desktop's current login, then sign Desktop in to `<account>` (you sign in in Desktop's window) and store that login too. Needs a terminal. |
| `cma desktop unlink [account]` | Forget the Desktop login cma stores for an account (it stays in a backup). |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failed, and nothing changed (or the change was fully rolled back). |
| 2 | State uncertain: a rollback did not complete. See [Recovery](#when-a-rollback-cannot-finish-exit-2). |
| 3 | Partial success: `switch --both` to an account not linked to Desktop (Claude Code switched, Desktop not), or `remove` when some accounts were removed and others failed (`remove_failed`). |

## How switching works

Claude Code keeps its login in the Keychain item `Claude Code-credentials`
(or a hashed variant when `CLAUDE_CONFIG_DIR` is set). It keeps the account
name it shows in `oauthAccount` in `~/.claude.json`. A switch does this:

1. It takes cma's lock, and finishes or rolls back any interrupted earlier
   operation.
2. **Live sync.** If Claude Code has refreshed the active account's token
   since the last command, cma stores the new token first, so nothing is
   lost.
3. It takes Claude Code's own `.storage-write` lock.
4. It backs up what it is about to change.
5. It writes the target account's credential into the Keychain item. Every
   other key in that item (for example `mcpOAuth`) is kept as it is.
6. It updates only `oauthAccount` in `~/.claude.json`.
7. Every write is read back and checked.
8. The whole switch is recorded in a journal. If cma fails or crashes
   partway, the next `cma` command rolls it back.

Which account a token belongs to always comes from the token itself: its
fingerprint, or Anthropic's `/api/oauth/profile` endpoint. It never comes
from `oauthAccount`, because Claude Desktop and running sessions rewrite that
field. If cma cannot tell whose token it is, it stores nothing.

How the code makes this safe is in
[architecture.md](architecture.md#how-a-mutation-is-made-safe).

### Running `claude` sessions

- If `claude` processes are running, `cma switch` asks before switching on a
  terminal. With `--json` (or without a terminal) it never asks: it refuses
  with `confirmation_required` unless you pass `--force`. The app shows a
  dialog and switches only if you choose Continue; it never answers for you.
- Sessions that are already running pick up the new account's token within
  about 30–40 seconds. Their `/status` keeps showing the old account name
  until they are restarted.
- If `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` is exported in a shell,
  `claude` sessions started from that shell ignore the Keychain, so a switch
  has no effect there. `cma status` warns about this (`env_override`).
- If the live login is one cma does not store (for example you ran `/login`
  inside Claude Code with a new account), switching away would lose it.
  cma asks separately for that case (`--replace-live`). It is still kept in
  the switch's backup either way.

### Token refresh

`cma usage`, `cma list --live` and the app's live usage refresh the expired
tokens of *inactive* accounts, so those accounts stay logged in. To avoid
fighting with Claude Code, cma never refreshes:

- the account Claude Code is using now;
- any account that was active within `refresh_grace_secs` (default 300 s),
  since sessions may still be running on its token.

### Claude Desktop

Desktop's login is a set of keys in its `config.json` (`lastKnownAccountUuid`,
`oauth:*`, …) and storage files (Cookies, Local Storage, …) under
`~/Library/Application Support/Claude`; the exact list ships with cma
([`crates/core/data/desktop_identity.json`](../crates/core/data/desktop_identity.json)).
Everything else there (your MCP
servers, window state, caches) is left alone. For each linked account that
is not live, cma keeps the storage files in
`~/.claude-multi-auth/desktop/<account uuid>/` (0700) and the `config.json`
values in the Keychain (service `claude-multi-auth-desktop`). The files are
encrypted by Chromium with this Mac's `Claude Safe Storage` key, so they only
work here. Every switch first captures the live login again, so tokens
Desktop refreshed are kept. A Desktop relaunch during a switch (for example
an auto-update) stops it without rolling back while Desktop runs (cma
never writes while Desktop runs): the journal is kept, and after you quit
Desktop the next `cma` command rolls it back.

### Session follow (Desktop only)

With `session_follow on`, a Desktop switch also moves the previous account's
local Code/Cowork sessions (from every organization) into the new account's
folder, so they show in its sidebar. A session whose name already exists
there is kept twice, the moved one with a `.cma-<time>` suffix. Moved
sessions keep the old organization's server-side references, so they resume
from their local transcripts but remote-control links may not work. With it
*off* (the default), sessions stay where they are. `cma restore <id>` moves
back only sessions that were not changed since. Transcripts in
`~/.claude/projects/` are never touched.

## Usage display (opt-in)

`cma usage`, `cma list --live` and the app's live usage (setting
`live_usage`, every `live_interval_secs`) show each OAuth account's 5-hour
and 7-day windows and their reset times.

**Disclaimer** (also shown once, the first time usage is fetched):

- To get these numbers, cma sends each stored account's OAuth token to
  Anthropic endpoints that are **not public API**:
  - `https://api.anthropic.com/api/oauth/usage`;
  - to refresh inactive accounts, the OAuth token endpoint
    `https://platform.claude.com/v1/oauth/token`.
- These endpoints may change or stop working.
- Using them may conflict with Anthropic's terms of service. **That risk is
  yours.**
- Nothing is sent for usage unless you ask for it.

Other network use is limited to what identifying accounts needs.
`cma login`, `import`, `import-current`, and syncing a live token cma has not
seen before all call `https://api.anthropic.com/api/oauth/profile`.

Console (API billing) accounts have no usage windows; they show
"n/a (API billing)".

## Backups, restore and recovery

Every operation that changes something first saves a backup of what it will
overwrite:

- File contents go to `~/.claude-multi-auth/backups/<id>/`, which holds
  `manifest.json` plus copies of non-secret files. Everything is mode 0600 in
  0700 directories, and cma excludes `~/.claude-multi-auth` from Time
  Machine.
- Secret values (Keychain items) go to the Keychain service
  `claude-multi-auth-backup`. They are never written to a file.

`cma backups` lists backups. `cma clean` keeps the newest 10 by default.

### `cma restore <id>`

- It puts back only what that one operation wrote. It writes only to
  allowlisted locations: the Claude Code Keychain items, cma's own items,
  `oauthAccount` in `~/.claude.json`, and cma's own files.
- **It refuses if a value changed since the operation** (`restore_conflict`).
  The usual cause is that Claude Code refreshed the live token. Restoring
  would replace that newer token with an older one, so the hint suggests
  `cma switch <account>` instead.
- **It refuses with `restore_older_login`** if it would put an older login of
  a stored account live while cma holds a newer one for it (for example cma
  refreshed that account since the switch). `cma switch <account>` is
  usually what you want: it puts the newer login live.
- `--force` restores anyway, after a confirmation. With `--json`, or without
  a terminal, the confirmation is `--yes`. A forced restore backs up what it
  overwrites in its own backup and warns **`restore_undo`**. That warning
  names the `cma restore <undo-id>` that puts the newer values back.
  - Run that undo command **before any other cma command**, then
    `cma switch <account>`.
  - Any other command first syncs the live login. It would then store the
    older login over the newer one, and the newer grant would no longer be
    tracked by cma (see [Known limits](security.md#known-limits)).
- A restore is itself an operation, with its own backup. `cma restore` on
  that backup undoes the restore.

### When a rollback cannot finish (exit 2)

If an operation is interrupted, the next command rolls it back (warning
`recovered`). Sometimes a rollback cannot complete safely: another program
changed an item in the meantime, or the backup is missing. Then:

- The journal and backup are kept. Every command that changes state, and
  every command that syncs, refuses with exit 2 (`state_uncertain`).
- `cma status` and `cma backups` still work. They show what the operation
  touched.
- Each later command retries the rollback.
- **`cma resolve-journal`** accepts the current state. It runs recovery
  once more first: if that succeeds, there is nothing to resolve. Otherwise,
  after confirmation (`--yes` with `--json`), it archives the journal into
  the backup directory and keeps the backup, so `cma restore <id>` still
  works afterwards.
