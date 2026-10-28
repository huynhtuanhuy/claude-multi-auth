# claude-multi-auth

[![CI](https://github.com/huynhtuanhuy/claude-multi-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/huynhtuanhuy/claude-multi-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Keep several Claude accounts logged in on one Mac and switch Claude Code and
Claude Desktop between them without logging out and back in. If you use a
work and a personal account, or several organizations, you no longer have
to sign out, sign in again in the browser, and lose your place each time:
log each account in once, then switch with one command or one menu click.

It has two parts:

- **`cma`**, a command line tool. It logs accounts in, stores them, switches
  between them, shows usage, and keeps backups.
- **Claude Multi Auth.app**, a menubar app. It does the same through a menu,
  and the `cma` binary ships inside it.

> **Unofficial.** claude-multi-auth is an independent project. It is not
> affiliated with, endorsed by, or supported by Anthropic. "Claude",
> "Claude Code" and "Claude Desktop" are Anthropic's products.

> **What it touches.** To switch accounts, cma rewrites the login state of
> Anthropic's apps on your Mac:
>
> - the Keychain item `Claude Code-credentials` (Claude Code's login);
> - the `oauthAccount` field in `~/.claude.json`;
> - Claude Desktop's login keys and storage files under
>   `~/Library/Application Support/Claude` (only when you use the Desktop
>   target).
>
> Every change is backed up first and rolled back on failure (see
> [How switching works](#how-switching-works) and
> [Backups, restore and recovery](#backups-restore-and-recovery)). The
> opt-in usage display calls Anthropic endpoints that are not public API
> (see [Usage display](#usage-display-opt-in)).

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [How switching works](#how-switching-works)
- [Usage display (opt-in)](#usage-display-opt-in)
- [Backups, restore and recovery](#backups-restore-and-recovery)
- [Security notes](#security-notes)
- [Known limits](#known-limits)
- [Uninstall](#uninstall)
- [Building from source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

More documentation:

- [docs/architecture.md](docs/architecture.md): how the code is organized
  and how a switch is made safe.
- [docs/json-api.md](docs/json-api.md): the `--json` contract.
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
  [CHANGELOG.md](CHANGELOG.md).

## Requirements

- macOS 13 or later.
- Claude Code, run and logged in at least once. cma refuses to work if `~/.claude` or
  `~/.claude.json` is missing. It never creates them.
- Optional: Claude Desktop, if you want to switch it too.
- To build: Rust (pinned in `rust-toolchain.toml`), Node.js with npm, and
  the Xcode command line tools.

## Install

There are no prebuilt downloads yet; build from source.

**Command line only:**

```sh
git clone https://github.com/huynhtuanhuy/claude-multi-auth.git
cd claude-multi-auth
cargo build -p cma --release      # the binary is target/release/cma
```

Copy `target/release/cma` to a directory on your `PATH` (for example
`~/.local/bin`).

**Menubar app (with `cma` inside):**

1. Build it:
   ```sh
   npm --prefix app ci
   npm --prefix app run bundle
   ```
   The result is `target/release/bundle/macos/Claude Multi Auth.app` (see
   [Building from source](#building-from-source)). Copy it to
   `/Applications`.
2. The app is ad-hoc signed and **not notarized**. The first time, open it
   with right-click → Open, or allow it under System Settings → Privacy &
   Security.
3. The app lives in the menubar only (no Dock icon).
4. **Install the command line tool** (optional): in the menubar choose
   *Settings…*, then click **Install CLI**. This creates a symlink
   `~/.local/bin/cma` that points to the `cma` binary inside the app:
   - Install CLI never overwrites a regular file at that path.
   - If a symlink there points somewhere else, it asks before replacing it.
   - If your shell does not find `cma`, add `~/.local/bin` to `PATH`. For zsh,
     put `export PATH="$HOME/.local/bin:$PATH"` in `~/.zshrc`.
   - You can also run the binary directly:
     `"/Applications/Claude Multi Auth.app/Contents/MacOS/cma"`.

## Quick start

```sh
cma import-current --alias work   # store the account Claude Code is logged in to now
cma login --alias personal        # log in another account in the browser
cma list                          # both accounts; "CLI●" marks the active one
cma switch personal               # Claude Code now uses "personal"
cma switch work                   # and back
```

Claude Desktop too (optional):

```sh
cma desktop import-current        # link the account Desktop is signed in to now
cma desktop link personal         # sign Desktop in to "personal" once and store it
cma switch work --desktop         # Desktop now uses "work" (it is quit and started again)
cma switch personal --both        # Claude Code and Desktop together
```

What each step does:

- `cma login` runs `claude auth login` in an isolated config directory, so
  the account Claude Code is using now is not touched.
- Accounts can be named by row number, alias, email, email prefix or key
  prefix (case-insensitive).
- Start a new `claude` session after switching; `/status` shows the new
  account.

From the menubar:

- Each account has a submenu with **Switch CLI**, **Switch Desktop** (or
  **Link Desktop…** when Desktop has not been linked to that account yet) and
  **Switch CLI + Desktop**. The menu also shows which account Claude Desktop
  is signed in as.
- **Session follow (Desktop)** turns the `session_follow` setting on or off.
- *Add account…* opens Terminal and runs `cma login` there.
- *Settings…* has the accounts, backups, settings, launch-at-login and
  Install CLI.

## Commands

Every command accepts `--json`: it prints exactly one JSON document and never
prompts. The contract (fields, warning and error codes) is in
[docs/json-api.md](docs/json-api.md).

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

Exit codes:

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
(`crates/core/data/desktop_identity.json`). Everything else there (your MCP
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
    tracked by cma (see [Known limits](#known-limits)).
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
- **No notarization.** The app is ad-hoc signed only.

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
    `restore_undo` undo.
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

## Uninstall

1. In the app's *Settings…*, turn off **Launch at login**, then choose
   *Quit*.
   - If the app is already deleted, remove its LaunchAgent from
     `~/Library/LaunchAgents/` instead. It is the `.plist` file named after
     "Claude Multi Auth".
2. Delete `/Applications/Claude Multi Auth.app`.
3. Remove the CLI link, if you installed it:
   ```sh
   [ -L ~/.local/bin/cma ] && rm ~/.local/bin/cma
   ```
   If you copied a `cma` binary built from source onto your `PATH`
   instead, delete that file.
4. Optionally, export accounts you want to keep first
   (`cma export <dir> --yes`). Then delete cma's Keychain items. Each
   command below deletes one item per call and prints nothing secret, so
   repeat it until it reports that the item could not be found:
   ```sh
   while security delete-generic-password -s claude-multi-auth >/dev/null 2>&1; do :; done
   while security delete-generic-password -s claude-multi-auth-backup >/dev/null 2>&1; do :; done
   ```
5. Remove Keychain items left by interrupted logins, **before** deleting
   `~/.claude-multi-auth`. Only the next `cma login` removes such leftovers
   (those older than an hour); no other command does. Each leftover has a
   `~/.claude-multi-auth/login-<number>` directory whose `.cma-login.json`
   marker names its Keychain item (`service`, `account`), a service of the
   form `Claude Code-credentials-<8 hex digits>`. Deleting the directory
   first loses that name.
   ```sh
   ls -d ~/.claude-multi-auth/login-* 2>/dev/null   # nothing listed: skip this step
   for d in ~/.claude-multi-auth/login-*/; do
     m="$d.cma-login.json"
     [ -f "$m" ] || { echo "no marker in $d"; continue; }
     svc=$(plutil -extract service raw -o - "$m")
     acct=$(plutil -extract account raw -o - "$m")
     security delete-generic-password -s "$svc" -a "$acct" >/dev/null && echo "deleted $svc"
   done
   ```
   - This prints only service names, never a secret (no `-w`).
   - A directory without a marker: keep `~/.claude-multi-auth` for now, run
     `cma login` and cancel it with Ctrl-C at the browser step; its sweep
     removes leftovers older than an hour (the item name is computed from
     the directory path).
   - **Do not delete other `Claude Code-credentials-…` items.** Claude Code
     uses hashed items for custom `CLAUDE_CONFIG_DIR`s.
   - Developers who ran the `#[ignore]` real-Keychain tests may also have
     items in service `claude-multi-auth-test`:
     `while security delete-generic-password -s claude-multi-auth-test >/dev/null 2>&1; do :; done`.
6. Delete cma's data directory (registry, backups, locks):
   ```sh
   rm -rf ~/.claude-multi-auth
   ```

Claude Code's own login (`Claude Code-credentials` and `~/.claude.json`)
stays as it is: Claude Code keeps using whichever account was active last.

## Building from source

Requirements:

- Rust 1.97 (pinned in `rust-toolchain.toml`);
- Node.js with npm;
- the Xcode command line tools.

```sh
cargo build -p cma --release           # the CLI: target/release/cma
npm --prefix app ci
npm --prefix app run bundle            # the app (with cma inside)
```

How `npm --prefix app run bundle` works:

- It runs `tauri build` with
  [`app/src-tauri/tauri.bundle.conf.json`](app/src-tauri/tauri.bundle.conf.json).
- That config's `beforeBuildCommand` runs
  [`app/scripts/build-sidecar.sh`](app/scripts/build-sidecar.sh). The script
  builds `cma` in release mode and copies it to
  `app/src-tauri/binaries/cma-<target triple>`.
- Tauri then bundles it as `Contents/MacOS/cma`, and the app is ad-hoc
  signed.
- The result is
  `target/release/bundle/macos/Claude Multi Auth.app`, under
  `$CARGO_TARGET_DIR` if that is set. `CARGO_TARGET_DIR` must be an absolute
  path.
- The sidecar is kept out of `tauri.conf.json` on purpose. With it there,
  every plain `cargo build`/`test`/`clippy` of the workspace would need the
  sidecar binary to exist first.

Development builds of the app look for `cma` via `CMA_DEV_BIN`, for example
`CMA_DEV_BIN=$PWD/target/debug/cma npm --prefix app run tauri dev`. Release
builds ignore `CMA_DEV_BIN` and use only the `cma` inside the bundle.

Running the tests, the checks CI runs, and how the tests stay away from
your real Keychain and Claude state are in
[CONTRIBUTING.md](CONTRIBUTING.md). How the code is organized is in
[docs/architecture.md](docs/architecture.md).

## Contributing

Bug reports, ideas and pull requests are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems
privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). claude-multi-auth is not affiliated with Anthropic.
