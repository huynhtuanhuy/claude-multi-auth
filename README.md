# claude-multi-auth

[![CI](https://github.com/huynhtuanhuy/claude-multi-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/huynhtuanhuy/claude-multi-auth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/huynhtuanhuy/claude-multi-auth?include_prereleases&sort=semver)](https://github.com/huynhtuanhuy/claude-multi-auth/releases)
[![npm](https://img.shields.io/npm/v/claude-multi-auth)](https://www.npmjs.com/package/claude-multi-auth)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Switch Claude Code and Claude Desktop between several Claude accounts on one
Mac, without logging out. Linux and Windows support is coming soon.

![cma demo](docs/assets/demo.gif)

Keep several Claude accounts logged in at once. If you use a work and a
personal account, or several organizations, you no longer have to sign out,
sign in again in the browser, and lose your place each time: log each
account in once, then switch with one command or one menu click. It ships as
**`cma`**, a command line tool that logs accounts in, stores them, switches
between them, shows usage and keeps backups, and **Claude Multi Auth.app**,
a menubar app that does the same through a menu, with the `cma` binary
inside.

## Features

- Switch Claude Code, Claude Desktop, or both to another account without
  logging out and back in.
- **Keep your Claude Desktop history across accounts.** Each account's
  sidebar and local sessions are still there when you switch back, and with
  *session follow* on, your local Code/Cowork sessions move with you to the
  account you switch to, so you can keep working in them.
- A menubar app that does everything through a menu, with launch at login.
- Optional usage display: each account's 5-hour and 7-day windows, off
  until you ask for it.
- Every change is journaled, backed up first, read back, and rolled back on
  failure; `cma restore` undoes any single operation.
- Aware of running `claude` sessions: asks before switching under them and
  keeps the tokens they refresh.
- `--json` on every command, with a documented contract for scripting.
- Never prints tokens or writes them to plain files; credentials stay in
  the macOS Keychain.

## Keep working when you switch accounts

Hit the usage limit on one account in the middle of a task? Switch and carry on:

- **Claude Code:** running `claude` sessions pick up the new account's token
  within about 30 seconds (their `/status` keeps the old name until
  restarted), and cma never touches your transcripts in
  `~/.claude/projects/`, so earlier conversations stay available to
  `claude --resume`.
- **Claude Desktop:** cma swaps Desktop's login without logging out (a
  logout would revoke it), so every account keeps its own sidebar and
  sessions. Turn on session follow (`cma config set session_follow on`, or
  the menubar toggle) and a Desktop switch also moves your local Code and
  Cowork sessions to the new account's sidebar, where they resume from
  their local transcripts.

Chats stored on claude.ai stay with the account that owns them; cma moves
only what lives on your Mac. Details:
[session follow](docs/usage.md#session-follow-desktop-only).

## Install

| Platform | Command line | Menubar app | Claude Desktop switching |
|----------|:------------:|:-----------:|:------------------------:|
| macOS 13+ (Apple silicon and Intel) | ✅ | ✅ | ✅ |
| Linux | 🚧 coming soon | 🚧 coming soon | — |
| Windows | 🚧 coming soon | 🚧 coming soon | 🚧 coming soon |

Claude Code must have been run and logged in at least once.

| You want | Run |
|----------|-----|
| Command line only (`cma`) | `npm install -g claude-multi-auth` (or `npx claude-multi-auth --cli`) |
| Menubar app only | `npx claude-multi-auth --app` |
| Both | `npx claude-multi-auth --all` |
| Choose interactively | `npx claude-multi-auth` |

- `npx claude-multi-auth` needs Node.js 18 or later and never uses `sudo`.
- The app is ad-hoc signed, not notarized: a browser-downloaded dmg needs
  the one-time **Open Anyway** step.
- Gatekeeper, release files and attestations, the app's **Install CLI**,
  uninstalling and building from source are in
  [docs/install.md](docs/install.md).

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

Start a new `claude` session after switching; `/status` shows the new
account. Accounts can be named by row number, alias, email, email prefix or
key prefix. The menubar app offers the same per account: **Switch CLI**,
**Switch Desktop** and **Switch CLI + Desktop**.

## Commands

| Command | What it does |
|---|---|
| `cma list [--live]` | List accounts with cached usage; `--live` refreshes it and lets you switch. |
| `cma status` | Active account, live login state, running sessions, warnings. |
| `cma login` | Log in an account in the browser without touching the active login. |
| `cma import-current` | Store the account Claude Code is logged in to now. |
| `cma switch [account]` | Switch Claude Code (default), Claude Desktop (`--desktop`), or both (`--both`). |
| `cma remove` / `cma alias` | Forget or name accounts. |
| `cma export` / `cma import` | Export credential files to a private directory, or import them (they hold refresh tokens). |
| `cma usage [account]` | Fetch usage once (opt-in). |
| `cma config get\|set` | Read or change settings. |
| `cma backups` / `cma restore <id>` / `cma clean` | List, restore and prune backups. |
| `cma resolve-journal` | Accept the current state after a rollback that could not finish. |
| `cma desktop import-current\|link\|unlink` | Link Claude Desktop logins to accounts. |

All flags, the exit codes and the menubar items are in
[docs/usage.md](docs/usage.md#commands). Every command accepts `--json`; the
contract is in [docs/json-api.md](docs/json-api.md).

## How it works

Claude Code keeps its login in the Keychain item `Claude Code-credentials`
and the displayed account in `oauthAccount` in `~/.claude.json`. A switch
takes cma's lock, stores any token Claude Code refreshed since the last
command, takes Claude Code's own lock, backs up what it will change, writes
the target credential, reads every write back, and journals the operation so
the next command rolls back an interrupted one. Token identity comes from
the token itself, never from `oauthAccount`. See
[docs/usage.md](docs/usage.md#how-switching-works) and
[docs/architecture.md](docs/architecture.md).

## What it touches & safety

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
> [How switching works](docs/usage.md#how-switching-works) and
> [Backups, restore and recovery](docs/usage.md#backups-restore-and-recovery)). The
> opt-in usage display calls Anthropic endpoints that are not public API
> (see [Usage display](docs/usage.md#usage-display-opt-in)).

The threat model, what is briefly visible to other processes of your user,
and the accepted limits are in [docs/security.md](docs/security.md).

## Documentation

- [docs/install.md](docs/install.md): requirements, installer details,
  Gatekeeper, release files, uninstall, building from source.
- [docs/usage.md](docs/usage.md): every command and flag, how switching
  works, usage display, backups, restore and recovery.
- [docs/security.md](docs/security.md): security notes and known limits.
- [docs/json-api.md](docs/json-api.md): the `--json` contract.
- [docs/architecture.md](docs/architecture.md): how the code is organized
  and how a switch is made safe.
- [docs/release.md](docs/release.md): how releases are built and published.
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
  [CHANGELOG.md](CHANGELOG.md).

## Contributing

Bug reports, ideas and pull requests are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems
privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). claude-multi-auth is not affiliated with Anthropic.
