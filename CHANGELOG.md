# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

First release.

### Added

- `cma` command line tool for macOS: store several Claude accounts and
  switch Claude Code between them without logging out (`login`,
  `import-current`, `list`, `status`, `switch`, `remove`, `alias`).
- Isolated `cma login` that runs `claude auth login` without touching the
  account Claude Code is using.
- Claude Desktop target: link accounts (`cma desktop link`,
  `cma desktop import-current`, `cma desktop unlink`) and switch Desktop
  (`cma switch --desktop`) or both apps (`cma switch --both`) without
  logging Desktop out; optional session follow (`session_follow`).
- Safe writes: every change is backed up, journaled, read back and rolled
  back on failure or after a crash; `backups`, `restore`, `resolve-journal`
  and `clean`.
- Opt-in usage display (`cma usage`, `cma list --live`) with background
  token refresh for inactive accounts.
- `export` and `import` of stored Claude Code credentials.
- `--json` on every command, with a versioned contract
  ([docs/json-api.md](docs/json-api.md)).
- Claude Multi Auth.app, a menubar app with the `cma` binary inside:
  switch Claude Code and Claude Desktop per account, link Desktop, add
  accounts, toggle session follow, view backups and settings, install the
  CLI, and launch at login.
