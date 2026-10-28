# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [0.1.2] - 2026-10-28

### Changed

- npm releases are staged by CI and published only after a maintainer
  approves them with 2FA. 0.1.1 was released on GitHub but not on npm.

## [0.1.1] - 2026-10-28

### Fixed

- The release workflow now publishes the npm package (it passed the tarball
  path in a form npm read as a GitHub repository).

## [0.1.0] - 2026-10-28

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
- Releases with universal (Apple silicon and Intel) builds: the app as
  `.dmg` and `.app.zip`, `cma` as a tarball, `SHA256SUMS`, and GitHub build
  attestations.
- npm package `claude-multi-auth` with an installer
  (`npx claude-multi-auth`): install the command line tool, the menubar app,
  or both (`--cli`, `--app`, `--all`), and uninstall them (`--uninstall`).
  The app is downloaded from the GitHub Release of the same version and
  checked against a SHA-256 shipped in the package.
