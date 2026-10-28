# Contributing

Thanks for helping. claude-multi-auth handles login credentials, so changes
are held to a simple rule: never lose or leak a login. Read
[docs/architecture.md](docs/architecture.md) first; the module docs at the
top of each file in `crates/core/src/` explain the invariants in detail.

## Setup

- macOS 13 or later, with the Xcode command line tools.
- Rust: the toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
  (with `rustfmt` and `clippy`); `rustup` installs it on the first `cargo`
  command.
- Node.js with npm, for the menubar app in `app/`.

```sh
npm --prefix app ci
npm --prefix app run build     # type-check and build the webview into app/dist
cargo build --workspace
```

Build the frontend before the first `cargo build`/`test`/`clippy` of the
workspace: the app crate (`app/src-tauri`) embeds `app/dist` at compile
time.

To run the app against a debug `cma`:

```sh
cargo build -p cma
CMA_DEV_BIN=$PWD/target/debug/cma npm --prefix app run tauri dev
```

This uses your real Keychain and Claude state, like any `cma` build. Use
throwaway accounts when you try changes by hand.

## Checks

These are what CI runs ([`.github/workflows/ci.yml`](.github/workflows/ci.yml));
run them before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix app run build
node scripts/check-versions.mjs          # every version file agrees
npm --prefix npm test                    # the npm installer
node --test scripts/test/*.test.mjs      # the release scripts
```

How releases are built and published is in [docs/release.md](docs/release.md).

## Tests never touch your real state

- Core tests use an in-memory secret store and temporary directories.
- The CLI integration tests (`crates/cli/tests/`) run the real `cma` binary
  on a test backend: `CMA_SECRET_BACKEND=fake`, which redirects the
  Keychain, the HTTP endpoints, the process list, `claude auth login` and
  Claude Desktop control into files under `CMA_FAKE_DIR` (see
  [`crates/cli/src/testbackend.rs`](crates/cli/src/testbackend.rs) for the
  file formats).
- The backend exists only with the `test-backends` feature, which the
  crate's own dev-dependency enables for its tests. A release build refuses
  to compile with it, and any build without it refuses to start when
  `CMA_SECRET_BACKEND` is set.
- It also refuses to run unless `CMA_HOME` is set with
  `CMA_ALLOW_HOME_OVERRIDE=1`, and unless `HOME` and every Claude Code
  directory lie outside your real home directory. New integration tests
  should use the existing harness in `crates/cli/tests/cli.rs`, which sets
  up a temporary `HOME`, `CMA_HOME` and fake directory.
- Use dummy values only. Never put a real token, email or account id in a
  test or fixture.
- Tests that need the real Keychain are `#[ignore]` and use only the service
  `claude-multi-auth-test`. Run them deliberately with
  `cargo test -p cma-core -- --ignored keychain`. The
  [Uninstall](docs/install.md#uninstall) steps shows how to delete leftover test
  items.

## Regenerating the demo

The README demo is recorded with [VHS](https://github.com/charmbracelet/vhs)
on the test backend, so it shows only dummy accounts. From the repository
root:

```sh
vhs docs/assets/demo/demo.tape
```

The tape runs [`docs/assets/demo/seed.sh`](docs/assets/demo/seed.sh), which
builds a debug `cma` with `test-backends` into `target/agent`, seeds a
throwaway world under `$TMPDIR` and removes it when the recording ends (a
failed recording leaves it behind as `$TMPDIR/cma-demo.*`; delete it by
hand). It writes `docs/assets/demo.gif` and the still `docs/assets/demo.png`. To try
the fake world by hand, run `eval "$(docs/assets/demo/seed.sh)"` in a new
shell and `rm -rf "$CMA_DEMO_WORLD"` when done.

## Changes that need extra care

- **Anything that writes a login** (Keychain items, `~/.claude.json`,
  Claude Desktop's files): go through the backup and journal, read the
  write back, and keep the lock order in `crates/core/src/lock.rs`.
- **Secrets**: never in a file, a log, an error message, command output or
  a command line, except where the
  [security notes](docs/security.md#security-notes) say so.
- **The `--json` contract**: changes within `schema_version` 1 are additive
  only. Update [docs/json-api.md](docs/json-api.md) in the same change.
- **Claude Desktop data**: what counts as Desktop's login and where it keeps
  sessions is data in `crates/core/data/`. Say which Desktop version you
  checked a change against.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `chore:`, with
  an optional scope such as `fix(core):`, `feat(cli):` or `feat(app):`.
- Keep a pull request to one change, with tests for the behavior it
  changes, and update the README or the docs when user-visible behavior
  changes.
- Add a line under the unreleased section of [CHANGELOG.md](CHANGELOG.md)
  for user-visible changes.
- Report security problems privately; see [SECURITY.md](SECURITY.md).

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
