# Installing claude-multi-auth

How to install, update and remove the `cma` command line tool and the
Claude Multi Auth menubar app, and how to build both from source. The short
version is in the [README](../README.md#install).

- [Requirements](#requirements)
- [Install with npm](#install-with-npm)
- [Gatekeeper](#gatekeeper)
- [Other release files](#other-release-files)
- [The menubar app and Install CLI](#the-menubar-app-and-install-cli)
- [Uninstall](#uninstall)
- [Building from source](#building-from-source)

## Requirements

- macOS 13 or later.
- Claude Code, run and logged in at least once. cma refuses to work if `~/.claude` or
  `~/.claude.json` is missing. It never creates them.
- Optional: Claude Desktop, if you want to switch it too.
- To install with npm: Node.js 18 or later.
- To build: Rust (pinned in `rust-toolchain.toml`), Node.js with npm, and
  the Xcode command line tools.

## Install with npm

Every release has a universal build (Apple silicon and Intel) of both parts.
One installer, from npm, installs either or both:

| You want | Run |
|----------|-----|
| Command line only (`cma`) | `npm install -g claude-multi-auth` (or `npx claude-multi-auth --cli`) |
| Menubar app only | `npx claude-multi-auth --app` |
| Both | `npx claude-multi-auth --all` |
| Choose interactively | `npx claude-multi-auth` |

`npx claude-multi-auth` needs Node.js 18 or later. Without a flag it asks
what to install. The installer:

- **CLI:** runs `npm install -g claude-multi-auth@<its own version>`. The
  package contains the `cma` binary itself, so after a global install
  `cma` is on your `PATH` wherever npm puts global commands. It never uses
  `sudo`; if npm reports `EACCES`, give npm a global prefix you own
  ([npm docs](https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally)).
- **App:** downloads `Claude-Multi-Auth_<version>_universal.app.zip` from
  this project's GitHub Release of the **same version** (over https, from
  GitHub hosts only), checks its SHA-256 against a checksum that ships
  inside the npm package, and moves the app into `/Applications`, or
  `~/Applications` when `/Applications` is not writable. An older version
  there goes to the Trash. Quit the app first if it is running (on a
  terminal the installer waits for you to quit it).
- Run `claude-multi-auth --help` (after a global install) or
  `npx claude-multi-auth --help` for all options, including `--uninstall`
  and `--yes`.

## Gatekeeper

The app is ad-hoc signed and **not notarized** yet.

- Installed by `npx claude-multi-auth --app`: Node downloads the zip, so
  macOS does not mark it as downloaded from the internet ("quarantine") and
  it opens without a Gatekeeper prompt. This also means Gatekeeper does not
  check it; the installer's SHA-256 check is what verifies it.
- Downloaded in a browser: get `Claude-Multi-Auth_<version>_universal.dmg`
  from [Releases](https://github.com/huynhtuanhuy/claude-multi-auth/releases),
  open it and drag the app to Applications. The first time you open it,
  macOS refuses because the developer cannot be verified. Open
  System Settings → Privacy & Security, scroll to the message about
  Claude Multi Auth and click **Open Anyway**, then confirm.

## Other release files

The release also contains `cma-<version>-macos-universal.tar.gz` (just the
`cma` binary; put it on your `PATH`; a browser download needs
`xattr -d com.apple.quarantine cma` or the same Open Anyway step) and
`SHA256SUMS`. The dmg, zip, tarball and npm package each have a GitHub
build attestation:
`gh attestation verify <file> -R huynhtuanhuy/claude-multi-auth`.

How releases are built and published is in [release.md](release.md).

## The menubar app and Install CLI

1. The app lives in the menubar only (no Dock icon).
2. The app has its own copy of `cma` inside. **Install CLI** (in the
   menubar choose *Settings…*, then click **Install CLI**) creates a
   symlink `~/.local/bin/cma` that points to it, if you prefer that over
   the npm install:
   - Install CLI never overwrites a regular file at that path.
   - If a symlink there points somewhere else, it asks before replacing it.
   - If your shell does not find `cma`, add `~/.local/bin` to `PATH`. For zsh,
     put `export PATH="$HOME/.local/bin:$PATH"` in `~/.zshrc`.
   - You can also run the binary directly:
     `"/Applications/Claude Multi Auth.app/Contents/MacOS/cma"`.
   - With both installed, the `cma` that comes first on your `PATH` wins
     (`command -v cma` shows which). The installer points this out.

To build from source instead, see [Building from source](#building-from-source).

## Uninstall

The installer removes what it installed and nothing else:

```sh
npx claude-multi-auth --uninstall --all   # or --cli / --app
```

`--app` moves the app to the Trash; `--cli` runs
`npm uninstall -g claude-multi-auth`. Neither touches your accounts,
backups or Keychain items. To remove everything by hand, or what the
installer leaves behind:

1. In the app's *Settings…*, turn off **Launch at login**, then choose
   *Quit*.
   - If the app is already deleted, remove its LaunchAgent from
     `~/Library/LaunchAgents/` instead. It is the `.plist` file named after
     "Claude Multi Auth".
2. Delete `/Applications/Claude Multi Auth.app` (or
   `~/Applications/Claude Multi Auth.app`).
3. Remove the command line tool:
   - installed with npm: `npm uninstall -g claude-multi-auth`;
   - the app's Install CLI link:
     ```sh
     [ -L ~/.local/bin/cma ] && rm ~/.local/bin/cma
     ```
   - a `cma` binary from the tarball or built from source that you copied
     onto your `PATH`: delete that file.
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
git clone https://github.com/huynhtuanhuy/claude-multi-auth.git
cd claude-multi-auth
cargo build -p cma --release           # the CLI: target/release/cma
npm --prefix app ci
npm --prefix app run bundle            # the app (with cma inside)
```

Copy `target/release/cma` to a directory on your `PATH` (for example
`~/.local/bin`), and the app to `/Applications`.

How `npm --prefix app run bundle` works:

- It runs `tauri build` with
  [`app/src-tauri/tauri.bundle.conf.json`](../app/src-tauri/tauri.bundle.conf.json).
- That config's `beforeBuildCommand` runs
  [`app/scripts/build-sidecar.sh`](../app/scripts/build-sidecar.sh). The script
  builds `cma` in release mode and copies it to
  `app/src-tauri/binaries/cma-<target triple>`.
- Tauri then bundles it as `Contents/MacOS/cma`, and the app is ad-hoc
  signed.
- The result is
  `target/release/bundle/macos/Claude Multi Auth.app`, under
  `$CARGO_TARGET_DIR` if that is set. `CARGO_TARGET_DIR` must be an absolute
  path.
- `npm --prefix app run bundle -- --target universal-apple-darwin` builds
  the universal app the releases ship (needs
  `rustup target add aarch64-apple-darwin x86_64-apple-darwin`); the
  script then builds `cma` for both architectures and joins them with
  `lipo`. The result is under `target/universal-apple-darwin/release/`.
  How releases are made is in [release.md](release.md).
- The sidecar is kept out of `tauri.conf.json` on purpose. With it there,
  every plain `cargo build`/`test`/`clippy` of the workspace would need the
  sidecar binary to exist first.

Development builds of the app look for `cma` via `CMA_DEV_BIN`, for example
`CMA_DEV_BIN=$PWD/target/debug/cma npm --prefix app run tauri dev`. Release
builds ignore `CMA_DEV_BIN` and use only the `cma` inside the bundle.

Running the tests, the checks CI runs, and how the tests stay away from
your real Keychain and Claude state are in
[CONTRIBUTING.md](../CONTRIBUTING.md). How the code is organized is in
[architecture.md](architecture.md).
