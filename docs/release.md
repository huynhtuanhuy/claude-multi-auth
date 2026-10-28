# Releasing

How a version of claude-multi-auth gets from `main` to GitHub Releases and
npm. The workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## What a release contains

| File | What it is |
|------|------------|
| `Claude-Multi-Auth_<v>_universal.dmg` | The menubar app, for browser downloads. |
| `Claude-Multi-Auth_<v>_universal.app.zip` | The same app; the npm installer downloads this one. |
| `cma-<v>-macos-universal.tar.gz` | The `cma` binary and `LICENSE`. |
| `SHA256SUMS` | SHA-256 of the three files above. |
| npm `claude-multi-auth@<v>` | `cma` (as `bin/cma`), the installer (`claude-multi-auth`), and `checksums.json` with the SHA-256 of the files above. |

Every binary is universal (Apple silicon and Intel), ad-hoc signed and not
notarized.

## Before the first release (once)

1. **Make the repository public.** npm provenance and GitHub build
   attestations are not available for private repositories, so a tag push
   from a private repository fails at those steps.
2. **Claim the npm name with a manual first publish.** A trusted publisher
   can only be configured for a package that exists, so the very first
   `npm publish` is done by hand from your machine:
   1. Push the first tag as in [Cutting a release](#cutting-a-release). The
      build and the GitHub Release succeed; the npm job fails because no
      trusted publisher is configured yet. That is expected.
   2. Download the npm tarball that run built and publish it:
      ```sh
      gh run download <run id> -R huynhtuanhuy/claude-multi-auth -n npm-package -D first-publish
      npm login
      npm publish first-publish/claude-multi-auth-<v>.tgz --access public --provenance=false
      ```
      Publish this tarball rather than one from a local
      `scripts/package-release.sh` run: its `checksums.json` holds the
      SHA-256 of the app zip attached to the release, and a local build's
      zip has a different checksum, so its installer would refuse the
      release's app. A publish from your machine carries no provenance;
      later CI publishes do.
3. **Configure npm trusted publishing.** On npmjs.com, open the package's
   *Settings* → *Trusted publishing*, choose GitHub Actions and enter:
   - organization or user: `huynhtuanhuy`
   - repository: `claude-multi-auth`
   - workflow filename: `release.yml`
   - environment: leave empty

   From then on the workflow publishes with a short-lived OIDC token; there
   is no `NPM_TOKEN` secret. Afterwards you can disallow token publishing in
   the same settings page.

## Cutting a release

1. Bump the version in all of these (they must match; CI checks with
   `node scripts/check-versions.mjs`):
   - `Cargo.toml` (`[workspace.package] version`), then `cargo check` to
     update `Cargo.lock`;
   - `app/package.json` and `app/package-lock.json`
     (`npm --prefix app version <v> --no-git-tag-version`);
   - `app/src-tauri/tauri.conf.json`;
   - `npm/package.json`.
2. In `CHANGELOG.md`, give the version's heading its date:
   `## [<v>] - YYYY-MM-DD`. The workflow refuses a heading that still says
   "unreleased", and uses the section's text as the release notes.
3. Commit, push to `main`, and wait for CI on `main` to pass.
4. Tag that exact commit and push the tag:
   ```sh
   git tag -a v<v> -m v<v>
   git push origin v<v>
   ```
   Tags with a pre-release suffix (`v1.2.0-rc.1`, `-alpha`, `-beta`) make a
   GitHub pre-release and publish to npm under the `next` dist-tag instead of
   `latest`.

## What the workflow does

1. **Resolve version.** The tag must equal every version file. The
   CHANGELOG must have a dated section for it.
2. **Verify main CI.** The latest completed `ci.yml` run on `main` must be
   for the tagged commit and must have succeeded. If you tagged while CI was
   still running, wait for it to finish and re-run the workflow.
3. **Build** on `macos-latest`, without a build cache:
   - `npm --prefix app run bundle -- --target universal-apple-darwin`. Its
     `beforeBuildCommand` runs `app/scripts/build-sidecar.sh`, which builds
     `cma` for both architectures and joins them with `lipo`.
   - [`scripts/package-release.sh`](../scripts/package-release.sh) checks
     that every binary has both architectures, that
     `codesign --verify --deep --strict` passes, and that `cma --version` and
     the app's version match. It then writes the zip, dmg, tarball,
     `SHA256SUMS`, and the npm package with `checksums.json`, and runs
     `npm pack`.
   - GitHub build provenance attestations for all of them
     (`gh attestation verify <file> -R huynhtuanhuy/claude-multi-auth`).
4. **GitHub Release** with the CHANGELOG section as notes and the files
   attached.
5. **npm publish** of the packed tarball, after the release exists, so the
   installer can always download its app.

If a later job fails, fix the cause and use *Re-run failed jobs*. A release
that was already created makes the release job fail on re-run; delete the
release (not the tag) first.

## Dry runs

*Actions* → *Release* → *Run workflow* with `dry_run` checked (the default)
runs the build and packaging on any branch and uploads the results as
workflow artifacts (`release-assets`, `npm-package`, `release-notes`). It
creates no release, publishes nothing and skips the main CI check and the
attestations. A manual run with `dry_run` unchecked fails on purpose:
publishing happens only from a pushed tag.

## Trying the release build locally

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm --prefix app ci
npm --prefix app run bundle -- --target universal-apple-darwin
sh scripts/package-release.sh \
  "target/universal-apple-darwin/release/bundle/macos/Claude Multi Auth.app" \
  app/src-tauri/binaries/cma-universal-apple-darwin \
  dist
```

With `CARGO_TARGET_DIR` set, the app is under
`$CARGO_TARGET_DIR/universal-apple-darwin/release/bundle/macos/`.

To try the packed npm package without touching your real global install,
install it into a temporary prefix:

```sh
tmp=$(mktemp -d)
npm install -g --prefix "$tmp" dist/npm/claude-multi-auth-<v>.tgz
"$tmp/bin/cma" --version
"$tmp/bin/claude-multi-auth" --help
```

The installer has three environment variables for testing only:

| Variable | Effect |
|----------|--------|
| `CMA_INSTALLER_APPS_DIR` | Install into, and uninstall from, this directory instead of `/Applications` and `~/Applications`. |
| `CMA_INSTALLER_BASE_URL` | Download the app zip from this base URL (for example a local `http://127.0.0.1:<port>/`) instead of the GitHub release. Only that origin is allowed. |
| `CMA_INSTALLER_TRASH_DIR` | Move replaced or uninstalled apps here instead of the Trash. |

The SHA-256 check against the package's `checksums.json` always applies.
Never run `--cli` while testing: it is a real `npm install -g`.

The installer's unit tests run with `npm --prefix npm test`; the release
scripts' with `node --test scripts/test/*.test.mjs`.

## Notarization (later)

The app is ad-hoc signed only, so a browser download needs the Gatekeeper
"Open Anyway" step (see [Gatekeeper](install.md#gatekeeper)). Notarizing it needs an Apple Developer
ID. When there is one, add these repository secrets and pass them to the
build step: Tauri signs and notarizes during `tauri build` when they are set.

- `APPLE_CERTIFICATE` (base64 `.p12`) and `APPLE_CERTIFICATE_PASSWORD`;
- `APPLE_SIGNING_IDENTITY` (`Developer ID Application: …`), replacing
  `"signingIdentity": "-"` in `app/src-tauri/tauri.conf.json`;
- `APPLE_ID`, `APPLE_PASSWORD` (an app-specific password) and
  `APPLE_TEAM_ID`, or an App Store Connect API key (`APPLE_API_ISSUER`,
  `APPLE_API_KEY`, `APPLE_API_KEY_PATH`).

The standalone `cma` in the tarball and the npm package would then need
`codesign` with the same identity and `notarytool` too, and the dmg built by
`scripts/package-release.sh` should be signed, notarized and stapled.
