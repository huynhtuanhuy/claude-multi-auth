#!/bin/sh
# Turn a universal build into the release assets and the npm package.
#
#   scripts/package-release.sh <Claude Multi Auth.app> <universal cma> <out dir>
#
# Checks first, then writes:
#   <out>/release/Claude-Multi-Auth_<v>_universal.app.zip
#   <out>/release/Claude-Multi-Auth_<v>_universal.dmg
#   <out>/release/cma-<v>-macos-universal.tar.gz
#   <out>/release/SHA256SUMS
#   <out>/npm/package/                   staged npm package (with bin/cma and
#                                        checksums.json)
#   <out>/npm/claude-multi-auth-<v>.tgz  `npm pack` of it, what gets published
#
# Checks: both binaries are universal (arm64 + x86_64), the app passes
# `codesign --verify --deep --strict`, and the app, `cma --version` and every
# version file (scripts/check-versions.mjs) agree. Used by the release
# workflow and runnable locally; it only writes under <out dir>.
set -eu

if [ $# -ne 3 ]; then
  echo "usage: package-release.sh <Claude Multi Auth.app> <universal cma> <out dir>" >&2
  exit 1
fi
app=$1
cma=$2
out=$3
repo=$(cd "$(dirname "$0")/.." && pwd)

fail() {
  echo "package-release: $*" >&2
  exit 1
}

[ -d "$app/Contents" ] || fail "not an app bundle: $app"
[ -x "$cma" ] || fail "not an executable: $cma"
[ "$(basename "$app")" = "Claude Multi Auth.app" ] || fail "unexpected bundle name: $(basename "$app")"

mkdir -p "$out"
out=$(cd "$out" && pwd)

version=$(node "$repo/scripts/check-versions.mjs")
echo "package-release: version $version"

# --- checks ---------------------------------------------------------------

check_universal() {
  archs=$(lipo -archs "$1")
  for arch in arm64 x86_64; do
    case " $archs " in
      *" $arch "*) ;;
      *) fail "$1 has archs '$archs', expected arm64 and x86_64" ;;
    esac
  done
  echo "package-release: $(basename "$1"): $archs"
}
check_universal "$cma"
check_universal "$app/Contents/MacOS/claude-multi-auth"
check_universal "$app/Contents/MacOS/cma"

codesign --verify --deep --strict "$app" || fail "codesign verification failed for $app"
codesign --verify --strict "$cma" || fail "codesign verification failed for $cma"

app_version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")
[ "$app_version" = "$version" ] || fail "app version is $app_version, expected $version"
for bin in "$cma" "$app/Contents/MacOS/cma"; do
  got=$("$bin" --version)
  [ "$got" = "cma $version" ] || fail "$bin --version printed '$got', expected 'cma $version'"
done

# --- release assets -------------------------------------------------------

zip_name=Claude-Multi-Auth_${version}_universal.app.zip
dmg_name=Claude-Multi-Auth_${version}_universal.dmg
tar_name=cma-${version}-macos-universal.tar.gz

rel=$out/release
npm_out=$out/npm
rm -rf "$rel" "$npm_out"
mkdir -p "$rel" "$npm_out"
work=$(mktemp -d "${TMPDIR:-/tmp}/cma-package.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

# Never ship AppleDouble (._*) files in the archives.
export COPYFILE_DISABLE=1

ditto -c -k --keepParent "$app" "$rel/$zip_name"

mkdir "$work/dmg"
ditto "$app" "$work/dmg/Claude Multi Auth.app"
ln -s /Applications "$work/dmg/Applications"
# hdiutil occasionally fails with "Resource busy" on CI runners; retry.
tries=0
until hdiutil create -quiet -volname "Claude Multi Auth" -srcfolder "$work/dmg" \
  -fs HFS+ -format UDZO -ov "$rel/$dmg_name"; do
  tries=$((tries + 1))
  [ "$tries" -lt 3 ] || fail "hdiutil create failed"
  sleep 5
done
hdiutil verify -quiet "$rel/$dmg_name" || fail "hdiutil verify failed"

mkdir "$work/tar"
cp "$cma" "$work/tar/cma"
chmod 0755 "$work/tar/cma"
cp "$repo/LICENSE" "$work/tar/LICENSE"
tar -czf "$rel/$tar_name" --uid 0 --gid 0 -C "$work/tar" cma LICENSE

(cd "$rel" && shasum -a 256 "$zip_name" "$dmg_name" "$tar_name" > SHA256SUMS)

# --- npm package ----------------------------------------------------------

stage=$npm_out/package
mkdir -p "$stage/bin" "$stage/lib"
cp "$repo/npm/package.json" "$repo/npm/README.md" "$repo/npm/installer.mjs" "$stage/"
cp "$repo/npm/lib/installer.mjs" "$stage/lib/"
cp "$repo/LICENSE" "$stage/"
cp "$cma" "$stage/bin/cma"
chmod 0755 "$stage/bin/cma" "$stage/installer.mjs"

# The installer verifies the downloaded app against this, so the app's
# integrity rests on the npm package, not on the download host.
node - "$rel/SHA256SUMS" "$version" "$stage/checksums.json" <<'EOF'
const fs = require('node:fs');
const [sumsPath, version, outPath] = process.argv.slice(2);
const files = {};
for (const line of fs.readFileSync(sumsPath, 'utf8').split('\n')) {
  const m = line.match(/^([0-9a-f]{64}) [ *](.+)$/);
  if (m) files[m[2]] = m[1];
}
fs.writeFileSync(outPath, JSON.stringify({ version, files }, null, 2) + '\n');
EOF

(cd "$stage" && npm pack --ignore-scripts --pack-destination "$npm_out" >/dev/null)
tgz=$npm_out/claude-multi-auth-$version.tgz
[ -f "$tgz" ] || fail "npm pack did not produce $tgz"

echo "package-release: wrote"
ls -l "$rel" "$tgz"
cat "$rel/SHA256SUMS"
