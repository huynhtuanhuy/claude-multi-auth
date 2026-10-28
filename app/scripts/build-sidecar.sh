#!/bin/sh
# Build the `cma` CLI in release mode and place it where Tauri's
# `bundle.externalBin` ("binaries/cma") expects it:
#   app/src-tauri/binaries/cma-<host target triple>
# The bundler then copies it to Claude Multi Auth.app/Contents/MacOS/cma.
#
# Run by `npm run bundle` (through tauri.bundle.conf.json's
# beforeBuildCommand). Honours an absolute CARGO_TARGET_DIR; without one the
# workspace target/ is used. Paths are resolved from this script's location,
# so the working directory does not matter.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$repo/target}
case $target_dir in
  /*) ;;
  *)
    echo "build-sidecar: CARGO_TARGET_DIR must be absolute (got: $target_dir)" >&2
    exit 1
    ;;
esac

# Same deployment target as the bundle (tauri.conf.json minimumSystemVersion).
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
triple=$(rustc --print host-tuple)
cargo build --manifest-path "$repo/Cargo.toml" -p cma --release --locked

src=$target_dir/release/cma
dest_dir=$repo/app/src-tauri/binaries
dest=$dest_dir/cma-$triple
mkdir -p "$dest_dir"
cp "$src" "$dest.tmp"
chmod 0755 "$dest.tmp"
mv -f "$dest.tmp" "$dest"
echo "build-sidecar: $dest"
