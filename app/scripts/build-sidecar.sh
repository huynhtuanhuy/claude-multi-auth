#!/bin/sh
# Build the `cma` CLI in release mode and place it where Tauri's
# `bundle.externalBin` ("binaries/cma") expects it:
#   app/src-tauri/binaries/cma-<target triple>
# The bundler then copies it to Claude Multi Auth.app/Contents/MacOS/cma.
#
# Run by `npm run bundle` (through tauri.bundle.conf.json's
# beforeBuildCommand). The target triple is, in order:
#   1. CMA_SIDECAR_TARGET, if set;
#   2. TAURI_ENV_TARGET_TRIPLE, which `tauri build` sets for this command
#      (so `npm run bundle -- --target universal-apple-darwin` just works);
#   3. the host triple.
# For `universal-apple-darwin` the script builds both Apple targets and
# joins them with `lipo` into one universal binary. It also keeps the two
# per-architecture binaries next to it: Tauri compiles the app once per
# architecture, and each of those builds checks that its own
# `binaries/cma-<arch triple>` exists.
#
# Honours an absolute CARGO_TARGET_DIR; without one the workspace target/ is
# used. Paths are resolved from this script's location, so the working
# directory does not matter.
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
host=$(rustc --print host-tuple)
triple=${CMA_SIDECAR_TARGET:-${TAURI_ENV_TARGET_TRIPLE:-$host}}
echo "build-sidecar: target $triple"

# Copy a built binary to binaries/cma-<triple>, replacing it atomically.
place() {
  cp "$1" "$dest_dir/cma-$2.tmp"
  chmod 0755 "$dest_dir/cma-$2.tmp"
  mv -f "$dest_dir/cma-$2.tmp" "$dest_dir/cma-$2"
  echo "build-sidecar: $dest_dir/cma-$2"
}

# Build `cma` for one rustc target and print the path of the result.
build_one() {
  if [ "$1" = "$host" ]; then
    # Host build: target/release, shared with a plain `cargo build --release`.
    cargo build --manifest-path "$repo/Cargo.toml" -p cma --release --locked >&2
    echo "$target_dir/release/cma"
  else
    cargo build --manifest-path "$repo/Cargo.toml" -p cma --release --locked --target "$1" >&2
    echo "$target_dir/$1/release/cma"
  fi
}

dest_dir=$repo/app/src-tauri/binaries
dest=$dest_dir/cma-$triple
mkdir -p "$dest_dir"
rm -f "$dest.tmp"

case $triple in
  universal-apple-darwin)
    arm=$(build_one aarch64-apple-darwin)
    intel=$(build_one x86_64-apple-darwin)
    place "$arm" aarch64-apple-darwin
    place "$intel" x86_64-apple-darwin
    lipo -create "$arm" "$intel" -output "$dest.tmp"
    # Each slice keeps the linker's ad-hoc signature; sign the fat file as a
    # whole as well so `codesign --verify --strict` accepts it on its own.
    codesign --force --sign - "$dest.tmp"
    archs=$(lipo -archs "$dest.tmp")
    for arch in arm64 x86_64; do
      case " $archs " in
        *" $arch "*) ;;
        *)
          echo "build-sidecar: universal binary has archs '$archs', expected arm64 and x86_64" >&2
          exit 1
          ;;
      esac
    done
    ;;
  *)
    src=$(build_one "$triple")
    cp "$src" "$dest.tmp"
    ;;
esac

chmod 0755 "$dest.tmp"
mv -f "$dest.tmp" "$dest"
echo "build-sidecar: $dest"
