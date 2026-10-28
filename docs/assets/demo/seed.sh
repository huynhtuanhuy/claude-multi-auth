#!/usr/bin/env bash
# Seed a throwaway, fully fake world for recording the README demo.
#
# Builds a debug `cma` with the test backend (CMA_SECRET_BACKEND=fake), creates
# a fresh temporary HOME / CMA_HOME / fake-backend dir under $TMPDIR, registers
# dummy accounts through the fake Keychain, profile and usage endpoints, and
# prints the `export` lines that point a shell at that world:
#
#   eval "$(docs/assets/demo/seed.sh)"
#
# Nothing here touches the real ~/.claude, ~/.claude.json, ~/.claude-multi-auth,
# the Keychain or Claude Desktop: the fake backend refuses to run unless every
# Claude path lies outside the real home directory. All tokens are dummies.
# Remove the world afterwards with: rm -rf "$CMA_DEMO_WORLD"
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
target_dir="${CMA_DEMO_TARGET_DIR:-$repo/target/agent}"

# Build quietly; progress goes to stderr so stdout stays eval-able.
CARGO_TARGET_DIR="$target_dir" cargo build --quiet -p cma --features test-backends \
  --manifest-path "$repo/Cargo.toml" >&2
bin_dir="$target_dir/debug"
[ -x "$bin_dir/cma" ] || { echo "seed.sh: $bin_dir/cma was not built" >&2; exit 1; }

world="$(mktemp -d "${TMPDIR:-/tmp}/cma-demo.XXXXXX")"
case "$(cd "$world" && pwd -P)" in
  "$(cd ~ && pwd -P)"/*) echo "seed.sh: $world is inside the real home; set TMPDIR elsewhere" >&2; rm -rf "$world"; exit 1 ;;
esac
# Remove the half-built world if any step below fails.
trap 'rc=$?; [ "$rc" -eq 0 ] || rm -rf "$world"' EXIT
home="$world/home"
fake="$world/fake"
mkdir -p "$home/.claude" "$fake" # cma creates CMA_HOME itself, mode 700
printf '{"numStartups": 3}\n' >"$home/.claude.json"

far=4000000000000 # expiry far in the future, in ms
# Reset times relative to now so the demo shows sensible "resets in" values.
iso() { date -u -v+"$1" '+%Y-%m-%dT%H:%M:%S+00:00'; }

oauth() { # tag plan
  printf '{"accessToken":"dummy-access-%s","refreshToken":"dummy-refresh-%s","expiresAt":%s,"refreshTokenExpiresAt":%s,"scopes":["user:inference","user:profile"],"subscriptionType":"%s"}' \
    "$1" "$1" "$far" "$far" "$2"
}

cat >"$fake/profiles.json" <<JSON
{
  "dummy-access-work": {
    "account": {"uuid": "11111111-1111-4111-8111-111111111111", "email": "work@example.com", "display_name": "Demo"},
    "organization": {"uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "name": "Acme Inc"}
  },
  "dummy-access-personal": {
    "account": {"uuid": "22222222-2222-4222-8222-222222222222", "email": "personal@example.com", "display_name": "Demo"},
    "organization": {"uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "name": "Personal"}
  },
  "dummy-access-side": {
    "account": {"uuid": "33333333-3333-4333-8333-333333333333", "email": "side@example.com", "display_name": "Demo"},
    "organization": {"uuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "name": "Side LLC"}
  }
}
JSON

cat >"$fake/usage.json" <<JSON
{
  "dummy-access-work": {
    "five_hour": {"utilization": 82.0, "resets_at": "$(iso 1H)"},
    "seven_day": {"utilization": 64.0, "resets_at": "$(iso 3d)"}
  },
  "dummy-access-personal": {
    "five_hour": {"utilization": 12.0, "resets_at": "$(iso 4H)"},
    "seven_day": {"utilization": 23.0, "resets_at": "$(iso 5d)"}
  },
  "dummy-access-side": {
    "five_hour": {"utilization": 0.0, "resets_at": null},
    "seven_day": {"utilization": 7.0, "resets_at": "$(iso 6d)"}
  }
}
JSON

# The live Claude Code login (fake Keychain item) is the work account.
user=demo
printf '[{"service":"Claude Code-credentials","account":"%s","value":%s}]\n' \
  "$user" "$(printf '{"claudeAiOauth":%s}' "$(oauth work max)" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')" \
  >"$fake/secrets.json"

export HOME="$home" USER="$user" CMA_HOME="$world/cma-home" CMA_ALLOW_HOME_OVERRIDE=1 \
  CMA_SECRET_BACKEND=fake CMA_FAKE_DIR="$fake"
cma="$bin_dir/cma"
"$cma" import-current --json >/dev/null
"$cma" alias set 1 work --json >/dev/null
oauth personal pro >"$fake/login.json"
"$cma" login --alias personal --json >/dev/null
oauth side pro >"$fake/login.json"
"$cma" login --alias side --json >/dev/null
rm -f "$fake/login.json" "$fake/requests.log"
"$cma" usage --json >/dev/null # warm the usage cache

# One running `claude` session, so a switch asks for confirmation.
printf '4242 1 -zsh\n4243 4242 claude\n' >"$fake/ps.txt"

cat <<EOF
export CMA_DEMO_WORLD='$world'
export HOME='$home'
export USER='$user'
export CMA_HOME='$world/cma-home'
export CMA_ALLOW_HOME_OVERRIDE=1
export CMA_SECRET_BACKEND=fake
export CMA_FAKE_DIR='$fake'
export PATH='$bin_dir':/usr/bin:/bin
EOF
