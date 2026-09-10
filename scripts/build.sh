#!/usr/bin/env bash
# Build the koolearn-video-crypt-skill command-line tools.
#
# Usage:
#   ./scripts/build.sh                  # build for the host platform
#   ./scripts/build.sh -all             # cross-compile every supported target
#   ./scripts/build.sh windows amd64    # explicit GOOS / GOARCH
#   ./scripts/build.sh -o dist          # custom output directory
#
# Binaries are written to <out>/<goos>-<goarch>/ . The tools are pure Go with
# no cgo and no third-party dependencies, so cross-compiling needs nothing else.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="bin"
GOOS_ARG=""
GOARCH_ARG=""
ALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    -all|--all)      ALL=1; shift ;;
    -o|--out)        OUT="$2"; shift 2 ;;
    -h|--help)       sed -n '2,11p' "$0"; exit 0 ;;
    -*)              echo "unknown flag: $1" >&2; exit 2 ;;
    *)               if [ -z "$GOOS_ARG" ]; then GOOS_ARG="$1"
                     elif [ -z "$GOARCH_ARG" ]; then GOARCH_ARG="$1"
                     else echo "unexpected argument: $1" >&2; exit 2; fi
                     shift ;;
  esac
done

CMDS="vodexport hlsget vodkey"

if ! command -v go >/dev/null 2>&1; then
  echo "error: go is not installed or not in PATH (need Go 1.23+)" >&2
  exit 1
fi

build_one() {
  local goos="$1" goarch="$2" ext="" dest
  [ "$goos" = "windows" ] && ext=".exe"
  dest="$OUT/$goos-$goarch"
  mkdir -p "$dest"
  for cmd in $CMDS; do
    printf '  %-9s %s/%s\n' "$cmd" "$goos" "$goarch"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
      go build -trimpath -ldflags "-s -w" -o "$dest/$cmd$ext" "./cmd/$cmd"
  done
}

if [ "$ALL" = "1" ]; then
  for t in "windows amd64" "windows arm64" "darwin amd64" "darwin arm64"; do
    build_one $t
  done
elif [ -n "$GOOS_ARG" ]; then
  build_one "$GOOS_ARG" "${GOARCH_ARG:-$(go env GOARCH)}"
else
  build_one "$(go env GOOS)" "$(go env GOARCH)"
fi

echo "done -> $OUT/"
