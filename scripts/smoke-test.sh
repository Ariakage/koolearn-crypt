#!/usr/bin/env bash
# smoke-test.sh — synthetic end-to-end check for vodexport.
#
# It needs no koolearn key material: a plaintext HLS VOD (METHOD=NONE) is
# generated with ffmpeg into a fake download root, so the export path runs
# without decryption. Because that cache holds no key container, these runs also
# exercise the -token auto fallback (nothing to recover, v2 check skipped).
# Four paths are covered:
#   1) -list discovers the video without a token
#   2) -no-mux concatenation is byte-identical to the plaintext source
#   3) the default remux produces a playable MP4 (~6s)
#   4) a PATH without ffmpeg makes the tool degrade to .ts instead of failing
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/bin/vodexport"

c_cyan=$'\033[36m'; c_green=$'\033[32m'; c_red=$'\033[31m'; c_off=$'\033[0m'
log() { printf '%s[smoke]%s %s\n' "$c_cyan" "$c_off" "$*"; }
pass(){ printf '%s[PASS]%s %s\n' "$c_green" "$c_off" "$*"; }
die() { printf '%s[FAIL]%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }

for dep in ffmpeg ffprobe; do
  command -v "$dep" >/dev/null 2>&1 || die "$dep not found in PATH"
done

md5of() { md5 -q "$1" 2>/dev/null || md5sum "$1" | awk '{print $1}'; }

log "building vodexport ..."
mkdir -p "$(dirname "$BIN")"
( cd "$REPO" && go build -o "$BIN" ./cmd/vodexport )

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vodexport-smoke.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

ROOT="$WORK/root"
ID="6p0f88testvideo"
VID="$ROOT/$ID"
mkdir -p "$VID"

ffmpeg -v error -y \
  -f lavfi -i testsrc=duration=6:size=320x240:rate=25 \
  -f lavfi -i sine=frequency=440:duration=6 \
  -c:v libx264 -pix_fmt yuv420p -g 50 -sc_threshold 0 -c:a aac -shortest \
  -hls_time 2 -hls_playlist_type vod \
  -hls_segment_filename "$VID/seg%03d.ts" "$VID/index.m3u8"

cat "$VID"/seg*.ts > "$WORK/truth.ts"
TRUTH="$(md5of "$WORK/truth.ts")"

log "discover:"
"$BIN" -q -list "$ROOT"

log "no-mux:"
"$BIN" -q -no-mux -out "$WORK/out-ts" "$ROOT"
GOT="$(md5of "$WORK/out-ts/$ID.ts")"
[[ "$GOT" == "$TRUTH" ]] || die "ts mismatch: got $GOT want $TRUTH"
pass "no-mux: .ts is byte-identical to the plaintext source"

log "remux to mp4:"
"$BIN" -q -out "$WORK/out-mp4" "$ROOT"
[[ -s "$WORK/out-mp4/$ID.mp4" ]] || die "no mp4 produced"
DUR="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$WORK/out-mp4/$ID.mp4")"
awk -v d="$DUR" 'BEGIN{exit !(d>5 && d<7.5)}' || die "unexpected mp4 duration $DUR"
pass "remux: mp4 produced (duration=${DUR}s)"

log "ffmpeg-missing fallback:"
env PATH=/usr/bin:/bin "$BIN" -out "$WORK/out-fb" "$ROOT"
[[ -f "$WORK/out-fb/$ID.ts" ]] || die "no .ts fallback"
pass "fallback: degraded to .ts when ffmpeg is absent"

printf '\n%s[smoke] ALL PASS%s\n' "$c_green" "$c_off"
