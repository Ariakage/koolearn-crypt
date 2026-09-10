#!/usr/bin/env bash
# e2e-test.sh — end-to-end verification for scheme B (standard HLS AES-128).
#
# It builds a local encrypted HLS stream with ffmpeg + openssl, serves it over
# HTTP, runs `hlsget`, and checks that the decrypted+concatenated output is
# byte-identical to the plaintext source. Two scenarios are covered:
#   1) explicit static IV in #EXT-X-KEY
#   2) default IV = media sequence number (no IV attribute)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/bin/hlsget"
PORT="${PORT:-8791}"
HOST="127.0.0.1"

c_cyan=$'\033[36m'; c_green=$'\033[32m'; c_red=$'\033[31m'; c_off=$'\033[0m'
log() { printf '%s[e2e]%s %s\n' "$c_cyan" "$c_off" "$*"; }
pass(){ printf '%s[PASS]%s %s\n' "$c_green" "$c_off" "$*"; }
die() { printf '%s[FAIL]%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }

# A PYTHONHOME/PYTHONPATH inherited from the caller's shell can point at a
# different interpreter and make python3 abort before it starts; drop them only
# when python3 is currently unusable, leaving healthy environments untouched.
if ! python3 -c 'pass' >/dev/null 2>&1; then
  unset PYTHONHOME PYTHONPATH
fi

for dep in ffmpeg ffprobe openssl python3; do
  command -v "$dep" >/dev/null 2>&1 || die "$dep not found in PATH"
done

md5of() { md5 -q "$1" 2>/dev/null || md5sum "$1" | awk '{print $1}'; }

log "building hlsget ..."
mkdir -p "$(dirname "$BIN")"
( cd "$REPO" && go build -o "$BIN" ./cmd/hlsget )

WORK="$(mktemp -d "${TMPDIR:-/tmp}/hlsb-e2e.XXXXXX")"
SRV_PID=""
cleanup() {
  [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
  [[ -n "$SRV_PID" ]] && wait "$SRV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# gen_plain <dir>  — produce a 6s VOD HLS (2s segments) with plaintext .ts
gen_plain() {
  local d="$1"; mkdir -p "$d"
  ffmpeg -v error -y \
    -f lavfi -i testsrc=duration=6:size=320x240:rate=25 \
    -f lavfi -i sine=frequency=440:duration=6 \
    -c:v libx264 -pix_fmt yuv420p -g 50 -sc_threshold 0 -c:a aac -shortest \
    -hls_time 2 -hls_playlist_type vod \
    -hls_segment_filename "$d/seg%03d.ts" "$d/index.m3u8"
}

# scenario <name> <iv_mode: fixed|seq>
scenario() {
  local name="$1" iv_mode="$2"
  local d="$WORK/$name"
  log "── scenario: $name (iv=$iv_mode) ──"
  gen_plain "$d"

  # ground truth = concatenation of the plaintext segments
  cat "$d"/seg*.ts > "$d/_truth.ts"
  local gt; gt="$(md5of "$d/_truth.ts")"
  local nseg; nseg="$(ls "$d"/seg*.ts | grep -v _truth | wc -l | tr -d ' ')"
  log "  plaintext: $nseg segments, truth md5=$gt"
  [[ "$nseg" -ge 3 ]] || die "expected >=3 segments, got $nseg (GOP/keyframe issue)"

  # 16-byte raw key file + hex key
  local keyhex ivhex
  keyhex="$(openssl rand -hex 16)"
  ivhex="$(openssl rand -hex 16)"
  python3 - "$d/key.bin" "$keyhex" <<'PY'
import sys, binascii
open(sys.argv[1], 'wb').write(binascii.unhexlify(sys.argv[2]))
PY

  # encrypt each segment with AES-128-CBC + PKCS#7 (openssl default)
  local i=0 iv f
  for f in "$d"/seg*.ts; do
    if [[ "$iv_mode" == "fixed" ]]; then iv="$ivhex"; else iv="$(printf '%032x' "$i")"; fi
    openssl enc -aes-128-cbc -K "$keyhex" -iv "$iv" -in "$f" -out "$f.enc"
    mv -f "$f.enc" "$f"
    i=$((i + 1))
  done

  # rebuild the playlist: drop the plaintext one, inject #EXT-X-KEY
  local keyline='#EXT-X-KEY:METHOD=AES-128,URI="key.bin"'
  [[ "$iv_mode" == "fixed" ]] && keyline="$keyline,IV=0x$ivhex"
  local tmp="$d/_pl.m3u8"
  awk -v kl="$keyline" 'NR==1{print; print kl; next} /^_truth\.ts$/{next} {print}' "$d/index.m3u8" > "$tmp"
  mv -f "$tmp" "$d/index.m3u8"
  rm -f "$d/_truth.ts"   # don't serve truth over http

  # run hlsget (concat only) and compare bytes
  local out="$WORK/$name.out"; mkdir -p "$out"
  "$BIN" -q -no-mux -keep-segments -o "$out/decoded.ts" -work "$out/work" \
    "http://$HOST:$PORT/$name/index.m3u8"
  local got; got="$(md5of "$out/decoded.ts")"
  log "  decoded md5=$got"
  [[ "$got" == "$gt" ]] || die "concat mismatch in '$name': got $got want $gt"
  pass "$name: decrypted concat is byte-identical to plaintext source"

  # run hlsget with remux -> mp4, verify duration via ffprobe
  "$BIN" -q -o "$out/video.mp4" -work "$out/work2" "http://$HOST:$PORT/$name/index.m3u8"
  [[ -f "$out/video.mp4" ]] || die "mp4 not produced in '$name'"
  local dur; dur="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$out/video.mp4")"
  log "  mp4 duration=${dur}s"
  awk -v d="$dur" 'BEGIN{exit !(d>5 && d<7.5)}' || die "unexpected mp4 duration $dur in '$name'"
  pass "$name: mp4 remux ok (~6s)"
}

# start one http server rooted at $WORK; scenarios live in subdirs
log "starting http server on $HOST:$PORT (root=$WORK) ..."
( cd "$WORK" && exec python3 -m http.server "$PORT" --bind "$HOST" >/dev/null 2>&1 ) &
SRV_PID=$!
for _ in $(seq 1 40); do
  if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(('$HOST',$PORT))==0 else 1)"; then break; fi
  sleep 0.25
done

scenario s_fixed fixed
scenario s_seq   seq

printf '\n%s[e2e] ALL PASS%s\n' "$c_green" "$c_off"
