---
name: koolearn-video-crypt-skill
description: Decrypt and export offline-cached koolearn (新东方在线 / 新东方大学考试) HLS course videos to MP4 by replaying the desktop client's private KEY. container key derivation and AES-128-CBC zero-IV segment decryption in pure Go, then remuxing with ffmpeg (optional). Use when the user wants to export, decrypt, convert or merge koolearn / 新东方 cached videos, handle key.bin KEY. containers, vodkey.bin or local.m3u8 caches, or produce MP4 from downloaded courses. Also includes a standard AES-128 HLS downloader and a key-extraction diagnostic.
version: 1.0.0
author: Ariakage
---

# koolearn Video Crypt

Replays the koolearn desktop client **offline** to turn locally cached, privately
encrypted videos into MP4:

1. `key.bin` (a private `KEY.` v2 container) yields the 16-byte segment key via `kcrypt`
2. each `.ts` segment is AES-128-CBC decrypted with a **zero IV** and PKCS#7 unpadded
3. segments are concatenated into one MPEG-TS and remuxed to MP4 with ffmpeg

No network access is used for the export itself.

## Commands

| command | role |
|---|---|
| `vodexport` | **main**: discover every cached video under a download root and export it (route C) |
| `vodkey` | diagnostic: recover and print the 16-byte key from a single `key.bin` |
| `hlsget` | route B: download + decrypt a **standard** `AES-128` HLS playlist from a URL |

## Prerequisites

- **Go 1.23+** — required only to build the tools (pure standard library, no cgo, no third-party deps).
- **ffmpeg** — **optional**. If it is missing from `PATH`, `vodexport` and `hlsget`
  automatically fall back to `-no-mux` and leave a plaintext `.ts` instead of failing.
  Install it when you want MP4 output linked below.

## Step 1 — build

macOS / Linux:

```bash
./scripts/build.sh              # build for the host platform
./scripts/build.sh -all         # cross-compile windows+darwin, amd64+arm64
./scripts/build.sh windows amd64
```

Windows (PowerShell):

```powershell
.\scripts\build.ps1
.\scripts\build.ps1 -All
.\scripts\build.ps1 -GOOS windows -GOARCH amd64
```

Binaries land in `bin/<goos>-<goarch>/` (e.g. `bin/darwin-arm64/vodexport`,
`bin/windows-amd64/vodexport.exe`). To skip building, use `go run ./cmd/vodexport ...`.

## Step 2 — locate the cache

| platform | download root |
|---|---|
| macOS | `~/Library/Application Support/koolearn/koolearn/download/` |
| Windows | `%APPDATA%\koolearn\koolearn\download\` |

Each video is one subdirectory holding `<hash>_0.m3u8`, `<hash>_0/key.bin` and
`<hash>-*.ts` segments. A subdirectory with exactly one `.m3u8` is treated as a video.

## Step 3 — the token is recovered automatically

The token is the numeric **user id**, and the client only ever stores it in the
clear as the folder name under `<data root>/cache/<uid>/` (e.g.
`.../koolearn/koolearn/cache/110607776/settings.db`). You do **not** have to look
it up: `-token` defaults to `auto`, which recovers it for you.

How `auto` works, and why it is the most reliable option:

1. Every cached `key.bin` carries `md5(token)` in its `tokenTag`, so the tool
   reads that hash straight from the container — no key or network needed.
2. It tests each numeric `cache/<uid>/` directory name against that hash. The
   match is **exact and collision-free**, so a hit is always the real token.
3. The token is **not** an input to the key derivation — it only gates the
   container through that md5. So when nothing matches (empty cache, moved
   download root, fresh machine) the tool **skips the v2 token check and still
   decrypts correctly** instead of failing.

Net effect: `auto` gives the highest success rate, and the skip fallback makes a
missing token harmless. Pass `-token <uid>` only to force a value you already know.

## Step 4 — export

List first, then export — no token argument is needed, it is recovered:

```bash
BIN=bin/darwin-arm64        # use your own bin/<goos>-<goarch>
ROOT="$HOME/Library/Application Support/koolearn/koolearn/download"

"$BIN/vodexport" -list "$ROOT"
"$BIN/vodexport" -jobs 4 -out export "$ROOT"            # token: auto
"$BIN/vodexport" -token 110607776 -out export "$ROOT"   # force a known token
```

Output: `<out>/<video-id>.mp4`. Existing outputs are **skipped**, not overwritten.

`vodexport` flags:

| flag | meaning |
|---|---|
| `-token <uid>` | token to use; default `auto` recovers it from `cache/` (see Step 3) |
| `-out <dir>` | output directory (default `export`) |
| `-jobs <n>` | videos exported concurrently (default `4`) |
| `-only <id,id>` | export just these video ids |
| `-overwrite` | re-export even if the output exists |
| `-keep-ts` | keep the plaintext `.ts` next to the `.mp4` |
| `-no-mux` | stop at the plaintext `.ts` (no ffmpeg); output is `<id>.ts` |
| `-list` | list discovered videos and exit |
| `-q` | quiet |
| `<root>` | download root (positional, or `-in`) |

> Always quote the macOS path — it contains a space.

## Verifying the output

```bash
ffmpeg -v error -i export/<video-id>.mp4 -f null -
```

A clean run prints nothing; any decode error is reported.

## Diagnostic — recover one key

```bash
"$BIN/vodkey" -key <base-key> "$ROOT/<video-id>/<hash>_0/key.bin"
```

`-token` also defaults to `auto` (recovered from `cache/`); pass `-token <uid>`
to force a value, or `-skip-token-check` to drop the v2 token check explicitly.
`-expires` overrides the expiry (default: read from the container), `-normalize`
applies the addon's Method fallback. `-key` may be omitted when the container is
self-describing.

## Route B — standard HLS from a URL

```bash
"$BIN/hlsget" -o out.mp4 -c 8 -H 'Referer: https://host/' https://host/index.m3u8
"$BIN/hlsget" -no-mux -o out.ts https://host/index.m3u8
```

Use this only for playlists whose `#EXT-X-KEY METHOD` is `AES-128`; it does not
handle koolearn's private `KOOLEARN` method — that is what `vodexport` is for.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `token mismatch` (`codeBadToken`) | the explicit `-token` is wrong; omit it so `auto` recovers the right one from `cache/` |
| `no videos found` | the subdirectory must contain exactly one `.m3u8` |
| `key expired` | the cached `key.bin` expired — re-download the video in the client |
| `ffmpeg not found ... falling back to -no-mux` | expected when ffmpeg is absent; install ffmpeg, or accept `.ts` |
| `unsupported METHOD` | only `KOOLEARN` (zero IV) and `AES-128` are handled |
| garbled first packet / 15-byte key | the §12.6 off-by-one defect — already handled by the `DecryptRaw` fallback; rebuild from this skill |

## Self-test (no key material needed)

Each script builds its own binary. `.ts`/`.mp4` outputs are produced under the
temp dir and removed on exit.

```bash
./scripts/smoke-test.sh   # synthetic METHOD=NONE cache: auto token, -no-mux md5, mp4 remux, ffmpeg fallback
./scripts/e2e-test.sh     # route B: build an AES-128 HLS, serve it, download and verify
```

Alongside these, `go test ./...` covers the crypto and playlist packages.
Run all three after any change to the export path.

## Deep reference

- `README.md` — full reverse-engineering notes: `KEY.` container format (§5.2),
  key derivation (§5.3), `decryptByPlan` (§5.4), route B/C details (§10–§12),
  and the §12.6 defect.
- `docs/decrypt-node-reverse.md` — native module (`decrypt.node`) disassembly notes.
- `reference/koolearn-decrypt/` — original extracted JS wrapper (`main.js`, `package.json`).

## Compliance

For personal study and security research on a locally installed client only.
Exported content may be protected by copyright and the service's Terms of Service.
Use it only on content you are authorized to access, at your own risk. See `README.md` §0.
