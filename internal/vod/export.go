// Package vod exports videos that the koolearn desktop client has already
// downloaded into its local cache.
//
// A download root holds one directory per video:
//
//	<root>/<video-id>/<hash>_0.m3u8          # media playlist, METHOD=KOOLEARN
//	<root>/<video-id>/<hash>_0/key.bin       # KEY. container
//	<root>/<video-id>/<hash>_0/<hash>-00001.ts
//
// The playlist is ordinary HLS VOD apart from the private key method
// (METHOD=KOOLEARN). Every segment is AES-128-CBC encrypted with an all-zero IV
// under the single 16-byte key that key.bin yields, and each segment carries
// its own PKCS#7 padding. Export replays the client offline: recover the key
// with kcrypt, decrypt the segments in playlist order and remux the
// concatenated MPEG-TS to MP4 with ffmpeg. With NoMux the plaintext .ts is
// left as the artifact instead, so ffmpeg is not required at all.
//
// Nothing here touches the network: the point is to work on the client's cache.
package vod

import (
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"koolearn-crypt/internal/hls"
	"koolearn-crypt/internal/kcrypt"
	"koolearn-crypt/internal/m3u8"
)

// KeyMethod is the private #EXT-X-KEY method koolearn writes into its local
// playlists. Segments encrypted this way use AES-128-CBC with a zero IV.
const KeyMethod = "KOOLEARN"

// ErrExists reports that the destination MP4 already exists and Options did
// not ask for it to be overwritten. The returned Result still describes the
// skipped video.
var ErrExists = errors.New("output already exists")

// Video is one cached video discovered under a download root.
type Video struct {
	ID       string // directory name, e.g. "6p0f88627403889r6kc1ig0le"
	Dir      string // absolute path of the video directory
	Playlist string // path to the media playlist
}

// Options controls one Export call.
type Options struct {
	// Token is the client token, normally the numeric user id. It is optional:
	// the container key does not depend on it, and the only v2 check that
	// consumes it (the tokenTag match) is skipped when it is empty or when
	// SkipTokenCheck is set. vod.ResolveToken can fill it from the local cache.
	Token string
	// SkipTokenCheck forces the v2 tokenTag check to be skipped even when Token
	// is set. The recovered key is identical either way, so this is a safe
	// fallback whenever the token cannot be trusted.
	SkipTokenCheck bool

	OutDir    string                        // directory for the produced files
	Overwrite bool                          // re-export even if the output exists
	KeepTS    bool                          // keep the plaintext .ts next to the .mp4
	NoMux     bool                          // stop at the plaintext .ts (<id>.ts); skip ffmpeg
	Remux     func(ts, mp4 string) error    // defaults to hls.RemuxQuiet; ignored when NoMux
	Logf      func(format string, a ...any) // progress sink; defaults to no output
}

// Result describes the outcome of one Export call.
type Result struct {
	Video    Video
	Out      string // path of the produced file (.mp4, or .ts when NoMux)
	TS       string // path of the plaintext .ts, empty when removed
	Segments int
	Bytes    int64 // plaintext MPEG-TS size
	Skipped  bool
	Elapsed  time.Duration
}

// Discover returns the videos found directly under root, sorted by id.
// Directories without a playlist are ignored; a directory with more than one
// playlist is an error because the choice would be arbitrary.
func Discover(root string) ([]Video, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read download root: %w", err)
	}
	var out []Video
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		playlist, err := findPlaylist(dir)
		if err != nil {
			return nil, err
		}
		if playlist == "" {
			continue
		}
		out = append(out, Video{ID: e.Name(), Dir: dir, Playlist: playlist})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// keyOpts carries the token material used to open key containers.
type keyOpts struct {
	token string
	skip  bool
}

// Export decrypts one video and writes <OutDir>/<id>.mp4 (or <OutDir>/<id>.ts
// when NoMux is set). It returns ErrExists (wrapped) together with a Skipped
// result when the destination is present and Overwrite is false.
func Export(ctx context.Context, v Video, opt Options) (*Result, error) {
	if opt.OutDir == "" {
		return nil, errors.New("vod: output dir is required")
	}
	// An empty token means "unknown": skip the v2 token check instead of
	// failing, since the key derivation does not consume the plaintext token.
	ko := keyOpts{token: opt.Token, skip: opt.SkipTokenCheck || opt.Token == ""}
	remux := opt.Remux
	if remux == nil {
		remux = hls.RemuxQuiet
	}
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	start := time.Now()
	ext := ".mp4"
	if opt.NoMux {
		ext = ".ts"
	}
	out := filepath.Join(opt.OutDir, v.ID+ext)
	if !opt.Overwrite {
		if _, err := os.Stat(out); err == nil {
			return &Result{Video: v, Out: out, Skipped: true}, fmt.Errorf("%s: %w", out, ErrExists)
		}
	}
	if err := os.MkdirAll(opt.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	pl, err := readPlaylist(v.Playlist)
	if err != nil {
		return nil, err
	}

	// With NoMux the plaintext .ts is the final artifact, so it must always be
	// kept at the output path; otherwise it is an intermediate that is removed
	// unless the caller asked to keep it.
	keep := opt.KeepTS || opt.NoMux
	tsFile, tsPath, err := openTS(out, keep)
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		tsFile.Close()
		if !keep {
			_ = os.Remove(tsPath)
		}
	}
	defer cleanup()

	keys := map[string][]byte{}
	var written int64
	for i, seg := range pl.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		plain, err := decryptSegment(v, seg, ko, keys)
		if err != nil {
			return nil, fmt.Errorf("segment %d (%s): %w", i, seg.URI, err)
		}
		if _, err := tsFile.Write(plain); err != nil {
			return nil, fmt.Errorf("write segment %d: %w", i, err)
		}
		written += int64(len(plain))
	}
	if err := tsFile.Close(); err != nil {
		return nil, fmt.Errorf("close %s: %w", tsPath, err)
	}
	logf("decrypted %d segments (%s)", len(pl.Segments), humanBytes(written))

	if opt.NoMux {
		// No remux step: tsPath already points at out.
		logf("wrote %s", out)
	} else {
		if err := remux(tsPath, out); err != nil {
			return nil, err
		}
		if !keep {
			_ = os.Remove(tsPath)
		}
		logf("wrote %s", out)
	}

	res := &Result{
		Video:    v,
		Out:      out,
		Segments: len(pl.Segments),
		Bytes:    written,
		Elapsed:  time.Since(start),
	}
	if keep {
		res.TS = tsPath
	}
	return res, nil
}

// readPlaylist loads and parses a media playlist, rejecting master playlists
// (a local download always points at one rendition).
func readPlaylist(path string) (*m3u8.Playlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read playlist: %w", err)
	}
	pl, err := m3u8.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if pl.IsMaster {
		return nil, fmt.Errorf("%s is a master playlist, expected a media playlist", path)
	}
	if len(pl.Segments) == 0 {
		return nil, fmt.Errorf("%s has no segments", path)
	}
	return pl, nil
}

// openTS returns the writable intermediate file. When keep is false it is a
// temporary file that the caller removes.
func openTS(out string, keep bool) (*os.File, string, error) {
	if keep {
		path := strings.TrimSuffix(out, filepath.Ext(out)) + ".ts"
		f, err := os.Create(path)
		if err != nil {
			return nil, "", fmt.Errorf("create %s: %w", path, err)
		}
		return f, path, nil
	}
	f, err := os.CreateTemp("", "vodexport-*.ts")
	if err != nil {
		return nil, "", fmt.Errorf("create temp ts: %w", err)
	}
	return f, f.Name(), nil
}

// decryptSegment reads one segment and returns its plaintext MPEG-TS bytes.
func decryptSegment(v Video, seg m3u8.Segment, ko keyOpts, keys map[string][]byte) ([]byte, error) {
	path, err := resolveLocal(v.Playlist, seg.URI)
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read segment: %w", err)
	}
	if seg.Key == nil || seg.Key.Method == "" || strings.EqualFold(seg.Key.Method, "NONE") {
		return blob, nil
	}
	key, iv, err := segmentKey(v.Playlist, seg, ko, keys)
	if err != nil {
		return nil, err
	}
	return hls.DecryptAES128CBC(blob, key, iv)
}

// segmentKey resolves the key for a segment, caching by key path so a
// multi-key playlist only decrypts each container once.
func segmentKey(playlist string, seg m3u8.Segment, ko keyOpts, keys map[string][]byte) (key, iv []byte, err error) {
	path, err := resolveLocal(playlist, seg.Key.URI)
	if err != nil {
		return nil, nil, err
	}
	key, ok := keys[path]
	if !ok {
		if key, err = containerKey(path, ko); err != nil {
			return nil, nil, err
		}
		keys[path] = key
	}

	switch strings.ToUpper(seg.Key.Method) {
	case KeyMethod:
		return key, make([]byte, aes.BlockSize), nil
	case "AES-128":
		if iv, err = hls.IVForSegment(seg.Key.IV, seg.Seq); err != nil {
			return nil, nil, err
		}
		return key, iv, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key METHOD=%q (want %s)", seg.Key.Method, KeyMethod)
	}
}

// containerKey decrypts a KEY. container into its 16-byte segment key. The
// expires field is read from the container itself and fed back to kcrypt as
// ctx.Expires, which is what the client does when the cached value is fresh.
func containerKey(path string, ko keyOpts) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key container: %w", err)
	}
	expires, err := kcrypt.ContainerExpires(data)
	if err != nil {
		return nil, fmt.Errorf("key container %s: %w", path, err)
	}
	ctx := kcrypt.Context{
		Expires:        expires,
		UseToken:       ko.token != "",
		Token:          []byte(ko.token),
		SkipTokenCheck: ko.skip,
	}
	key, err := kcrypt.Decrypt(data, ctx)
	if err != nil {
		return nil, fmt.Errorf("key container %s: %w", path, err)
	}
	if len(key) != aes.BlockSize {
		// The reference strip is lossy for a 16-byte plaintext ending in 0x01
		// (encryptByPlan pads nothing at that length), so retry without it
		// before rejecting the container.
		raw, rawErr := kcrypt.DecryptRaw(data, ctx)
		if rawErr != nil {
			return nil, fmt.Errorf("key container %s: %w", path, rawErr)
		}
		if len(raw) != aes.BlockSize {
			return nil, fmt.Errorf("key container %s yielded %d bytes (%d without unpad), expected %d",
				path, len(key), len(raw), aes.BlockSize)
		}
		key = raw
	}
	return key, nil
}

// resolveLocal turns an HLS URI into a local path relative to the file that
// referenced it. Remote URIs are rejected: this package only reads the cache.
func resolveLocal(baseFile, uri string) (string, error) {
	if u, err := url.Parse(uri); err == nil {
		if u.Scheme != "" && u.Host != "" {
			return "", fmt.Errorf("remote URI %q is not supported, expected a cached file", uri)
		}
		if u.Path != "" {
			uri = u.Path
		}
	}
	if filepath.IsAbs(uri) {
		return filepath.Clean(uri), nil
	}
	return filepath.Join(filepath.Dir(baseFile), filepath.FromSlash(uri)), nil
}

// findPlaylist returns the media playlist of a video directory, or "" when the
// directory is not a download.
func findPlaylist(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", dir, err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".m3u8") {
			continue
		}
		found = append(found, filepath.Join(dir, e.Name()))
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		sort.Strings(found)
		return "", fmt.Errorf("%s holds %d playlists (%s); cannot pick one", dir, len(found), strings.Join(found, ", "))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
