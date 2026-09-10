// Token resolution for vodexport.
//
// The client's token is normally the numeric user id, and the client files its
// per-user state under <data root>/cache/<uid>/. Because the token is not an
// input to the container key derivation — only its MD5, baked into the
// tokenTag, is compared at parse time — a candidate can be checked against a
// key container with an exact, collision-free test. That lets the tool recover
// the token from the local cache instead of asking the user to remember it.
//
// When no candidate verifies (no cache dir, or the cache was cleared) the
// caller simply skips the v2 token check: decryption is unaffected.
package vod

import (
	"crypto/md5"
	"os"
	"path/filepath"

	"koolearn-crypt/internal/kcrypt"
	"koolearn-crypt/internal/m3u8"
)

// ResolveToken recovers the client token by matching the numeric directory
// names under the client's cache/ against the MD5 stored in the video key
// containers. verified is false when nothing matches; that is not an error and
// the caller should fall back to skipping the token check.
func ResolveToken(root string, videos []Video) (token string, verified bool, err error) {
	h, ok, err := firstTokenHash(videos)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	token, verified = matchTokenInCache(root, h)
	return token, verified, nil
}

// ResolveTokenForContainer is ResolveToken for a single KEY. container, used by
// the vodkey diagnostic. The cache is searched from the container's directory.
func ResolveTokenForContainer(path string) (token string, verified bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	h, has, err := kcrypt.ContainerTokenHash(data)
	if err != nil {
		return "", false, err
	}
	if !has {
		return "", false, nil
	}
	token, verified = matchTokenInCache(filepath.Dir(path), h)
	return token, verified, nil
}

// firstTokenHash returns the token hash of the first video whose key container
// carries a token tag. Unreadable or token-less videos are skipped, so a mixed
// download root still resolves as long as one verifiable container exists.
func firstTokenHash(videos []Video) (h [16]byte, ok bool, err error) {
	for _, v := range videos {
		path, found := firstKeyContainer(v)
		if !found {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		h, has, err := kcrypt.ContainerTokenHash(data)
		if err != nil || !has {
			continue
		}
		return h, true, nil
	}
	return h, false, nil
}

// matchTokenInCache tests every numeric cache directory name against h.
func matchTokenInCache(start string, h [16]byte) (string, bool) {
	for _, dir := range cacheDirs(start) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || !isNumeric(name) {
				continue
			}
			if md5.Sum([]byte(name)) == h {
				return name, true
			}
		}
	}
	return "", false
}

// firstKeyContainer returns the key container referenced by a video playlist.
// A video whose segments are unencrypted has none.
func firstKeyContainer(v Video) (string, bool) {
	data, err := os.ReadFile(v.Playlist)
	if err != nil {
		return "", false
	}
	pl, err := m3u8.Parse(string(data))
	if err != nil {
		return "", false
	}
	for _, seg := range pl.Segments {
		if seg.Key == nil || seg.Key.URI == "" {
			continue
		}
		if path, err := resolveLocal(v.Playlist, seg.Key.URI); err == nil {
			return path, true
		}
	}
	return "", false
}

// cacheDirs lists the directories that may hold the client's per-user cache.
// The usual layout puts cache/ next to download/ under one data root, but the
// download path can be moved, so every ancestor is probed and the platform data
// roots are tried as a fallback.
func cacheDirs(start string) []string {
	var dirs []string
	seen := map[string]bool{}
	add := func(d string) {
		if d == "" {
			return
		}
		d = filepath.Clean(d)
		if seen[d] {
			return
		}
		seen[d] = true
		dirs = append(dirs, d)
	}

	p := filepath.Clean(start)
	for i := 0; i < 6; i++ {
		add(filepath.Join(p, "cache"))
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	// macOS: ~/Library/Application Support, Windows: %APPDATA%.
	if cfg, err := os.UserConfigDir(); err == nil {
		add(filepath.Join(cfg, "koolearn", "koolearn", "cache"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, "Library", "Application Support", "koolearn", "koolearn", "cache"))
	}
	return dirs
}

// isNumeric reports whether s is a non-empty run of ASCII digits, the shape of
// a koolearn user id.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
