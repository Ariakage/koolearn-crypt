package vod

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"koolearn-crypt/internal/kcrypt"
)

const (
	testBaseKey = "5wqPBk89IkGBxXZy"
	testUID     = "402881234567890" // synthetic, deliberately not a real user id
	testExpires = int64(1_700_000_000)
)

// writeContainer mints a KEY. v2 container whose tokenTag carries md5(uid), the
// exact shape the client caches, and returns its bytes.
func writeContainer(t *testing.T, path, uid string) []byte {
	t.Helper()
	container, err := kcrypt.Encrypt([]byte("0123456789abcdef"), kcrypt.Context{
		Key:      []byte(testBaseKey),
		UseKey:   true,
		Expires:  testExpires,
		UseToken: true,
		Token:    []byte(uid),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, container, 0o644); err != nil {
		t.Fatal(err)
	}
	return container
}

// TestResolveTokenForContainerMatchesCache covers the happy path: the numeric
// uid directory under cache/ is matched by the container's md5 token hash, and
// the recovered token satisfies the v2 token check on decrypt.
func TestResolveTokenForContainerMatchesCache(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cache", testUID), 0o755); err != nil {
		t.Fatal(err)
	}
	// A decoy numeric directory must not be selected.
	if err := os.MkdirAll(filepath.Join(root, "cache", "999999999"), 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "videos", "v1", "key.bin")
	container := writeContainer(t, keyPath, testUID)

	got, verified, err := ResolveTokenForContainer(keyPath)
	if err != nil {
		t.Fatalf("ResolveTokenForContainer: %v", err)
	}
	if !verified || got != testUID {
		t.Fatalf("ResolveTokenForContainer = (%q, %v), want (%q, true)", got, verified, testUID)
	}

	if _, err := kcrypt.Decrypt(container, kcrypt.Context{
		Key: []byte(testBaseKey), UseKey: true, Expires: testExpires,
		UseToken: true, Token: []byte(got),
	}); err != nil {
		t.Fatalf("Decrypt with recovered token: %v", err)
	}
}

// TestResolveTokenNoCacheMatchIsNotFatal covers the fallback: with no matching
// cache directory the resolver reports success=false but no error, and the
// container still decrypts once the token check is skipped. A non-numeric token
// is used so no real numeric cache directory can ever match it.
func TestResolveTokenNoCacheMatchIsNotFatal(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "videos", "v1", "key.bin")
	container := writeContainer(t, keyPath, "unknown-token")

	got, verified, err := ResolveTokenForContainer(keyPath)
	if err != nil {
		t.Fatalf("ResolveTokenForContainer: %v", err)
	}
	if verified || got != "" {
		t.Fatalf("ResolveTokenForContainer = (%q, %v), want (\"\", false)", got, verified)
	}

	plain, err := kcrypt.Decrypt(container, kcrypt.Context{
		Key: []byte(testBaseKey), UseKey: true, Expires: testExpires,
		SkipTokenCheck: true,
	})
	if err != nil {
		t.Fatalf("Decrypt without token: %v", err)
	}
	if !bytes.Equal(plain, []byte("0123456789abcdef")) {
		t.Fatalf("Decrypt without token = %q, want the plaintext", plain)
	}
}

// TestResolveTokenFromVideoPlaylist drives the vodexport entry point: the token
// is recovered by reading the key container a media playlist points at.
func TestResolveTokenFromVideoPlaylist(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cache", testUID), 0o755); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(root, "videos", "v1")
	writeContainer(t, filepath.Join(dir, "key.bin"), testUID)

	const playlist = "#EXTM3U\n" +
		"#EXT-X-KEY:METHOD=KOOLEARN,URI=\"key.bin\"\n" +
		"#EXTINF:2.0,\n" +
		"seg000.ts\n"
	pl := filepath.Join(dir, "index.m3u8")
	if err := os.WriteFile(pl, []byte(playlist), 0o644); err != nil {
		t.Fatal(err)
	}

	got, verified, err := ResolveToken(root, []Video{{ID: "v1", Dir: dir, Playlist: pl}})
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if !verified || got != testUID {
		t.Fatalf("ResolveToken = (%q, %v), want (%q, true)", got, verified, testUID)
	}
}
