package kcrypt

import (
	"bytes"
	"math"
	"testing"
	"time"
)

func TestNormalizeExpiresAt(t *testing.T) {
	const now = int64(1_700_000_000)
	fallback := now * 1000

	cases := []struct {
		name    string
		expires int64
		want    int64
	}{
		{"just above floor", MethodExpiresFloor + 1, MethodExpiresFloor + 1},
		{"unix seconds", 1_700_000_000, 1_700_000_000},
		{"unix milliseconds", 1_700_000_000_000, 1_700_000_000_000},
		{"max int64", math.MaxInt64, math.MaxInt64},
		{"at floor", MethodExpiresFloor, fallback},
		{"just below floor", MethodExpiresFloor - 1, fallback},
		{"zero", 0, fallback},
		{"negative", -1, fallback},
		{"min int64", math.MinInt64, fallback},
	}
	for _, tc := range cases {
		if got := normalizeExpiresAt(tc.expires, now); got != tc.want {
			t.Errorf("%s: normalizeExpiresAt(%d, %d) = %d, want %d",
				tc.name, tc.expires, now, got, tc.want)
		}
	}
}

// TestNormalizeExpiresFallbackShape pins the two properties of the live
// wrapper: the fallback tracks the wall clock and is always a whole second
// scaled by 1000, because the reference computes time(NULL) * 1000.
func TestNormalizeExpiresFallbackShape(t *testing.T) {
	before := time.Now().Unix()
	got := NormalizeExpires(0)
	after := time.Now().Unix()

	if got%1000 != 0 {
		t.Fatalf("NormalizeExpires(0) = %d, want a multiple of 1000", got)
	}
	if got < before*1000 || got > after*1000 {
		t.Fatalf("NormalizeExpires(0) = %d, want within [%d, %d]", got, before*1000, after*1000)
	}

	const keep = int64(1_700_000_000_000)
	if v := NormalizeExpires(keep); v != keep {
		t.Fatalf("NormalizeExpires(%d) = %d, want unchanged", keep, v)
	}
}

// TestDecryptMethodNormalizesExpires pins the one observable difference
// between Decrypt and DecryptMethod. A container minted with an expiry exactly
// at MethodExpiresFloor decrypts through Decrypt, since `ge < ctx.Expires` is
// false, but not through DecryptMethod: the floor value is normalised to the
// current time, which changes the key derived by createKey and therefore the
// recovered expires block.
func TestDecryptMethodNormalizesExpires(t *testing.T) {
	key := []byte("5wqPBk89IkGBxXZy")
	token := []byte("user-12345678")
	plain := []byte("method guard probe")

	container, err := Encrypt(plain, Context{
		Key:      key,
		UseKey:   true,
		Expires:  MethodExpiresFloor,
		UseToken: true,
		Token:    token,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ctx := Context{Key: key, UseKey: true, Expires: MethodExpiresFloor, UseToken: true, Token: token}

	got, err := Decrypt(container, ctx)
	if err != nil {
		t.Fatalf("Decrypt at the floor: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Decrypt at the floor: got %q want %q", got, plain)
	}

	if _, err := DecryptMethod(container, ctx); err == nil {
		t.Fatal("DecryptMethod at the floor: want normalisation to break the derived key")
	}
}

// TestDecryptRawKeepsTrailingPadByte pins the only case where Decrypt and
// DecryptRaw diverge. encryptByPlan pads a 16-byte plaintext by zero bytes, so a
// plaintext ending in 0x01 survives encryption verbatim; the reference's
// unconditional PKCS#7 strip then drops that byte. DecryptRaw keeps it, which
// is what a 16-byte segment key needs.
func TestDecryptRawKeepsTrailingPadByte(t *testing.T) {
	key := []byte("5wqPBk89IkGBxXZy")
	plain := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x01,
	}
	ctx := Context{Key: key, UseKey: true, Expires: 1_700_000_000}

	container, err := Encrypt(plain, ctx)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(container, ctx)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if want := plain[:len(plain)-1]; !bytes.Equal(got, want) {
		t.Fatalf("Decrypt: got %x want %x", got, want)
	}

	raw, err := DecryptRaw(container, ctx)
	if err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}
	if !bytes.Equal(raw, plain) {
		t.Fatalf("DecryptRaw: got %x want %x", raw, plain)
	}
}
