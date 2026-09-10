package hls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := append([]byte{}, data...)
	for i := 0; i < pad; i++ {
		out = append(out, byte(pad))
	}
	return out
}

func encryptAES128CBC(t *testing.T, plain, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out
}

func TestDecryptRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes
	iv := []byte("abcdef9876543210")
	cases := [][]byte{
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 16),     // exact block -> full padding block
		bytes.Repeat([]byte{0x47}, 188*7),  // MPEG-TS-like length
		bytes.Repeat([]byte{0x00}, 188*40), // zeros
	}
	for i, plain := range cases {
		ct := encryptAES128CBC(t, plain, key, iv)
		got, err := DecryptAES128CBC(ct, key, iv)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("case %d: roundtrip mismatch: got %d bytes, want %d", i, len(got), len(plain))
		}
	}
}

func TestDecryptRejectsBadInput(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef9876543210")
	if _, err := DecryptAES128CBC(make([]byte, 15), key, iv); err == nil {
		t.Fatal("expected error for non-block-aligned ciphertext")
	}
	if _, err := DecryptAES128CBC(make([]byte, 16), []byte("short"), iv); err == nil {
		t.Fatal("expected error for short key")
	}
	// deterministic invalid-padding checks via pkcs7Unpad
	if _, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03, 0x03}, 4); err == nil {
		t.Fatal("expected error: padding bytes inconsistent")
	}
	if _, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03, 0x00}, 4); err == nil {
		t.Fatal("expected error: zero padding byte")
	}
	if _, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03, 0x05}, 4); err == nil {
		t.Fatal("expected error: padding byte larger than block size")
	}
}

func TestIVForSegment(t *testing.T) {
	wantFive := make([]byte, 16)
	wantFive[15] = 5

	iv, err := IVForSegment("0x00000000000000000000000000000005", 99)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(iv, wantFive) {
		t.Fatalf("explicit IV: got %x, want %x", iv, wantFive)
	}

	iv, err = IVForSegment("", 5) // default from media sequence
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(iv, wantFive) {
		t.Fatalf("seq IV: got %x, want %x", iv, wantFive)
	}

	iv, err = IVForSegment("0x05", 99) // short hex -> left-padded
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(iv, wantFive) {
		t.Fatalf("short IV: got %x, want %x", iv, wantFive)
	}

	iv, err = IVForSegment("", 0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}
	wantLarge := []byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	if !bytes.Equal(iv, wantLarge) {
		t.Fatalf("large seq IV: got %x, want %x", iv, wantLarge)
	}

	if _, err := IVForSegment("0xZZ", 1); err == nil {
		t.Fatal("expected error for bad hex IV")
	}
}
