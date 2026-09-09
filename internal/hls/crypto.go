package hls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strings"
)

// DecryptAES128CBC decrypts one whole HLS segment blob using AES-128 in CBC
// mode and strips the PKCS#7 padding. Both key and iv must be 16 bytes.
func DecryptAES128CBC(blob, key, iv []byte) ([]byte, error) {
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("aes-128 key must be %d bytes, got %d", aes.BlockSize, len(key))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	if len(blob) == 0 {
		return blob, nil
	}
	if len(blob)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(blob), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(blob))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, blob)

	out, err = pkcs7Unpad(out, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pkcs7Unpad removes and validates PKCS#7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length %d", n)
	}
	pad := int(data[n-1])
	if pad == 0 || pad > blockSize || pad > n {
		return nil, fmt.Errorf("invalid pkcs7 padding byte %d", pad)
	}
	for _, b := range data[n-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("invalid pkcs7 padding bytes")
		}
	}
	return data[:n-pad], nil
}

// IVForSegment returns the 16-byte IV for a segment.
//
// Per RFC 8216: if #EXT-X-KEY carries an explicit IV (hex, e.g. 0x..), use it;
// otherwise the IV is the segment's media sequence number encoded as a 128-bit
// big-endian integer.
func IVForSegment(explicitIV string, seq int64) ([]byte, error) {
	if s := strings.TrimSpace(explicitIV); s != "" {
		s = strings.TrimPrefix(s, "0x")
		s = strings.TrimPrefix(s, "0X")
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("bad IV hex %q: %w", explicitIV, err)
		}
		switch {
		case len(b) == aes.BlockSize:
			return b, nil
		case len(b) < aes.BlockSize:
			iv := make([]byte, aes.BlockSize) // left-pad with zeros
			copy(iv[aes.BlockSize-len(b):], b)
			return iv, nil
		default:
			return nil, fmt.Errorf("IV too long: %d bytes", len(b))
		}
	}
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < 8; i++ {
		iv[15-i] = byte(uint64(seq) >> (8 * i))
	}
	return iv, nil
}
