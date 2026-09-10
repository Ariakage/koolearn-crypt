package kcrypt

import "crypto/aes"

// caesarDecrypt mirrors Caesar_Decrypt (0x6f00): every byte is shifted down by
// the corresponding key byte, cycling over the key. Byte arithmetic wraps
// modulo 256 in Go, matching the reference's 8-bit `subb`.
func caesarDecrypt(src, key []byte) []byte {
	dst := make([]byte, len(src))
	if len(key) == 0 {
		copy(dst, src)
		return dst
	}
	for i := range src {
		dst[i] = src[i] - key[i%len(key)]
	}
	return dst
}

// caesarEncrypt is the inverse of caesarDecrypt.
func caesarEncrypt(src, key []byte) []byte {
	dst := make([]byte, len(src))
	if len(key) == 0 {
		copy(dst, src)
		return dst
	}
	for i := range src {
		dst[i] = src[i] + key[i%len(key)]
	}
	return dst
}

// rc4XOR mirrors my_RC4 (0xd640): a textbook RC4 KSA followed by a PRGA that
// XORs the keystream into buf in place.
func rc4XOR(buf, key []byte) {
	if len(key) == 0 || len(buf) == 0 {
		return
	}
	var s [256]byte
	var k [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
		k[i] = key[i%len(key)]
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(k[i])) & 0xff
		s[i], s[j] = s[j], s[i]
	}
	i, j := 0, 0
	for n := range buf {
		i = (i + 1) & 0xff
		j = (j + int(s[i])) & 0xff
		s[i], s[j] = s[j], s[i]
		buf[n] ^= s[(int(s[i])+int(s[j]))&0xff]
	}
}

// fencePerm computes the transposition used by both Fence_Decrypt and
// Fence_Encrypt. The input is laid out column-major over an R x C grid and read
// back row-major; the first `full` columns hold R bytes, the rest hold R-1.
//
// The grid geometry comes straight from Fence_Decrypt (0xe5e0):
//
//	C    = (sum(key) + n) % 5 + 2
//	R    = ceil(n / C)
//	full = n % C, or C when that is 0
//
// The returned slice maps output position -> input position for decryption.
func fencePerm(n int, key []byte) []int {
	sum := 0
	for _, b := range key {
		sum += int(b)
	}
	c := (sum+n)%5 + 2
	r := (n + c - 1) / c
	full := n % c
	if full == 0 {
		full = c
	}

	// Column offsets in the column-major source layout.
	coff := make([]int, c)
	acc := 0
	for col := 0; col < c; col++ {
		coff[col] = acc
		if col < full {
			acc += r
		} else {
			acc += r - 1
		}
	}

	perm := make([]int, 0, n)
	for row := 0; row < r; row++ {
		for col := 0; col < c; col++ {
			height := r - 1
			if col < full {
				height = r
			}
			if row < height {
				perm = append(perm, coff[col]+row)
			}
		}
	}
	return perm
}

// fenceDecrypt mirrors Fence_Decrypt (0xe5e0).
func fenceDecrypt(src, key []byte) []byte {
	n := len(src)
	if n == 0 {
		return nil
	}
	perm := fencePerm(n, key)
	dst := make([]byte, len(perm))
	for j, srcIdx := range perm {
		dst[j] = src[srcIdx]
	}
	return dst
}

// fenceEncrypt mirrors Fence_Encrypt (0xe1c0), the inverse permutation of
// fenceDecrypt: it lays the input out row-major and reads it back column-major.
func fenceEncrypt(src, key []byte) []byte {
	n := len(src)
	if n == 0 {
		return nil
	}
	perm := fencePerm(n, key)
	dst := make([]byte, len(perm))
	for j, dstIdx := range perm {
		dst[dstIdx] = src[j]
	}
	return dst
}

// aesDecryptECB mirrors AesSetKey(...,Nk=4...)+AesDecryptECB: standard
// AES-128-ECB applied in place. The reference requires a 16-byte key and a
// length that is a multiple of 16; any trailing partial block is left untouched
// instead of reproducing its out-of-bounds access.
func aesDecryptECB(buf, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	bs := block.BlockSize()
	for i := 0; i+bs <= len(buf); i += bs {
		block.Decrypt(buf[i:i+bs], buf[i:i+bs])
	}
	return nil
}

// aesEncryptECB is the encryption counterpart of aesDecryptECB.
func aesEncryptECB(buf, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	bs := block.BlockSize()
	for i := 0; i+bs <= len(buf); i += bs {
		block.Encrypt(buf[i:i+bs], buf[i:i+bs])
	}
	return nil
}
