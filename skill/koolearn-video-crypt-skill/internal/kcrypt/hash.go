package kcrypt

import (
	"crypto/md5"
	"crypto/sha1"
)

// md5Sum is the reference GetMd5 helper (0x7390).
func md5Sum(src []byte) [16]byte {
	return md5.Sum(src)
}

// sha1LittleEndian computes SHA-1 and re-emits the digest in host byte order.
//
// The reference stores Intermediate_Hash[5] as a uint32 array, so the 20 digest
// bytes land in memory little-endian. Go's sha1.Sum returns the canonical
// big-endian form, so each 4-byte word is reversed here to match the reference.
func sha1LittleEndian(src []byte) [20]byte {
	be := sha1.Sum(src)
	var le [20]byte
	for w := 0; w < 5; w++ {
		i := w * 4
		le[i+0] = be[i+3]
		le[i+1] = be[i+2]
		le[i+2] = be[i+1]
		le[i+3] = be[i+0]
	}
	return le
}

// createHashTag mirrors createHashTag (0xdb70): MD5 over the little-endian
// SHA-1 digest of data. It returns the 16-byte tag payload.
func createHashTag(data []byte) [16]byte {
	le := sha1LittleEndian(data)
	return md5Sum(le[:])
}
