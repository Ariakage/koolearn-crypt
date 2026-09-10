package kcrypt

import (
	"encoding/binary"
	"math/rand"
)

// builtinBaseKey is the 16-byte constant at __TEXT,__const+0xecbb that
// createKey substitutes for the caller-supplied key when useKey is false.
const builtinBaseKey = "752500f5fa6b6b8f"

// Wire tag types, read as a little-endian uint16 at offset 0 of every tag.
const (
	tagEncrypt uint16 = 0x0001
	tagToken   uint16 = 0x0002
	tagExpires uint16 = 0x0003
	tagHash    uint16 = 0xffff
	tagData    uint16 = 0x00ff
)

// encryptTag mirrors the 40-byte encryptTag struct. plans and key alias the
// source buffer after a read (the reference reads are zero-copy) and are freshly
// allocated by createEncryptTag.
type encryptTag struct {
	encryptType byte
	plans       []byte
	key         []byte
}

// wireLen is the number of container bytes the tag occupies:
// tagType(2) + EncryptType(1) + PlansLength(2) + Plans + KeyLength(2) + Key.
func (t encryptTag) wireLen() int {
	return len(t.plans) + len(t.key) + 7
}

// dataTag mirrors the 16-byte dataTag struct; data aliases the source buffer.
type dataTag struct {
	tagType uint16
	data    []byte
}

// tokenTag mirrors the 18-byte tokenTag struct.
type tokenTag struct {
	tagType uint16
	token   [16]byte
}

// expiresTag mirrors the 32-byte expiresTag struct. Only the first 26 bytes are
// ever written to a container.
type expiresTag struct {
	tagType     uint16
	expires     int64
	expiresData [16]byte
}

// hashTag mirrors the 18-byte hashTag struct.
type hashTag struct {
	tagType uint16
	hash    [16]byte
}

// encryptTagRead mirrors encryptTagRead (0xdf00). It consumes
// PlansLength + KeyLength + 7 bytes and leaves plans/key aliasing src.
func encryptTagRead(src []byte) (encryptTag, int, bool) {
	var t encryptTag
	if len(src) < 5 {
		return t, 0, false
	}
	t.encryptType = src[2]
	pl := int(binary.LittleEndian.Uint16(src[3:5]))
	if len(src) < 7+pl {
		return t, 0, false
	}
	t.plans = src[5 : 5+pl]
	kl := int(binary.LittleEndian.Uint16(src[5+pl : 7+pl]))
	if len(src) < 7+pl+kl {
		return t, 0, false
	}
	t.key = src[7+pl : 7+pl+kl]
	return t, t.wireLen(), true
}

// dataTagRead mirrors dataTagRead (0xdfa0): tagType(2) + length(4) + data.
func dataTagRead(src []byte) (dataTag, int, bool) {
	var t dataTag
	if len(src) < 6 {
		return t, 0, false
	}
	t.tagType = binary.LittleEndian.Uint16(src[0:2])
	n := int(binary.LittleEndian.Uint32(src[2:6]))
	if len(src) < 6+n {
		return t, 0, false
	}
	t.data = src[6 : 6+n]
	return t, n + 6, true
}

// expiresTagRead mirrors expiresTagRead (0xdff0): tagType(2) + expires(8) +
// expiresData(16).
func expiresTagRead(src []byte) (expiresTag, int, bool) {
	var t expiresTag
	if len(src) < 26 {
		return t, 0, false
	}
	t.tagType = binary.LittleEndian.Uint16(src[0:2])
	t.expires = int64(binary.LittleEndian.Uint64(src[2:10]))
	copy(t.expiresData[:], src[10:26])
	return t, 26, true
}

// tokenTagRead mirrors tokenTagRead (0xe050): tagType(2) + token(16).
func tokenTagRead(src []byte) (tokenTag, int, bool) {
	var t tokenTag
	if len(src) < 18 {
		return t, 0, false
	}
	t.tagType = binary.LittleEndian.Uint16(src[0:2])
	copy(t.token[:], src[2:18])
	return t, 18, true
}

// hashTagRead mirrors hashTagRead (0xe0a0): tagType(2) + hash(16).
func hashTagRead(src []byte) (hashTag, int, bool) {
	var t hashTag
	if len(src) < 18 {
		return t, 0, false
	}
	t.tagType = binary.LittleEndian.Uint16(src[0:2])
	copy(t.hash[:], src[2:18])
	return t, 18, true
}

// headWriteInto mirrors headWriteInto (0xe1a0): "KEY." + version(2) LE.
func headWriteInto(dst []byte) int {
	copy(dst[0:4], "KEY.")
	binary.LittleEndian.PutUint16(dst[4:6], 2)
	return 6
}

// encryptTagWriteInto mirrors encryptTagWriteInto (0xdd70).
func encryptTagWriteInto(dst []byte, t encryptTag) int {
	binary.LittleEndian.PutUint16(dst[0:2], tagEncrypt)
	dst[2] = t.encryptType
	binary.LittleEndian.PutUint16(dst[3:5], uint16(len(t.plans)))
	copy(dst[5:], t.plans)
	off := 5 + len(t.plans)
	binary.LittleEndian.PutUint16(dst[off:off+2], uint16(len(t.key)))
	copy(dst[off+2:], t.key)
	return t.wireLen()
}

// dataTagWriteInto mirrors dataTagWriteInto (0xdea0).
func dataTagWriteInto(dst []byte, t dataTag) int {
	binary.LittleEndian.PutUint16(dst[0:2], t.tagType)
	binary.LittleEndian.PutUint32(dst[2:6], uint32(len(t.data)))
	copy(dst[6:], t.data)
	return len(t.data) + 6
}

// expiresTagWriteInto mirrors expiresTagWriteInto (0xdf10).
func expiresTagWriteInto(dst []byte, t expiresTag) int {
	binary.LittleEndian.PutUint16(dst[0:2], t.tagType)
	binary.LittleEndian.PutUint64(dst[2:10], uint64(t.expires))
	copy(dst[10:26], t.expiresData[:])
	return 26
}

// tokenTagWriteInto mirrors tokenTagWriteInto (0xdf70).
func tokenTagWriteInto(dst []byte, t tokenTag) int {
	binary.LittleEndian.PutUint16(dst[0:2], t.tagType)
	copy(dst[2:18], t.token[:])
	return 18
}

// hashTagWriteInto mirrors hashTagWriteInto (0xdfc0).
func hashTagWriteInto(dst []byte, t hashTag) int {
	binary.LittleEndian.PutUint16(dst[0:2], t.tagType)
	copy(dst[2:18], t.hash[:])
	return 18
}

// createKey mirrors createKey (0xdc50). The MD5 input is laid out as:
//
//	[e_tag->Key klen] [basekey keyLen | builtinBaseKey]
//	[zero padding up to 0x20] [expires LE64 @0x20] [token 16B @0x28]
//
// bufLen is klen+40 when expires > 0 and klen+16 otherwise. The expires and
// token writes use fixed offsets independent of klen, so a short klen leaves a
// zero gap and a long token is truncated by bufLen — both reproduced here.
func createKey(et encryptTag, baseKey []byte, keyLen int, expires int64, token [16]byte, useKey bool) [16]byte {
	klen := len(et.key)
	bufLen := klen + 16
	if expires > 0 {
		bufLen = klen + 40
	}
	buf := make([]byte, bufLen)
	copy(buf, et.key)
	if useKey {
		if keyLen > len(baseKey) {
			keyLen = len(baseKey)
		}
		copy(buf[klen:], baseKey[:keyLen])
	} else {
		copy(buf, builtinBaseKey)
	}
	if expires > 0 {
		binary.LittleEndian.PutUint64(buf[0x20:0x28], uint64(expires))
		copy(buf[0x28:], token[:])
	}
	return md5Sum(buf)
}

// createEncryptTag mirrors createEncryptTag (0xd9e0): a random plan list of
// 4..8 entries in [0,31], a random 16-byte per-container key, EncryptType 1.
func createEncryptTag() encryptTag {
	var t encryptTag
	t.encryptType = 1
	pl := rand.Intn(5) + 4
	t.plans = make([]byte, pl)
	for i := range t.plans {
		t.plans[i] = byte(rand.Intn(32))
	}
	t.key = make([]byte, 16)
	createPartKey(t.key)
	return t
}

// createPartKey mirrors createPartKey (0x7400): fill with rand() bytes.
func createPartKey(key []byte) {
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
}

// createDataTag mirrors createDataTag (0xdab0). It returns the tag only; the
// caller derives the wire length from len(tag.data)+6.
func createDataTag(et encryptTag, data, key []byte) dataTag {
	return dataTag{tagType: tagData, data: encryptByPlan(et.plans, key, data)}
}

// createExpiresTag mirrors createExpiresTag (0xdae0): the 8-byte little-endian
// expires value is encrypted into a 16-byte block.
func createExpiresTag(et encryptTag, expires int64, key []byte) expiresTag {
	var t expiresTag
	t.tagType = tagExpires
	t.expires = expires
	var plain [8]byte
	binary.LittleEndian.PutUint64(plain[:], uint64(expires))
	enc := encryptByPlan(et.plans, key, plain[:])
	copy(t.expiresData[:], enc)
	return t
}

// createTokenTag mirrors createTokenTag (0xdb40): MD5 of the token.
func createTokenTag(token []byte) tokenTag {
	return tokenTag{tagType: tagToken, token: md5Sum(token)}
}

// getData mirrors getData (0xe140). The reference returns an uninitialised
// dataTag when EncryptType != 1 because decryptByPlan bails out early; the Go
// version returns an empty tag instead of leaving the caller with garbage.
func getData(et encryptTag, key, src []byte) dataTag {
	return getDataWith(et, key, src, true)
}

// getDataWith is getData with the trailing PKCS#7 strip made optional. The
// reference always strips, which is lossy for a 16-byte plaintext ending in
// 0x01; see decryptByPlanRaw.
func getDataWith(et encryptTag, key, src []byte, unpad bool) dataTag {
	var t dataTag
	if et.encryptType != 1 {
		return t
	}
	if unpad {
		t.data = decryptByPlan(et.plans, key, src)
	} else {
		t.data = decryptByPlanRaw(et.plans, key, src)
	}
	return t
}

// getExpires mirrors getExpires (0xe0f0): decrypt the 16-byte expires block and
// reinterpret the 8-byte plaintext as a little-endian int64. -1 means the
// recovered length was not 8.
func getExpires(ex expiresTag, et encryptTag, key []byte) int64 {
	tmp := getData(et, key, ex.expiresData[:])
	if len(tmp.data) != 8 {
		return -1
	}
	return int64(binary.LittleEndian.Uint64(tmp.data))
}
