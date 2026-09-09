package kcrypt

import "encoding/binary"

// magic is "KEY." read as a little-endian uint32, the first four container
// bytes. The header is magic(4) + version(2) little-endian.
const magic uint32 = 0x2e59454b

const (
	headerLen     = 6
	hashTagLen    = 18
	tokenTagLen   = 18
	expiresTagLen = 26
)

// Context mirrors the Pasrser_CTX fields that affect the wire format. Key is
// truncated or zero-padded to 16 bytes exactly like the reference memcpy.
type Context struct {
	Key      []byte
	UseKey   bool
	Expires  int64
	UseToken bool
	Token    []byte
}

// Decrypt mirrors decrypt_parse (0x2540). It walks the tag list, derives the
// container key with createKey, runs the version-2 integrity checks, and
// finally decrypts the data tag.
//
// Unlike the reference it never reads out of bounds: a tag whose declared
// length runs past the container returns codeBadMagic instead of returning
// uninitialised memory.
func Decrypt(container []byte, ctx Context) ([]byte, error) {
	if len(container) < headerLen {
		return nil, errf(codeBadMagic, "container shorter than header")
	}
	if binary.LittleEndian.Uint32(container[0:4]) != magic {
		return nil, errf(codeBadMagic, "bad KEY. magic")
	}
	version := binary.LittleEndian.Uint16(container[4:6])
	if version != 1 && version != 2 {
		return nil, errf(codeBadVersion, "unsupported container version %d", version)
	}

	var (
		et encryptTag
		dt dataTag
		tk tokenTag
		ex expiresTag
		ht hashTag
	)

	p := headerLen
	count := 0
	for p < len(container) {
		if count == 9 {
			return nil, errf(codeBadMagic, "more than 9 tags")
		}
		if p+2 > len(container) {
			return nil, errf(codeBadMagic, "truncated tag at offset %d", p)
		}
		var (
			n  int
			ok bool
		)
		switch binary.LittleEndian.Uint16(container[p : p+2]) {
		case tagEncrypt:
			et, n, ok = encryptTagRead(container[p:])
		case tagToken:
			tk, n, ok = tokenTagRead(container[p:])
		case tagExpires:
			ex, n, ok = expiresTagRead(container[p:])
		case tagHash:
			ht, n, ok = hashTagRead(container[p:])
		case tagData:
			dt, n, ok = dataTagRead(container[p:])
		default:
			n, ok = 0, true
		}
		if !ok {
			return nil, errf(codeBadMagic, "truncated tag at offset %d", p)
		}
		p += n
		count++
	}
	if count > 8 {
		return nil, errf(codeBadMagic, "more than 8 tags")
	}

	baseKey := make([]byte, 16)
	copy(baseKey, ctx.Key)
	key16 := createKey(et, baseKey, 16, ctx.Expires, tk.token, ctx.UseKey)

	if version == 2 {
		if ht.tagType != 0 {
			if len(container) < hashTagLen {
				return nil, errf(codeBadMagic, "container shorter than hashTag")
			}
			if createHashTag(container[:len(container)-hashTagLen]) != ht.hash {
				return nil, errf(codeBadHash, "hash mismatch")
			}
		}
		if tk.tagType != 0 {
			if md5Sum(ctx.Token) != tk.token {
				return nil, errf(codeBadToken, "token mismatch")
			}
		}
		ge := getExpires(ex, et, key16[:])
		if ge != ex.expires {
			return nil, errf(codeBadExpires, "expires tag mismatch")
		}
		if ge < ctx.Expires {
			return nil, errf(codeBadExpires, "container expired")
		}
	}

	return getData(et, key16[:], dt.data).data, nil
}

// Encrypt mirrors encrypt_parse (0x22b0). It always emits version 2 and the
// tag order header → encryptTag → [tokenTag] → expiresTag → dataTag → hashTag,
// with the hash covering every preceding byte.
func Encrypt(plain []byte, ctx Context) ([]byte, error) {
	et := createEncryptTag()

	var tk tokenTag
	tokenLen := 0
	if ctx.UseToken {
		tk = createTokenTag(ctx.Token)
		tokenLen = tokenTagLen
	}

	baseKey := make([]byte, 16)
	copy(baseKey, ctx.Key)
	key16 := createKey(et, baseKey, 16, ctx.Expires, tk.token, ctx.UseKey)

	dt := createDataTag(et, plain, key16[:])
	ex := createExpiresTag(et, ctx.Expires, key16[:])

	total := len(dt.data) + 6 + et.wireLen() + headerLen +
		tokenLen + expiresTagLen + hashTagLen
	buf := make([]byte, total)

	p := 0
	p += headWriteInto(buf[p:])
	p += encryptTagWriteInto(buf[p:], et)
	if ctx.UseToken {
		p += tokenTagWriteInto(buf[p:], tk)
	}
	p += expiresTagWriteInto(buf[p:], ex)
	p += dataTagWriteInto(buf[p:], dt)
	hashTagWriteInto(buf[p:], hashTag{tagType: tagHash, hash: createHashTag(buf[:p])})
	return buf, nil
}
