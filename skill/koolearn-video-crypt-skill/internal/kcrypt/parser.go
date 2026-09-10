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

	// SkipTokenCheck drops the version-2 tokenTag comparison. The token is not
	// an input to createKey — it only gates the container through the md5 stored
	// in tokenTag — so skipping the check yields the exact same key whenever the
	// token is unknown. Set it to degrade gracefully instead of failing with
	// codeBadToken.
	SkipTokenCheck bool
}

// Decrypt mirrors decrypt_parse (0x2540). It walks the tag list, derives the
// container key with createKey, runs the version-2 integrity checks, and
// finally decrypts the data tag.
//
// Unlike the reference it never reads out of bounds: a tag whose declared
// length runs past the container returns codeBadMagic instead of returning
// uninitialised memory.
func Decrypt(container []byte, ctx Context) ([]byte, error) {
	return decrypt(container, ctx, true)
}

// DecryptRaw is Decrypt without the trailing PKCS#7 strip on the data tag. The
// reference strips unconditionally, so a plaintext that is already a multiple
// of 16 bytes and ends in 0x01 loses that byte; encryptByPlan adds no padding
// at that length, making the byte real data. Callers expecting a fixed-length
// key use this as a fallback when Decrypt comes up short.
func DecryptRaw(container []byte, ctx Context) ([]byte, error) {
	return decrypt(container, ctx, false)
}

func decrypt(container []byte, ctx Context, unpad bool) ([]byte, error) {
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
		if tk.tagType != 0 && !ctx.SkipTokenCheck {
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

	return getDataWith(et, key16[:], dt.data, unpad).data, nil
}

// ContainerExpires returns the cleartext expires field of a KEY. container.
//
// The expires tag stores the value twice: once in the clear, so a client can
// tell whether a cached container is stale without the key, and once encrypted
// inside expiresData. Callers that only need the createKey input can therefore
// read it without decrypting the container.
//
// Unlike Decrypt this does not verify anything, so it returns codeBadMagic for
// any structural problem rather than the more specific token/expires codes.
func ContainerExpires(container []byte) (int64, error) {
	if len(container) < headerLen {
		return 0, errf(codeBadMagic, "container shorter than header")
	}
	if binary.LittleEndian.Uint32(container[0:4]) != magic {
		return 0, errf(codeBadMagic, "bad KEY. magic")
	}

	p := headerLen
	for p+2 <= len(container) {
		var n int
		switch binary.LittleEndian.Uint16(container[p : p+2]) {
		case tagEncrypt:
			if p+5 > len(container) {
				return 0, errf(codeBadMagic, "truncated encrypt tag")
			}
			pl := int(binary.LittleEndian.Uint16(container[p+3 : p+5]))
			if p+7+pl > len(container) {
				return 0, errf(codeBadMagic, "truncated encrypt tag plans")
			}
			kl := int(binary.LittleEndian.Uint16(container[p+5+pl : p+7+pl]))
			n = 7 + pl + kl
		case tagToken, tagHash:
			n = 18
		case tagExpires:
			if p+expiresTagLen > len(container) {
				return 0, errf(codeBadMagic, "truncated expires tag")
			}
			return int64(binary.LittleEndian.Uint64(container[p+2 : p+10])), nil
		case tagData:
			if p+6 > len(container) {
				return 0, errf(codeBadMagic, "truncated data tag")
			}
			n = 6 + int(binary.LittleEndian.Uint32(container[p+2:p+6]))
		default:
			return 0, errf(codeBadMagic, "unknown tag %#04x at %d", binary.LittleEndian.Uint16(container[p:p+2]), p)
		}
		if n <= 0 || p+n > len(container) {
			return 0, errf(codeBadMagic, "bad tag length %d at %d", n, p)
		}
		p += n
	}
	return 0, errf(codeBadMagic, "no expires tag")
}

// ContainerTokenHash returns the 16-byte token hash stored in the container's
// tokenTag — the MD5 of the client's plaintext token (normally the numeric user
// id). hasToken is false when the container carries no token tag.
//
// Like ContainerExpires it only walks the cleartext tag list, so it needs no
// key and performs no verification. Callers use it to test a candidate token
// against a cache without the risk of a wrong guess: md5 collisions are
// impossible here, so a match is exact.
func ContainerTokenHash(container []byte) (h [16]byte, hasToken bool, err error) {
	if len(container) < headerLen {
		return h, false, errf(codeBadMagic, "container shorter than header")
	}
	if binary.LittleEndian.Uint32(container[0:4]) != magic {
		return h, false, errf(codeBadMagic, "bad KEY. magic")
	}

	p := headerLen
	for p+2 <= len(container) {
		var n int
		switch binary.LittleEndian.Uint16(container[p : p+2]) {
		case tagToken:
			if p+tokenTagLen > len(container) {
				return h, false, errf(codeBadMagic, "truncated token tag")
			}
			copy(h[:], container[p+2:p+tokenTagLen])
			return h, true, nil
		case tagEncrypt:
			if p+5 > len(container) {
				return h, false, errf(codeBadMagic, "truncated encrypt tag")
			}
			pl := int(binary.LittleEndian.Uint16(container[p+3 : p+5]))
			if p+7+pl > len(container) {
				return h, false, errf(codeBadMagic, "truncated encrypt tag plans")
			}
			kl := int(binary.LittleEndian.Uint16(container[p+5+pl : p+7+pl]))
			n = 7 + pl + kl
		case tagHash:
			n = 18
		case tagExpires:
			if p+expiresTagLen > len(container) {
				return h, false, errf(codeBadMagic, "truncated expires tag")
			}
			n = expiresTagLen
		case tagData:
			if p+6 > len(container) {
				return h, false, errf(codeBadMagic, "truncated data tag")
			}
			n = 6 + int(binary.LittleEndian.Uint32(container[p+2:p+6]))
		default:
			return h, false, errf(codeBadMagic, "unknown tag %#04x at %d", binary.LittleEndian.Uint16(container[p:p+2]), p)
		}
		if n <= 0 || p+n > len(container) {
			return h, false, errf(codeBadMagic, "bad tag length %d at %d", n, p)
		}
		p += n
	}
	return h, false, errf(codeBadMagic, "no token tag")
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
