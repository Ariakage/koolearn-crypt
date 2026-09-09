package kcrypt

// Cipher selectors resolved through plansDIC. The on-wire plan byte is first
// mapped through the 32-entry dictionary below, then dispatched to a primitive.
const (
	cipherCaesar int8 = 0
	cipherRC4    int8 = 1
	cipherFence  int8 = 2
	cipherAES    int8 = 3
)

// plansDIC is the 32-byte constant table at __TEXT,__const +0xed30 in the
// reference binary. decryptByPlan indexes it with a signed plan byte, so only
// indices 0..31 are valid; the reference encryptor emits rand()%32 there.
var plansDIC = [32]int8{
	3, 1, 0, 0, 3, 0, 2, 3, 3, 1, 3, 3, 1, 1, 1, 2,
	3, 3, 0, 2, 0, 0, 1, 2, 3, 0, 3, 3, 2, 0, 1, 3,
}

// decryptByPlan mirrors decryptByPlan (0x7140). It applies the plan list in
// reverse order and then strips the PKCS#7 padding with the reference's
// deliberately forgiving rules. key is always the 16-byte derived key and each
// primitive receives that full length, exactly like the reference call sites.
func decryptByPlan(plans, key, data []byte) []byte {
	buf := append([]byte(nil), data...)
	for idx := len(plans) - 1; idx >= 0; idx-- {
		buf = applyPlan(plans[idx], key, buf, false)
	}
	return unpadFuzzy(buf)
}

// encryptByPlan mirrors encryptByPlan (0x6f80): PKCS#7 pad up to a 16-byte
// boundary first, then apply the plan list in forward order.
func encryptByPlan(plans, key, data []byte) []byte {
	paddedLen := (len(data) + 0x0f) &^ 0x0f
	buf := make([]byte, paddedLen)
	pad := byte(paddedLen - len(data))
	for i := len(data); i < paddedLen; i++ {
		buf[i] = pad
	}
	copy(buf, data)

	for idx := 0; idx < len(plans); idx++ {
		buf = applyPlan(plans[idx], key, buf, true)
	}
	return buf
}

// applyPlan resolves one plan byte and runs the matching primitive. Out-of-range
// plan bytes are skipped: the reference would index plansDIC out of bounds
// (undefined behaviour) and it never emits them, so the divergence is benign.
func applyPlan(planByte byte, key, buf []byte, encrypt bool) []byte {
	if int(planByte) >= len(plansDIC) {
		return buf
	}
	sel := plansDIC[planByte]
	if sel < 0 || sel > 3 {
		return buf
	}
	switch sel {
	case cipherCaesar:
		if encrypt {
			return caesarEncrypt(buf, key)
		}
		return caesarDecrypt(buf, key)
	case cipherRC4:
		rc4XOR(buf, key)
		return buf
	case cipherFence:
		if encrypt {
			return fenceEncrypt(buf, key)
		}
		return fenceDecrypt(buf, key)
	case cipherAES:
		if encrypt {
			_ = aesEncryptECB(buf, key)
		} else {
			_ = aesDecryptECB(buf, key)
		}
		return buf
	default:
		return buf
	}
}

// unpadFuzzy reproduces the reference PKCS#7 stripping at the tail of
// decryptByPlan. A final byte > 16 leaves the buffer untouched; a final byte of
// 0 also leaves it untouched; otherwise the trailing run is validated and only
// removed when every byte matches. A negative final length (possible only for a
// malformed, shorter-than-padding input) is clamped instead of reproducing the
// reference out-of-bounds read.
func unpadFuzzy(buf []byte) []byte {
	n := len(buf)
	if n == 0 {
		return buf
	}
	last := int(buf[n-1])
	finalLen := n
	if last <= 16 {
		finalLen = n - last
		if last != 0 && finalLen >= 0 {
			for i := finalLen; i < n; i++ {
				if int(buf[i]) != last {
					finalLen = n
					break
				}
			}
		}
	}
	if finalLen < 0 {
		finalLen = n
	}
	return buf[:finalLen]
}
