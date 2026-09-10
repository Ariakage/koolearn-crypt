package kcrypt

import "time"

// MethodExpiresFloor is the constant the addon's JS entry point Method
// (0x1be0) compares the `expires` argument against:
//
//	movq  -0xa0(%rbp), %rax    ; rax = expires (v8::Value::IntegerValue)
//	cmpq  $0x58d10eef, %rax
//	jg    keep                 ; expires > floor -> use as-is
//	xorl  %edi, %edi
//	callq time                 ; otherwise time(NULL)
//	imulq $0x3e8, %rax, %rax   ; seconds -> milliseconds
//	movq  %rax, -0x58(%rbp)    ; ctx.expires
//
// 0x58D10EEF = 1490095855 = 2017-03-21 11:30:55 UTC.
const MethodExpiresFloor int64 = 0x58D10EEF

// normalizeExpiresAt is the pure core of NormalizeExpires. now is the current
// wall-clock time in whole seconds, matching what time(NULL) returns in the
// reference. Kept separate so the boundary can be tested without a clock.
func normalizeExpiresAt(expires, now int64) int64 {
	if expires > MethodExpiresFloor {
		return expires
	}
	return now * 1000
}

// NormalizeExpires mirrors the expires guard in Method (0x1be0):
//
//	ctx.expires = expires > 0x58D10EEF ? expires : time(NULL) * 1000
//
// An expires value that is missing, zero or implausibly old (at or below
// 2017-03-21 11:30:55 UTC) is replaced by the current wall-clock time in
// milliseconds. The reference multiplies whole seconds, so the fallback is
// always a multiple of 1000. The reference does not inspect the unit of a
// value above the floor; any plausible timestamp is passed through untouched.
func NormalizeExpires(expires int64) int64 {
	return normalizeExpiresAt(expires, time.Now().Unix())
}

// DecryptMethod mirrors the addon's full JS entry point: Method (0x1be0)
// normalises ctx.Expires with NormalizeExpires and then calls decrypt_parse.
// Prefer it when replaying real client behaviour. Decrypt mirrors
// decrypt_parse alone and leaves ctx.Expires untouched, which is what the
// oracle cross-checks rely on.
func DecryptMethod(container []byte, ctx Context) ([]byte, error) {
	ctx.Expires = NormalizeExpires(ctx.Expires)
	return Decrypt(container, ctx)
}
