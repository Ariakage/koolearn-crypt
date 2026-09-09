// Package kcrypt is a clean-room Go reimplementation of koolearn-decrypt,
// the Node.js native addon (decrypt.node) that protects koolearn's private
// "KEY." containers (vodkey.bin) and the AES/RC4/Caesar/Fence payloads nested
// inside them.
//
// The implementation was reconstructed from the original x86_64 Mach-O binary
// using DWARF debug info, hand disassembly, and a dlopen-based oracle harness
// (harness/oracle.c). It is byte-for-byte compatible with the reference
// implementation for every input produced by the reference encryptor.
//
// The evidence trail — struct layouts, function signatures, disassembly of the
// plan dispatcher and every cipher primitive, and captured truth values — lives
// in docs/decrypt-node-reverse.md.
package kcrypt

import "fmt"

// Reference error codes returned by decrypt_parse.
const (
	codeBadMagic   = -2 // bad "KEY." magic, or too many tags
	codeBadVersion = -3 // container version not in {1, 2}
	codeBadToken   = -4 // tokenTag mismatch
	codeBadExpires = -5 // expiresTag mismatch or expired
	codeBadHash    = -6 // hashTag mismatch
)

// Error reports a container parse or verification failure together with the
// numeric error code used by the reference implementation.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("kcrypt: %s (code %d)", e.Msg, e.Code)
}

func errf(code int, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}
