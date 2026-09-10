// Command vodkey decrypts a koolearn key.bin (a KEY. v2 container) and prints
// the recovered key material.
//
// Usage:
//
//	vodkey -key 5wqPBk89IkGBxXZy path/to/key.bin
//
// The expires value is read straight out of the container (it is stored in the
// clear inside the expires tag), so it does not have to be supplied. Pass
// -expires to override, or -normalize to run the addon's Method fallback first.
//
// The token is optional too: -token auto (the default) recovers it from the
// client cache by matching the container's token hash, and when it cannot be
// found the v2 token check is skipped, which does not change the recovered key.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"koolearn-crypt/internal/kcrypt"
	"koolearn-crypt/internal/vod"
)

func main() {
	key := flag.String("key", "", "base key (ET hardcoded or caller key)")
	token := flag.String("token", "auto", "token (numeric user id), or \"auto\" to recover it from the local cache")
	expires := flag.Int64("expires", 0, "expires override; 0 = read from the container")
	normalize := flag.Bool("normalize", false, "apply the addon Method expires fallback")
	skipToken := flag.Bool("skip-token-check", false, "skip the v2 tokenTag check (when the token is unknown)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: vodkey -key K path/to/key.bin")
		os.Exit(2)
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	exp := *expires
	if exp == 0 {
		exp, err = kcrypt.ContainerExpires(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "expires:", err)
			os.Exit(1)
		}
	}
	if *normalize {
		exp = kcrypt.NormalizeExpires(exp)
	}

	tok, tokNote := resolveToken(*token, flag.Arg(0))
	skip := *skipToken || tok == ""

	fmt.Fprintf(os.Stderr, "container=%d bytes expires=%d token=%s\n", len(data), exp, tokNote)

	ctx := kcrypt.Context{
		Key:            []byte(*key),
		UseKey:         *key != "",
		Expires:        exp,
		UseToken:       tok != "",
		Token:          []byte(tok),
		SkipTokenCheck: skip,
	}

	out, err := kcrypt.Decrypt(data, ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decrypt:", err)
		os.Exit(1)
	}

	fmt.Printf("len=%d\n", len(out))
	fmt.Printf("hex=%x\n", out)
	fmt.Printf("text=%q\n", out)
}

// resolveToken returns the token to use and a note describing its origin.
// "auto" (or an empty value) reads the token hash from the container and matches
// it against the numeric cache directories; an empty result is not fatal because
// the container key does not depend on the token.
func resolveToken(flagVal, path string) (token, note string) {
	if flagVal != "" && !strings.EqualFold(flagVal, "auto") {
		return flagVal, flagVal + " (from -token)"
	}
	tok, verified, err := vod.ResolveTokenForContainer(path)
	if err != nil {
		return "", "unknown (resolve failed: " + err.Error() + "; token check skipped)"
	}
	if verified {
		return tok, tok + " (auto: matched cache/<uid>)"
	}
	return "", "unknown (no cache match; token check skipped - key unaffected)"
}
