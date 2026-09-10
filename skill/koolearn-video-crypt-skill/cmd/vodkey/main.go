// Command vodkey decrypts a koolearn key.bin (a KEY. v2 container) and prints
// the recovered key material.
//
// Usage:
//
//	vodkey -key 5wqPBk89IkGBxXZy -token 110607776 path/to/key.bin
//
// The expires value is read straight out of the container (it is stored in the
// clear inside the expires tag), so it does not have to be supplied. Pass
// -expires to override, or -normalize to run the addon's Method fallback first.
package main

import (
	"flag"
	"fmt"
	"os"

	"koolearn-crypt/internal/kcrypt"
)

func main() {
	key := flag.String("key", "", "base key (ET hardcoded or caller key)")
	token := flag.String("token", "", "token, typically the numeric user id")
	expires := flag.Int64("expires", 0, "expires override; 0 = read from the container")
	normalize := flag.Bool("normalize", false, "apply the addon Method expires fallback")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: vodkey -key K -token T path/to/key.bin")
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

	fmt.Fprintf(os.Stderr, "container=%d bytes expires=%d token=%q\n", len(data), exp, *token)

	ctx := kcrypt.Context{
		Key:      []byte(*key),
		UseKey:   *key != "",
		Expires:  exp,
		UseToken: *token != "",
		Token:    []byte(*token),
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
