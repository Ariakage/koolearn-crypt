package kcrypt

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// oracleProc drives harness/oracle, the x86_64 dlopen harness that loads the
// reference decrypt.node and exposes every symbol over a line protocol. Every
// cross-check in this file compares the Go port against that reference.
type oracleProc struct {
	t   *testing.T
	cmd *exec.Cmd
	in  *bufio.Writer
	out *bufio.Scanner
}

func newOracle(t *testing.T) *oracleProc {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	bin := filepath.Join(root, "harness", "oracle")
	node := filepath.Join(root, "reference", "koolearn-decrypt", "decrypt.node")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("oracle harness not built (run harness/build.sh): %v", err)
	}
	if _, err := os.Stat(node); err != nil {
		t.Skipf("reference decrypt.node missing: %v", err)
	}

	cmd := exec.Command(bin, node)
	cmd.Dir = root
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("oracle stdin: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("oracle stdout: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("oracle harness cannot start (x86_64 + Rosetta required): %v", err)
	}

	o := &oracleProc{t: t, cmd: cmd, in: bufio.NewWriter(stdin), out: bufio.NewScanner(stdout)}
	o.out.Buffer(make([]byte, 0, 1<<16), 1<<22)
	t.Cleanup(func() {
		_, _ = o.in.WriteString("quit\n")
		_ = o.in.Flush()
		_ = cmd.Wait()
	})

	// MD5(0x00) is a fixed, well-known value: proves the addon loaded and the
	// protocol round-trips before any test logic runs.
	if got := o.raw("md5 00"); got != "93b885adfe0da089cdf634904fd59f71" {
		t.Fatalf("oracle handshake failed: got %q, stderr=%s", got, stderr.String())
	}
	return o
}

// raw sends one command line and returns the single response line.
func (o *oracleProc) raw(line string) string {
	o.t.Helper()
	if _, err := o.in.WriteString(line + "\n"); err != nil {
		o.t.Fatalf("oracle write %q: %v", line, err)
	}
	if err := o.in.Flush(); err != nil {
		o.t.Fatalf("oracle flush: %v", err)
	}
	if !o.out.Scan() {
		o.t.Fatalf("oracle produced no reply to %q: %v", line, o.out.Err())
	}
	return o.out.Text()
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func arr16(b []byte) [16]byte {
	var a [16]byte
	copy(a[:], b)
	return a
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// splitLenHex parses the "<length> <hex>" reply shape used by decryptplan.
func splitLenHex(t *testing.T, resp string) (int, []byte) {
	t.Helper()
	fields := strings.Fields(resp)
	if len(fields) == 0 {
		t.Fatalf("empty reply")
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("bad length in %q: %v", resp, err)
	}
	if n == 0 {
		return 0, nil
	}
	if len(fields) < 2 {
		t.Fatalf("missing hex payload in %q", resp)
	}
	return n, mustHex(t, fields[1])
}

func TestCaesarAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 300; i++ {
		src := randBytes(rng, rng.Intn(96)+1)
		key := randBytes(rng, rng.Intn(32)+1)

		want := o.raw(fmt.Sprintf("caesar %x %x", src, key))
		if got := caesarDecrypt(src, key); hex.EncodeToString(got) != want {
			t.Fatalf("caesar #%d src=%x key=%x: got %x want %s", i, src, key, got, want)
		}
		wantEnc := o.raw(fmt.Sprintf("caesar_enc %x %x", src, key))
		if got := caesarEncrypt(src, key); hex.EncodeToString(got) != wantEnc {
			t.Fatalf("caesar_enc #%d src=%x key=%x: got %x want %s", i, src, key, got, wantEnc)
		}
	}
}

func TestRC4AgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 300; i++ {
		src := randBytes(rng, rng.Intn(128)+1)
		key := randBytes(rng, rng.Intn(32)+1)

		want := o.raw(fmt.Sprintf("rc4 %x %x", src, key))
		buf := append([]byte(nil), src...)
		rc4XOR(buf, key)
		if hex.EncodeToString(buf) != want {
			t.Fatalf("rc4 #%d src=%x key=%x: got %x want %s", i, src, key, buf, want)
		}
	}
}

func TestFenceAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 300; i++ {
		src := randBytes(rng, rng.Intn(96)+1)
		key := randBytes(rng, rng.Intn(32)+1)

		want := o.raw(fmt.Sprintf("fence %x %x", src, key))
		if got := fenceDecrypt(src, key); hex.EncodeToString(got) != want {
			t.Fatalf("fence #%d src=%x key=%x: got %x want %s", i, src, key, got, want)
		}
		wantEnc := o.raw(fmt.Sprintf("fence_enc %x %x", src, key))
		if got := fenceEncrypt(src, key); hex.EncodeToString(got) != wantEnc {
			t.Fatalf("fence_enc #%d src=%x key=%x: got %x want %s", i, src, key, got, wantEnc)
		}
	}
}

func TestAESECBAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < 200; i++ {
		data := randBytes(rng, (rng.Intn(4)+1)*16)
		key := randBytes(rng, 16)

		want := o.raw(fmt.Sprintf("aesecbdec %x %x", data, key))
		buf := append([]byte(nil), data...)
		if err := aesDecryptECB(buf, key); err != nil {
			t.Fatalf("aesDecryptECB: %v", err)
		}
		if hex.EncodeToString(buf) != want {
			t.Fatalf("aesecbdec #%d data=%x key=%x: got %x want %s", i, data, key, buf, want)
		}
		wantEnc := o.raw(fmt.Sprintf("aesecbenc %x %x", data, key))
		buf = append([]byte(nil), data...)
		if err := aesEncryptECB(buf, key); err != nil {
			t.Fatalf("aesEncryptECB: %v", err)
		}
		if hex.EncodeToString(buf) != wantEnc {
			t.Fatalf("aesecbenc #%d data=%x key=%x: got %x want %s", i, data, key, buf, wantEnc)
		}
	}
}

func TestHashPrimitivesAgainstOracle(t *testing.T) {
	o := newOracle(t)

	// 空输入无法走 oracle（其 strtok 不接受空 hex 参数），用公开标准值兜底。
	if got := fmt.Sprintf("%x", md5Sum(nil)); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("md5 empty: got %s", got)
	}

	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 200; i++ {
		// oracle 的 hex 参数必须至少 1 字节，否则 strtok 会把参数吞掉。
		src := randBytes(rng, rng.Intn(200)+1)

		if got := hex.EncodeToString(func() []byte { h := md5Sum(src); return h[:] }()); got != o.raw(fmt.Sprintf("md5 %x", src)) {
			t.Fatalf("md5 #%d src=%x: got %s", i, src, got)
		}
		if got := hex.EncodeToString(func() []byte { h := sha1LittleEndian(src); return h[:] }()); got != o.raw(fmt.Sprintf("sha1 %x", src)) {
			t.Fatalf("sha1 #%d src=%x: got %s", i, src, got)
		}

		// hashtag -> "<ret> <tagType> <hash16>"
		resp := strings.Fields(o.raw(fmt.Sprintf("hashtag %x", src)))
		if len(resp) != 3 {
			t.Fatalf("hashtag #%d: malformed reply %q", i, resp)
		}
		if resp[1] != "ffff" {
			t.Fatalf("hashtag #%d: tagType %s, want ffff", i, resp[1])
		}
		want := mustHex(t, resp[2])
		got := createHashTag(src)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("hashtag #%d src=%x: got %x want %x", i, src, got, want)
		}
	}
}

func TestDecryptByPlanAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(6))
	for i := 0; i < 400; i++ {
		plans := make([]byte, rng.Intn(9)+1)
		for j := range plans {
			plans[j] = byte(rng.Intn(32))
		}
		key := randBytes(rng, 16)
		// Data length stays a multiple of 16: the reference AES branch reads
		// whole blocks and would be undefined on a partial tail.
		data := randBytes(rng, (rng.Intn(8)+1)*16)

		wantLen, want := splitLenHex(t, o.raw(fmt.Sprintf("decryptplan %x %x %x", plans, key, data)))
		got := decryptByPlan(plans, key, data)
		if len(got) != wantLen || !bytes.Equal(got, want) {
			t.Fatalf("decryptplan #%d plans=%x key=%x data=%x:\n got (%d) %x\nwant (%d) %x",
				i, plans, key, data, len(got), got, wantLen, want)
		}
	}
}

func TestCreateKeyAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		eKey := randBytes(rng, 16)
		base := randBytes(rng, 16)
		token := randBytes(rng, 16)
		useKey := rng.Intn(2)
		expires := int64(0)
		if rng.Intn(2) == 1 {
			expires = int64(1_600_000_000 + rng.Intn(1<<24))
		}

		want := mustHex(t, o.raw(fmt.Sprintf("createkey %x 16 %x 16 %d %x %d",
			eKey, base, expires, token, useKey)))

		et := encryptTag{key: eKey}
		got := createKey(et, base, 16, expires, arr16(token), useKey == 1)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("createkey #%d eKey=%x base=%x expires=%d token=%x useKey=%d:\n got %x\nwant %x",
				i, eKey, base, expires, token, useKey, got, want)
		}
	}
}

// TestDecryptParseAgainstOracle builds containers with the reference
// encrypt_parse and decrypts them with the Go port.
func TestDecryptParseAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(8))
	ctxKey := []byte("5wqPBk89IkGBxXZy")

	for i := 0; i < 200; i++ {
		plain := randBytes(rng, rng.Intn(150)+1)
		token := randBytes(rng, rng.Intn(24)+1)
		expires := int64(1_700_000_000 + rng.Intn(1<<24))
		useKey := rng.Intn(2) == 1
		useToken := rng.Intn(2) == 1

		resp := strings.Fields(o.raw(fmt.Sprintf("encryptparse %x %x %d %d %x %d",
			plain, ctxKey, boolInt(useKey), boolInt(useToken), token, expires)))
		if len(resp) != 2 {
			t.Fatalf("encryptparse #%d: malformed reply %q", i, resp)
		}
		container := mustHex(t, resp[1])

		got, err := Decrypt(container, Context{
			Key:      ctxKey,
			UseKey:   useKey,
			Expires:  expires,
			UseToken: useToken,
			Token:    token,
		})
		if err != nil {
			t.Fatalf("Decrypt #%d (useKey=%v useToken=%v): %v\ncontainer=%x",
				i, useKey, useToken, err, container)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("Decrypt #%d: got %x want %x", i, got, plain)
		}
	}
}

// TestEncryptParseAgainstOracle encrypts with the Go port and feeds the
// container to the reference decrypt_parse, including its v2 hash/token/expires
// checks.
func TestEncryptParseAgainstOracle(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(9))
	ctxKey := []byte("5wqPBk89IkGBxXZy")

	for i := 0; i < 200; i++ {
		plain := randBytes(rng, rng.Intn(150)+1)
		token := randBytes(rng, rng.Intn(24)+1)
		expires := int64(1_700_000_000 + rng.Intn(1<<24))
		useKey := rng.Intn(2) == 1
		useToken := rng.Intn(2) == 1

		container, err := Encrypt(plain, Context{
			Key:      ctxKey,
			UseKey:   useKey,
			Expires:  expires,
			UseToken: useToken,
			Token:    token,
		})
		if err != nil {
			t.Fatalf("Encrypt #%d: %v", i, err)
		}

		resp := strings.Fields(o.raw(fmt.Sprintf("decryptparse %x %x %d %d %x",
			container, ctxKey, boolInt(useKey), expires, token)))
		if len(resp) < 2 {
			t.Fatalf("decryptparse #%d: malformed reply %q", i, resp)
		}
		if ret, _ := strconv.Atoi(resp[0]); ret != 0 {
			t.Fatalf("decryptparse #%d returned %d (container=%x)", i, ret, container)
		}
		n, got := splitLenHex(t, strings.Join(resp[1:], " "))
		if n != len(plain) || !bytes.Equal(got, plain) {
			t.Fatalf("decryptparse #%d: got (%d) %x want (%d) %x", i, n, got, len(plain), plain)
		}
	}
}

// TestDecryptParseRejectsTampered pins the three v2 integrity failures to the
// reference error codes.
func TestDecryptParseRejectsTampered(t *testing.T) {
	o := newOracle(t)
	rng := rand.New(rand.NewSource(10))
	ctxKey := []byte("5wqPBk89IkGBxXZy")
	token := []byte("user-12345678")
	expires := int64(1_700_000_000)

	resp := strings.Fields(o.raw(fmt.Sprintf("encryptparse %x %x 1 1 %x %d",
		[]byte("tamper me please"), ctxKey, token, expires)))
	container := mustHex(t, resp[1])

	ctx := Context{Key: ctxKey, UseKey: true, Expires: expires, UseToken: true, Token: token}
	if _, err := Decrypt(container, ctx); err != nil {
		t.Fatalf("baseline decrypt: %v", err)
	}

	// Flip one payload byte (inside dataTag) -> hash mismatch.
	tampered := append([]byte(nil), container...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := Decrypt(tampered, ctx); err == nil || err.(*Error).Code != codeBadHash {
		t.Fatalf("tampered payload: got %v, want code %d", err, codeBadHash)
	}

	// Wrong token -> token mismatch.
	badToken := append([]byte(nil), token...)
	badToken[0] ^= 0x01
	badCtx := ctx
	badCtx.Token = badToken
	if _, err := Decrypt(container, badCtx); err == nil || err.(*Error).Code != codeBadToken {
		t.Fatalf("wrong token: got %v, want code %d", err, codeBadToken)
	}

	// Higher required expiry -> expired.
	lateCtx := ctx
	lateCtx.Expires = expires + 1
	if _, err := Decrypt(container, lateCtx); err == nil || err.(*Error).Code != codeBadExpires {
		t.Fatalf("late expiry: got %v, want code %d", err, codeBadExpires)
	}

	// Bad magic and bad version.
	if _, err := Decrypt([]byte("nope"), ctx); err == nil {
		t.Fatal("short container accepted")
	}
	badMagic := append([]byte(nil), container...)
	badMagic[0] = 'X'
	if _, err := Decrypt(badMagic, ctx); err == nil || err.(*Error).Code != codeBadMagic {
		t.Fatalf("bad magic: got %v, want code %d", err, codeBadMagic)
	}
	badVersion := append([]byte(nil), container...)
	badVersion[4] = 9
	if _, err := Decrypt(badVersion, ctx); err == nil || err.(*Error).Code != codeBadVersion {
		t.Fatalf("bad version: got %v, want code %d", err, codeBadVersion)
	}
	_ = rng
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
