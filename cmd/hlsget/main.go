// Command hlsget implements "scheme B": download a standard HLS stream
// encrypted with AES-128, decrypt every segment in Go, concatenate them and
// (optionally) remux to MP4 via ffmpeg.
//
// It intentionally does NOT touch koolearn's private encryption; use it for
// playlists whose #EXT-X-KEY METHOD is AES-128.
//
// Usage:
//
//	hlsget [flags] <playlist.m3u8 URL>
//
// Examples:
//
//	hlsget -o out.mp4 https://host/master.m3u8
//	hlsget -o out.mp4 -c 8 -H 'Referer: https://host/' -H 'Cookie: sid=abc' https://host/index.m3u8
//	hlsget -no-mux -keep-segments -o out.ts https://host/index.m3u8
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"koolearn-crypt/internal/hls"
)

type headersFlag struct{ m map[string]string }

func (h *headersFlag) String() string {
	if h == nil || h.m == nil {
		return ""
	}
	parts := make([]string, 0, len(h.m))
	for k, v := range h.m {
		parts = append(parts, k+": "+v)
	}
	return strings.Join(parts, " | ")
}

func (h *headersFlag) Set(s string) error {
	if h.m == nil {
		h.m = map[string]string{}
	}
	i := strings.Index(s, ":")
	if i <= 0 {
		return fmt.Errorf("bad header %q, want 'Key: Value'", s)
	}
	h.m[strings.TrimSpace(s[:i])] = strings.TrimSpace(s[i+1:])
	return nil
}

func main() {
	var (
		out       = flag.String("o", "output.mp4", "output file (.mp4, or .ts with -no-mux)")
		workDir   = flag.String("work", "", "working dir for segments (default: <out>.parts)")
		conc      = flag.Int("c", 4, "download concurrency")
		variant   = flag.Int("variant", -1, "master-playlist variant index (-1 = highest bandwidth)")
		retries   = flag.Int("retries", 3, "per-request retry count")
		timeout   = flag.Duration("timeout", 60*time.Second, "per-request timeout")
		noMux     = flag.Bool("no-mux", false, "only concatenate to .ts; skip ffmpeg remux")
		keepSegs  = flag.Bool("keep-segments", false, "keep per-segment decrypted files")
		hdrFlag   headersFlag
		quietFlag = flag.Bool("q", false, "quiet: no per-segment progress")
	)
	flag.Var(&hdrFlag, "H", "extra request header 'Key: Value' (repeatable)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	playlistURL := flag.Arg(0)

	// ffmpeg is optional: when it is missing, degrade to -no-mux rather than fail.
	if !*noMux {
		if _, err := exec.LookPath("ffmpeg"); err != nil {
			fmt.Fprintln(os.Stderr, "warning: ffmpeg not found in PATH; falling back to -no-mux (.ts output)")
			*noMux = true
		}
	}

	wd := *workDir
	if wd == "" {
		wd = *out + ".parts"
	}
	if err := os.MkdirAll(wd, 0o755); err != nil {
		fatal("create work dir: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := hls.Config{
		PlaylistURL: playlistURL,
		WorkDir:     wd,
		Concurrency: *conc,
		VariantIdx:  *variant,
		Headers:     hdrFlag.m,
		Retries:     *retries,
		Timeout:     *timeout,
	}
	if !*quietFlag {
		start := time.Now()
		cfg.OnProgress = func(done, total int, uri string) {
			fmt.Printf("\r\033[K[%d/%d] %s  (%s)", done, total, truncate(uri, 46), time.Since(start).Round(time.Second))
			if done == total {
				fmt.Println()
			}
		}
	}

	fmt.Printf("→ playlist : %s\n", playlistURL)
	fmt.Printf("→ work dir : %s\n", wd)

	res, err := hls.Run(ctx, cfg)
	if err != nil {
		fatal("download failed: %v", err)
	}
	fmt.Printf("→ segments : %d (encrypted=%v)\n", res.Segments, res.Encrypted)
	fmt.Printf("→ concat ts: %s\n", res.ConcatTS)

	finalOut := *out
	if *noMux {
		// Move/keep the concatenated .ts as the final artifact.
		if filepath.Ext(finalOut) == "" || strings.EqualFold(filepath.Ext(finalOut), ".mp4") {
			finalOut = strings.TrimSuffix(finalOut, filepath.Ext(finalOut)) + ".ts"
		}
		if err := moveFile(res.ConcatTS, finalOut); err != nil {
			fatal("rename ts: %v", err)
		}
		fmt.Printf("→ output ts: %s\n", finalOut)
	} else {
		fmt.Println("→ remuxing to mp4 via ffmpeg ...")
		if err := hls.Remux(res.ConcatTS, finalOut); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("→ output mp4: %s\n", finalOut)
	}

	if !*keepSegs {
		_ = os.RemoveAll(res.SegDir)
		_ = os.Remove(res.ConcatTS)
		if *workDir == "" {
			_ = os.RemoveAll(wd)
		}
	}
	fmt.Println("✓ done")
}

func usage() {
	fmt.Fprintf(os.Stderr, "hlsget — scheme B: standard HLS AES-128 downloader/decrypter\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n  hlsget [flags] <playlist.m3u8 URL>\n\nFlags:\n")
	flag.PrintDefaults()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// cross-device fallback: copy then remove
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return os.Remove(src)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
