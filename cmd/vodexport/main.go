// Command vodexport decrypts every video in a koolearn download directory and
// writes MP4 files.
//
// It replays the client offline: key.bin (a KEY. container) yields the 16-byte
// segment key through kcrypt, each segment is AES-128-CBC decrypted with a zero
// IV, and the concatenated MPEG-TS is remuxed to MP4 with ffmpeg.
//
// Usage:
//
//	vodexport -token 110607776 -out export \
//	  ~/Library/Application\ Support/koolearn/koolearn/download
//
// Examples:
//
//	vodexport -list ~/Library/.../download          # inspect what was found
//	vodexport -token 110607776 -only 6p0f88... ...  # export a single video
//	vodexport -token 110607776 -jobs 8 -keep-ts ... # keep the plaintext .ts
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"koolearn-crypt/internal/vod"
)

func main() {
	var (
		in        = flag.String("in", "", "download root (may also be the first argument)")
		out       = flag.String("out", "export", "output directory for the .mp4 files")
		token     = flag.String("token", "", "client token (the numeric user id); required unless -list")
		jobs      = flag.Int("jobs", 4, "videos to export concurrently")
		overwrite = flag.Bool("overwrite", false, "re-export videos whose .mp4 already exists")
		keepTS    = flag.Bool("keep-ts", false, "keep the plaintext .ts next to each .mp4")
		list      = flag.Bool("list", false, "list discovered videos and exit")
		only      = flag.String("only", "", "comma-separated video ids to export (default: all)")
		quiet     = flag.Bool("q", false, "suppress per-video progress")
	)
	flag.Usage = usage
	flag.Parse()

	root := *in
	if root == "" && flag.NArg() > 0 {
		root = flag.Arg(0)
	}
	if root == "" {
		usage()
		os.Exit(2)
	}

	videos, err := vod.Discover(root)
	if err != nil {
		fatal("%v", err)
	}
	if len(videos) == 0 {
		fatal("no videos found under %s", root)
	}
	videos = filter(videos, *only)
	if len(videos) == 0 {
		fatal("-only matched none of the %d discovered videos", len(videos))
	}

	if *list {
		for _, v := range videos {
			fmt.Printf("%s  %s\n", v.ID, v.Playlist)
		}
		fmt.Printf("total: %d videos\n", len(videos))
		return
	}
	if *token == "" {
		fatal("-token is required")
	}
	if *jobs < 1 {
		*jobs = 1
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal("create output dir: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("→ root  : %s\n", root)
	fmt.Printf("→ output: %s\n", *out)
	fmt.Printf("→ videos: %d (jobs=%d)\n", len(videos), *jobs)

	start := time.Now()
	type outcome struct {
		res *vod.Result
		err error
	}
	results := make([]outcome, len(videos))
	sem := make(chan struct{}, *jobs)
	var wg sync.WaitGroup
	for i, v := range videos {
		wg.Add(1)
		go func(i int, v vod.Video) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			opt := vod.Options{
				Token:     *token,
				OutDir:    *out,
				Overwrite: *overwrite,
				KeepTS:    *keepTS,
			}
			if !*quiet {
				opt.Logf = func(format string, a ...any) {
					fmt.Printf("[%s] %s\n", v.ID, fmt.Sprintf(format, a...))
				}
			}
			res, err := vod.Export(ctx, v, opt)
			results[i] = outcome{res, err}
		}(i, v)
	}
	wg.Wait()

	var exported, skipped, failed int
	for _, r := range results {
		switch {
		case r.err == nil:
			exported++
			fmt.Printf("✓ %s  %d segments, %s  (%s)\n",
				r.res.Video.ID, r.res.Segments, humanBytes(r.res.Bytes), r.res.Elapsed.Round(time.Millisecond))
		case errors.Is(r.err, vod.ErrExists):
			skipped++
			if !*quiet {
				fmt.Printf("= %s  exists, skipped\n", r.res.Video.ID)
			}
		default:
			failed++
			id := "?"
			if r.res != nil {
				id = r.res.Video.ID
			}
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", id, r.err)
		}
	}
	fmt.Printf("→ done in %s: %d exported, %d skipped, %d failed\n",
		time.Since(start).Round(time.Second), exported, skipped, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// filter keeps the videos named in only (comma separated); an empty filter
// keeps everything.
func filter(videos []vod.Video, only string) []vod.Video {
	if strings.TrimSpace(only) == "" {
		return videos
	}
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	var out []vod.Video
	for _, v := range videos {
		if want[v.ID] {
			out = append(out, v)
		}
	}
	return out
}

func usage() {
	fmt.Fprintf(os.Stderr, "vodexport — decrypt koolearn cached VOD downloads into MP4\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n  vodexport -token <id> [flags] <download root>\n\nFlags:\n")
	flag.PrintDefaults()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
