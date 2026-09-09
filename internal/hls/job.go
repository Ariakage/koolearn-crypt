package hls

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"koolearn-crypt/internal/m3u8"
)

// Progress is called after each segment completes.
type Progress func(done, total int, uri string)

// Config controls a download+decrypt job (scheme B: standard HLS AES-128).
type Config struct {
	PlaylistURL string
	WorkDir     string
	Concurrency int
	VariantIdx  int // -1 = auto (highest bandwidth)
	Headers     map[string]string
	Retries     int
	Timeout     time.Duration
	OnProgress  Progress
}

// Result describes the job outputs.
type Result struct {
	ConcatTS  string // path to the concatenated plaintext MPEG-TS
	SegDir    string // directory holding per-segment .ts files
	Segments  int
	Encrypted bool
}

type job struct {
	fetcher   *Fetcher
	base      *url.URL
	segDir    string
	mu        sync.Mutex
	keys      map[string][]byte
	encrypted bool
}

// Run executes the full pipeline and returns the concatenated .ts path.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	base, err := url.Parse(cfg.PlaylistURL)
	if err != nil {
		return nil, fmt.Errorf("bad playlist url: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("only http(s) playlists are supported, got %q", base.Scheme)
	}
	fetcher := NewFetcher(cfg.Headers, cfg.Retries, cfg.Timeout)

	// 1. fetch + parse the playlist.
	pl, err := fetchPlaylist(ctx, fetcher, cfg.PlaylistURL)
	if err != nil {
		return nil, err
	}

	// 2. master playlist -> resolve to a media playlist.
	mediaURL := cfg.PlaylistURL
	mediaBase := base
	if pl.IsMaster {
		if len(pl.Variants) == 0 {
			return nil, fmt.Errorf("master playlist has no variants")
		}
		v := pickVariant(pl.Variants, cfg.VariantIdx)
		abs, err := Resolve(base, v.URI)
		if err != nil {
			return nil, err
		}
		mediaURL = abs
		if mediaBase, err = url.Parse(abs); err != nil {
			return nil, err
		}
		if pl, err = fetchPlaylist(ctx, fetcher, abs); err != nil {
			return nil, err
		}
	}
	if len(pl.Segments) == 0 {
		return nil, fmt.Errorf("media playlist (%s) has no segments", mediaURL)
	}

	// 3. detect encryption + prepare work dir.
	encrypted := false
	for _, s := range pl.Segments {
		if s.Key != nil && s.Key.Method != "" && s.Key.Method != "NONE" {
			if s.Key.Method != "AES-128" {
				return nil, fmt.Errorf("unsupported key METHOD=%q (scheme B only handles AES-128; "+
					"private/SAMPLE-AES needs scheme A or C)", s.Key.Method)
			}
			encrypted = true
		}
	}
	segDir := filepath.Join(cfg.WorkDir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", segDir, err)
	}

	// 4. download + decrypt segments concurrently.
	j := &job{fetcher: fetcher, base: mediaBase, segDir: segDir, keys: map[string][]byte{}, encrypted: encrypted}
	total := len(pl.Segments)
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}

	type task struct {
		idx int
		seg m3u8.Segment
	}
	tasks := make(chan task)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	setErr := func(e error) { errOnce.Do(func() { firstErr = e }) }

	var pmu sync.Mutex
	completed := 0

	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				if ctx.Err() != nil {
					return
				}
				out := filepath.Join(segDir, fmt.Sprintf("seg_%06d.ts", t.idx))
				if err := j.processSegment(ctx, t.seg, out); err != nil {
					setErr(fmt.Errorf("segment %d (%s): %w", t.idx, t.seg.URI, err))
					return
				}
				pmu.Lock()
				completed++
				c := completed
				pmu.Unlock()
				if cfg.OnProgress != nil {
					cfg.OnProgress(c, total, t.seg.URI)
				}
			}
		}()
	}

	go func() {
		defer close(tasks)
		for i, s := range pl.Segments {
			select {
			case tasks <- task{i, s}:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 5. concatenate segments in order.
	concatPath := filepath.Join(cfg.WorkDir, "concat.ts")
	if err := concatSegments(segDir, total, concatPath); err != nil {
		return nil, err
	}

	return &Result{ConcatTS: concatPath, SegDir: segDir, Segments: total, Encrypted: encrypted}, nil
}

func fetchPlaylist(ctx context.Context, f *Fetcher, u string) (*m3u8.Playlist, error) {
	data, err := f.Get(ctx, u)
	if err != nil {
		return nil, err
	}
	return m3u8.Parse(string(data))
}

func (j *job) processSegment(ctx context.Context, seg m3u8.Segment, outPath string) error {
	abs, err := Resolve(j.base, seg.URI)
	if err != nil {
		return err
	}
	blob, err := j.fetcher.Get(ctx, abs)
	if err != nil {
		return err
	}
	if seg.Key != nil && seg.Key.Method == "AES-128" {
		key, err := j.getKey(ctx, seg.Key.URI)
		if err != nil {
			return err
		}
		iv, err := IVForSegment(seg.Key.IV, seg.Seq)
		if err != nil {
			return err
		}
		if blob, err = DecryptAES128CBC(blob, key, iv); err != nil {
			return err
		}
	}
	return os.WriteFile(outPath, blob, 0o644)
}

// getKey downloads (and caches by absolute URI) a 16-byte AES-128 key.
func (j *job) getKey(ctx context.Context, uri string) ([]byte, error) {
	abs, err := Resolve(j.base, uri)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	if k, ok := j.keys[abs]; ok {
		j.mu.Unlock()
		return k, nil
	}
	j.mu.Unlock()

	k, err := j.fetcher.Get(ctx, abs)
	if err != nil {
		return nil, err
	}
	if len(k) != 16 {
		return nil, fmt.Errorf("key %s is %d bytes, expected 16 (AES-128)", abs, len(k))
	}
	j.mu.Lock()
	j.keys[abs] = k
	j.mu.Unlock()
	return k, nil
}

func pickVariant(vs []m3u8.Variant, idx int) m3u8.Variant {
	if idx >= 0 && idx < len(vs) {
		return vs[idx]
	}
	best := vs[0]
	for _, v := range vs[1:] {
		if v.Bandwidth > best.Bandwidth {
			best = v
		}
	}
	return best
}

func concatSegments(segDir string, total int, outPath string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 256*1024)
	for i := 0; i < total; i++ {
		p := filepath.Join(segDir, fmt.Sprintf("seg_%06d.ts", i))
		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("missing decrypted segment %d: %w", i, err)
		}
		_, err = io.CopyBuffer(out, f, buf)
		f.Close()
		if err != nil {
			return fmt.Errorf("concat segment %d: %w", i, err)
		}
	}
	return nil
}
