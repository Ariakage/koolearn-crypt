package hls

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultUserAgent mimics a desktop browser; koolearn's session.js also
// rewrites the UA, so callers can override it via headers.
const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Fetcher downloads resources with custom headers and simple retry/backoff.
type Fetcher struct {
	client  *http.Client
	headers map[string]string
	retries int
}

// NewFetcher builds a Fetcher. headers may be nil; a default User-Agent is
// always set and can be overridden by passing "User-Agent" in headers.
func NewFetcher(headers map[string]string, retries int, timeout time.Duration) *Fetcher {
	h := map[string]string{"User-Agent": DefaultUserAgent}
	for k, v := range headers {
		h[k] = v
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if retries < 0 {
		retries = 0
	}
	return &Fetcher{client: &http.Client{Timeout: timeout}, headers: h, retries: retries}
}

// Get fetches rawURL and returns the body bytes, retrying on transport/5xx errors.
func (f *Fetcher) Get(ctx context.Context, rawURL string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= f.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range f.headers {
			req.Header.Set(k, v)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("http status %d", resp.StatusCode)
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("GET %s failed after %d attempt(s): %w", rawURL, f.retries+1, lastErr)
}

// Resolve turns a (possibly relative) reference into an absolute URL against base.
func Resolve(base *url.URL, ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}
