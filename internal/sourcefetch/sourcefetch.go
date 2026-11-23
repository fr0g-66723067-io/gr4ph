// Package sourcefetch fetches a pinned upstream source over HTTPS after checking
// it against an allowlist of origins, so a URL handed to a generator flag can
// never reach an arbitrary host.
//
// It is deliberately untagged (no goexperiment.simd) and imports only the
// standard library, so the untagged generators that use it keep building on a
// stock toolchain.
package sourcefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// timeout bounds one whole fetch.
const timeout = 30 * time.Second

// Origin is one allowlisted source origin. Host is matched exactly (case
// insensitively, including any port) against the URL host, and Path is a path
// prefix the cleaned request path must start with.
type Origin struct {
	Host string
	Path string
}

// Fetcher fetches from an allowlist. The zero Fetcher allows no origin, so
// every URL is refused.
type Fetcher struct {
	// Origins are the allowed origins; an empty list refuses every URL.
	Origins []Origin
	// Transport, when non-nil, replaces http.DefaultTransport. Tests inject the
	// transport of an httptest TLS server.
	Transport http.RoundTripper
}

// Fetch returns the body of an HTTPS GET for src. src must use https, carry no
// userinfo, and match one of the configured origins by host and path prefix.
// Redirects are refused, so a 3xx is an error; a mismatch is an error before any
// connection is made.
func (f Fetcher) Fetch(src string) ([]byte, error) {
	u, err := url.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src, err)
	}
	if err := f.check(u); err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src, err)
	}
	client := &http.Client{
		Transport: f.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", src, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src, err)
	}
	return data, nil
}

// check enforces the allowlist on a parsed URL.
func (f Fetcher) check(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not https", u.Scheme)
	}
	if u.User != nil {
		return errors.New("userinfo is not allowed")
	}
	if u.Opaque != "" {
		return errors.New("opaque URLs are not allowed")
	}
	p := path.Clean(u.Path)
	hostAllowed := false
	for _, o := range f.Origins {
		if !strings.EqualFold(u.Host, o.Host) {
			continue
		}
		hostAllowed = true
		if strings.HasPrefix(p, o.Path) {
			return nil
		}
	}
	if !hostAllowed {
		return fmt.Errorf("host %q is not an allowlisted source", u.Host)
	}
	return fmt.Errorf("path %q is outside the allowlisted prefixes", p)
}
