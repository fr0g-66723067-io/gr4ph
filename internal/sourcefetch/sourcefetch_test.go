package sourcefetch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// roundTripFunc lets a test fail the moment a refused URL would dial.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestFetchAllowlistedOrigin covers a served body and an error status from an
// allowlisted origin.
func TestFetchAllowlistedOrigin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dir/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	f := Fetcher{
		Origins:   []Origin{{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/dir/"}},
		Transport: srv.Client().Transport,
	}
	got, err := f.Fetch(srv.URL + "/dir/file")
	if err != nil {
		t.Fatalf("Fetch(allowlisted): %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("Fetch(allowlisted) = %q, want hello", got)
	}
	if _, err := f.Fetch(srv.URL + "/dir/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("Fetch(404) err = %v, want a 404 error", err)
	}
}

// TestFetchRefusesBeforeDialing pins every refusal to the check, not the
// network: the transport fails the test if it is ever invoked.
func TestFetchRefusesBeforeDialing(t *testing.T) {
	f := Fetcher{
		Origins: []Origin{{Host: "example.com", Path: "/pinned/"}},
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("a refused URL must not dial")
			return nil, nil
		}),
	}
	tests := []struct {
		name, src, want string
	}{
		{"http scheme", "http://example.com/pinned/x.json", `scheme "http" is not https`},
		{"outside host", "https://evil.example/pinned/x.json", `host "evil.example" is not an allowlisted source`},
		{"dot-dot escapes", "https://example.com/pinned/../secret", `path "/secret" is outside the allowlisted prefixes`},
		{"outside path", "https://example.com/other/x.json", `path "/other/x.json" is outside the allowlisted prefixes`},
		{"userinfo", "https://user@example.com/pinned/x.json", "userinfo is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.Fetch(tt.src)
			if err == nil {
				t.Fatalf("Fetch(%s) was allowed", tt.src)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Fetch(%s) err = %q, want it to contain %q", tt.src, err, tt.want)
			}
		})
	}

	// The zero Fetcher allows no origin at all.
	var zero Fetcher
	_, err := zero.Fetch("https://example.com/pinned/x.json")
	if err == nil || !strings.Contains(err.Error(), `host "example.com" is not an allowlisted source`) {
		t.Fatalf("zero Fetcher err = %v, want the host refusal", err)
	}
}

// TestFetchRefusesRedirect pins redirect refusal: a 3xx is a status error, not
// a second request.
func TestFetchRefusesRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dir/file", http.StatusFound)
	}))
	defer srv.Close()

	f := Fetcher{
		Origins:   []Origin{{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/dir/"}},
		Transport: srv.Client().Transport,
	}
	if _, err := f.Fetch(srv.URL + "/dir/redir"); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("Fetch(redirect) err = %v, want a 302 error", err)
	}
}

// TestFetchTruncatedBody pins that a body shorter than its Content-Length is an
// error, not a silent partial read.
func TestFetchTruncatedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	defer srv.Close()

	f := Fetcher{
		Origins:   []Origin{{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/"}},
		Transport: srv.Client().Transport,
	}
	if _, err := f.Fetch(srv.URL + "/dir/file"); err == nil {
		t.Fatal("a truncated body must fail")
	}
}
