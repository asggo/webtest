package webtest

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// newHttpTester creates a server and client for testing the given handler.
func newHttpTester(t *testing.T, h http.Handler) (*httptest.Server, *http.Client, *url.URL) {
	server := httptest.NewTLSServer(h)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("could not newHttpTester:", err)
	}

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.Jar = jar

	url, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal("could not newHttpTester:", err)
	}

	return server, client, url
}

// TestHandler runs the test script files matched by glob against the given
// handler.
func TestHandler(t *testing.T, glob string, h http.Handler) {
	server, client, url := newHttpTester(t, h)
	defer server.Close()

	files, err := filepath.Glob(glob)
	if err != nil {
		t.Fatalf("could not TestHandler: %v", err)
	}

	if len(files) == 0 {
		t.Fatalf("could not TestHandler: no files match %v", glob)
	}

	for _, file := range files {
		data, err := os.Open(file)
		if err != nil {
			t.Fatalf("could not TestHandler: %v", err)
		}

		script := newScript(file)
		err := script.load(data)
		if err != nil {
			t.Fatalf("could not TestHandler: %v", err)
		}

		script.run(t, url, client, h)
}
