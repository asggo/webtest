package webtest

import (
	"path/filepath"
	"testing"
)


// TestHandler runs the test script files matched by glob against the given
// handler.
func TestHandler(t *testing.T, glob string, h http.Handler) {
	tester, err := newTester(h)
	if err != nil {
		t.Fatalf("could not TestHandler: %v", err)
	}

	defer tester.server.Close()

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

		err = tester.run(script)
		if err != nil {
			t.Fatalf("could not TestHandler: %v", err)
		}
	}
}
