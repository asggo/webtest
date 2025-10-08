package webtest

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
)

type tester struct {
	server *httptest.Server
	client *http.Client
	variables map[string]string
}

func (t *tester) run(s script) error {
	for _, test := range s.tests {
		err := test.run(t)
		if err != nil {
			return fmt.Errorf("could not tester.run: %v", err)
		}
	}

	return nil
}

// newTester creates new tester object with the given handler.
func newTester(h http.Handler) (tester, error) {
	var t tester

	server := httptest.NewTLSServer(h)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return t, fmt.Errorf("could not newTester: %v", err)
	}

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.Jar = jar

	t.server = server
	t.client = client
	t.variables = make(map[string]string)

	return t, nil
}