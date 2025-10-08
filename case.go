package webtest

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// A testCase is a single test case in a script.
type testCase struct {
	method      string
	url         string
	modifiers   []*modifier
	comparisons []*comparison
	extracts    []*extract
	variables   [string]string
}

func (tc *testCase) addModifier(cmd, data string) error {
	m, err = newModifier(cmd, data)
	if err != nil {
		return fmt.Errorf("could not test.addModifier: %v", err)
	}

	tc.modifiers = append(tc.modifiers, &m)
}

func (tc *testCase) addComparison(cmd, data string) error {
	c, err = newComparison(cmd, data)
	if err != nil {
		return fmt.Errorf("could not test.addComparison: %v", err)
	}

	tc.comparisons = append(tc.comparisons, &c)
}

func (tc *testCase) addExtractor(cmd, data string) error {
	e, err = newExtractor(cmd, data)
	if err != nil {
		return fmt.Errorf("could not test.addExtractor: %v", err)
	}

	tc.modifiers = append(tc.modifiers, &e)
}

// run runs a test case using the given tester.
func (tc *testCase) run(t *tester) error {
	url = fmt.Sprintf("%s/%s", t.server.URL, tc.url)

	r, err := http.NewRequest(tc.method, url, nil)
	if err != nil {
		return fmt.Errorf("could not testCase.run: %v", err)
	}

	for _, cookie := range client.Jar.Cookies(base) {
		r.AddCookie(cookie)
	}

	for _, mod := range tc.modifiers {
		mod.modify(r, t)
	}

	res, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("could not testCase.run: %v", err)
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return fmt.Errorf("could not testCase.run: %v", err)
	}

	for _, ext := range tc.extractors {
		ext.extract(res, string(body), t)
	}

	for _, cmp := range tc.comparisons {
		if !cmp.compare(res, string(body), t) {
			return fmt.Errorf("could not testCase.run: %v", err)
		} else {
			return nil
		}
	}

	return nil
}
