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

// A directive is a single action in a testCase.
type directive struct {
	line int
	cmd  string
	data string
}

// A testCase is a single test case in a script.
type testCase struct {
	lineNum     int
	method      string
	url         url.URL
	modifiers   []*modifier
	comparisons []*comparison
	extracts    []*extract
}

func (t *testCase) addModifier(cmd, data string) error {
	m, err = newModifier(cmd, data)
	if err != nil {
		return fmt.Errorf("could not test.addModifier: %v", err)
	}

	t.modifiers = append(t.modifiers, m)
}

func (t *testCase) addComparison(cmd, data string) error {
	c, err = newComparison(cmd, data)
	if err != nil {
		return fmt.Errorf("could not test.addComparison: %v", err)
	}

	t.comparisons = append(t.comparisons, m)
}

func (t *testCase) addExtractor(cmd, data string) error {
	e, err = newExtractor(cmd, data)
	if err != nil {
		return fmt.Errorf("could not test.addExtractor: %v", err)
	}

	t.modifiers = append(t.modifiers, m)
}

// runHandler runs a test case against the handler h.
func (t *testCase) runHandler(base *url.URL, client *http.Client, h http.Handler) ([]extracted, error) {
	var exts []extracted

	url := fmt.Sprintf("%s%s", base, t.url)
	r, err := t.newRequest(url)
	if err != nil {
		return exts, err
	}

	for _, cookie := range client.Jar.Cookies(base) {
		r.AddCookie(cookie)
	}

	res, err := client.Do(r)
	if err != nil {
		return exts, err
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return exts, err
	}

	for _, ext := range t.extractors {
		e := ext.extract(res, string(body))
		exts = append(exts, e)
	}

	for _, cmp := range t.comparisons {
		err := cmp.compare()
		if err != nil {
			return exts, fmt.Errorf("could not t.runHandler: line %d: %v", t.lineNum, err)
		}
	}

	return exts, nil
}

// newRequest creates a new request for the case c,
// using the URL u.
func (t *testCase) newRequest(u string) (*http.Request, error) {
	body := c.requestBody()
	r, err := http.NewRequest(c.method, u, body)
	if err != nil {
		return nil, err
	}

	for _, mod := range t.modifiers {
		mod.modify(r)
	}

	return r, nil
}

func newTestCase(lineNum int, method, data string) (testCase, error) {
	fields := string.Fields(data)

	if len(fields) != 1 {
		return nil, fmt.Errorf("could not newTestCase: expected `method url`")
	}

	return test{lineNum: lineNum, method: method, url: url}
}






// requestBody returns the body for the case's request.
func (c *case_) requestBody() io.Reader {
	if c.postbody == "" {
		return nil
	}
	return strings.NewReader(c.postbody)
}

// check checks the response against the comparisons for the case.
func (c *case_) check(resp *http.Response, body string) error {
	var msg bytes.Buffer
	for _, chk := range c.checks {
		what := chk.what
		if chk.whatArg != "" {
			what += " " + chk.whatArg
		}
		var value string
		switch chk.what {
		default:
			value = "unknown what: " + chk.what
		case "body":
			value = body
		case "trimbody":
			value = trim(body)
		case "code":
			value = fmt.Sprint(resp.StatusCode)
		case "cookie", "rawcookie":
			for _, ck := range resp.Cookies() {
				if ck.Name == chk.whatArg {
					if chk.what == "cookie" {
						value = ck.Value
					} else {
						value = ck.String()
					}
					break
				}
			}
		case "header":
			value = resp.Header.Get(chk.whatArg)
		case "redirect":
			if resp.StatusCode/10 == 30 {
				value = resp.Header.Get("Location")
			}
		}

		switch chk.op {
		default:
			fmt.Fprintf(&msg, "%s:%d: unknown operator %s\n", chk.file, chk.line, chk.op)
		case "==":
			if value != chk.want {
				fmt.Fprintf(&msg, "%s:%d: %s = %q, want %q\n", chk.file, chk.line, what, value, chk.want)
			}
		case "!=":
			if value == chk.want {
				fmt.Fprintf(&msg, "%s:%d: %s == %q (but want !=)\n", chk.file, chk.line, what, value)
			}
		case "~":
			if !chk.wantRE.MatchString(value) {
				fmt.Fprintf(&msg, "%s:%d: %s does not match %#q (but should)\n\t%s\n", chk.file, chk.line, what, chk.want, indent(value))
			}
		case "!~":
			if chk.wantRE.MatchString(value) {
				fmt.Fprintf(&msg, "%s:%d: %s matches %#q (but should not)\n\t%s\n", chk.file, chk.line, what, chk.want, indent(value))
			}
		case "contains":
			if !strings.Contains(value, chk.want) {
				fmt.Fprintf(&msg, "%s:%d: %s does not contain %#q (but should)\n\t%s\n", chk.file, chk.line, what, chk.want, indent(value))
			}
		case "!contains":
			if strings.Contains(value, chk.want) {
				fmt.Fprintf(&msg, "%s:%d: %s contains %#q (but should not)\n\t%s\n", chk.file, chk.line, what, chk.want, indent(value))
			}
		}
	}
	if msg.Len() > 0 && c.hint != "" {
		fmt.Fprintf(&msg, "hint: %s\n", indent(c.hint))
	}

	if msg.Len() > 0 {
		return fmt.Errorf("%s:%d: %s %s\n%s", c.file, c.line, c.method, c.url, msg.String())
	}
	return nil
}

// trim returns a trimming of s, in which all runs of spaces and tabs have
// been collapsed to a single space, leading and trailing spaces have been
// removed from each line, and blank lines are removed entirely.
func trim(s string) string {
	s = regexp.MustCompile(`[ \t]+`).ReplaceAllString(s, " ")
	s = regexp.MustCompile(`(?m)(^ | $)`).ReplaceAllString(s, "")
	s = strings.TrimLeft(s, "\n")
	s = regexp.MustCompile(`\n\n+`).ReplaceAllString(s, "\n")
	return s
}

// indent indents text for formatting in a message.
func indent(text string) string {
	if text == "" {
		return "(empty)"
	}
	if text == "\n" {
		return "(blank line)"
	}
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return "(blank lines)"
	}
	text = strings.ReplaceAll(text, "\n", "\n\t")
	return text
}
