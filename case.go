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

type testLine struct {
	line int
	cmd  string
	data string
}

// A testCase is a single test case (GET/HEAD/POST/PUT/PATCH/DELETE) in a script.
type testCase struct {
	lineNum   int
	method    string
	url       string
	modifiers []*modifier
	checks    []*check
	extracts  []*extract
}

func (t *testCase) load(data string) error {
	var data      strings.Builder
	var testLines []testLine

	scan := bufio.NewReader(data)
	ln := t.lineNum

	// Parse each line in our test case. Lines that begin with a `\t` are part
	// of the data for the most recently parsed line.
	for {
		line, err := scan.ReadString("\n")
		if err != nil {
			return fmt.Errorf("could not test.load: unexpected error %v at line %d", err, t.lineNum)
		}

		ln = ln + 1

		switch {
		case strings.HasPrefix(line, "\t"):
			if len(testLines) == 0 {
				return fmt.Errorf("could not test.load: unexpected \\t at line %d", ln)
			}

			testLines[len(testLines)-1].value += strings.TrimPrefix(line, "\t")
		default:
			cmd := string.Fields(line)[0]
			data := strings.TrimPrefix(line, cmd)
			testLines = append(testLines, testLine{line: ln, cmd: cmd, data: data})
		}
	}

	// Process our parsed lines to build a test case.
	for tl := range testLines {
		switch tl.cmd {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
			t.method = tl.cmd
			t.url = tl.data
			t.lineNum = tl.line
		case "reqheader", "reqcookie", "posttype", "postbody":
			m, err = newModifier(tl.cmd, tl.data)
			if err != nil {
				return fmt.Errorf("could not test.load: %v", err)
			}

			t.modifiers = append(t.modifiers, m)
		case "extheader", "extcookie", "extbody":
			e, err = newExtractor(tl.cmd, tl.data)
			if err != nil {
				return fmt.Errorf("could not test.load: %v", err)
			}
		}
	}
}

func newTest(lineNum int) test {
	return test{lineNum: lineNum}
}


// runHandler runs a test case against the handler h.
func (c *case_) runHandler(base *url.URL, client *http.Client, h http.Handler) error {
	url := fmt.Sprintf("%s%s", base, c.url)
	r, err := c.newRequest(url)
	if err != nil {
		return err
	}

	for _, cookie := range client.Jar.Cookies(base) {
		r.AddCookie(cookie)
	}

	res, err := client.Do(r)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}

	return c.check(res, string(body))
}

// newRequest creates a new request for the case c,
// using the URL u.
func (c *case_) newRequest(u string) (*http.Request, error) {
	body := c.requestBody()
	r, err := http.NewRequest(c.method, u, body)
	if err != nil {
		return nil, err
	}
	typ := c.posttype
	if body != nil && typ == "" {
		typ = "application/x-www-form-urlencoded"
	}
	if typ != "" {
		r.Header.Set("Content-Type", typ)
	}
	for _, kv := range c.headers {
		r.Header.Set(kv[0], kv[1])
	}
	for _, kv := range c.cookies {
		r.AddCookie(&http.Cookie{Name: kv[0], Value: kv[1]})
	}
	return r, nil
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
