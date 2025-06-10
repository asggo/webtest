package webtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// CheckHandlerE2E is like CheckHandler, but the handler is served by a test
// server and the request is executed by an HTTP client. If client is nil,
// http.DefaultClient is used.
func CheckHandlerE2E(fsys fs.FS, glob string, h http.Handler, client *http.Client) error {
	srv := httptest.NewServer(h)
	defer srv.Close()

	if client == nil {
		client = http.DefaultClient
	}
	return check(fsys, glob, func(c *case_) error { return c.runHandlerE2E(client, srv.URL) })
}

func check(fsys fs.FS, glob string, do func(*case_) error) error {
	files, err := fs.Glob(fsys, glob)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no files match %#q", glob)
	}
	var buf bytes.Buffer
	for _, file := range files {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			fmt.Fprintf(&buf, "# %s\n%v\n", file, err)
			continue
		}
		script, err := parseScript(file, string(data))
		if err != nil {
			fmt.Fprintf(&buf, "# %s\n%v\n", file, err)
			continue
		}
		hdr := false
		for _, c := range script.cases {
			if err := do(c); err != nil {
				if !hdr {
					fmt.Fprintf(&buf, "# %s\n", file)
					hdr = true
				}
				fmt.Fprintf(&buf, "## %s %s\n", c.method, c.url)
				fmt.Fprintf(&buf, "%v\n", err)
			}
		}
	}
	if buf.Len() > 0 {
		return errors.New(buf.String())
	}
	return nil
}

// A script is a parsed test script.
type script struct {
	cases []*case_
}

// A case_ is a single test case (GET/HEAD/POST/PUT/PATCH/DELETE) in a script.
type case_ struct {
	file      string
	line      int
	method    string
	url       string
	headers   [][2]string
	cookies   [][2]string
	postbody  string
	postquery string
	posttype  string
	hint      string
	checks    []*cmpCheck
}

// A cmp is a single comparison (check) made against a test case.
type cmpCheck struct {
	file     string
	line     int
	what     string
	whatArg  string
	op       string
	want     string
	wantRE   *regexp.Regexp
	wantJSON string // after unmarshal+re-marshal, so it is standardized
}

// runHandlerE2E runs a test case against the test server's base URL using
// the provided HTTP client.
func (c *case_) runHandlerE2E(client *http.Client, baseURL string) error {
	baseu, err := url.Parse(baseURL)
	if err != nil {
		return err
	}
	// the case url may have a scheme and host, if so we have to replace it
	// with the test server's.
	caseu, err := url.Parse(c.url)
	if err != nil {
		return err
	}
	caseu.Host = baseu.Host
	caseu.Scheme = baseu.Scheme

	req, err := c.newRequest(caseu.String())
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return c.check(resp, string(body))
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
		case "json", "!json":
			var v any
			if err := json.Unmarshal([]byte(value), &v); err != nil {
				fmt.Fprintf(&msg, "%s:%d: invalid JSON value: %s\n\t%s\n", chk.file, chk.line, err, value)
			}
			b, err := json.Marshal(v)
			if err != nil {
				fmt.Fprintf(&msg, "%s:%d: invalid JSON value: %s\n\t%s\n", chk.file, chk.line, err, value)
			}
			gotJSON := string(b)

			if chk.op == "json" {
				if gotJSON != chk.wantJSON {
					fmt.Fprintf(&msg, "%s:%d: %s json:\n\t%s\ndoes not match (but should):\n\t%s\n", chk.file, chk.line, what, value, chk.wantJSON)
				}
			} else {
				if gotJSON == chk.wantJSON {
					fmt.Fprintf(&msg, "%s:%d: %s json:\n\t%s\nmatches (but should not):\n\t%s\n", chk.file, chk.line, what, value, chk.wantJSON)
				}
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

// parseScript parses the test script in text.
// Errors are reported as being from file, but file is not directly read.
func parseScript(file, text string) (*script, error) {
	var current struct {
		Case      *case_
		Multiline *string
	}
	script := new(script)
	lastLineWasBlank := true
	lineno := 0
	line := ""
	errorf := func(format string, args ...interface{}) error {
		if line != "" {
			line = "\n" + line
		}
		return fmt.Errorf("%s:%d: %v%s", file, lineno, fmt.Sprintf(format, args...), line)
	}
	for text != "" {
		lineno++
		prevLine := line
		line, text, _ = cut(text, "\n")
		if strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimRight(line, " \t")
		if line == "" {
			lastLineWasBlank = true
			continue
		}
		what, args := splitOneField(line)

		// Add indented line to current multiline check, or else it ends.
		if what == "" {
			// Line is indented.
			if current.Multiline != nil {
				lastLineWasBlank = false
				*current.Multiline += args + "\n"
				continue
			}
			return nil, errorf("unexpected indented line")
		}

		// Multiline text is over; must be present.
		if current.Multiline != nil && *current.Multiline == "" {
			lineno--
			line = prevLine
			return nil, errorf("missing multiline text")
		}
		current.Multiline = nil

		// Look for start of new check.
		switch what {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
			if !lastLineWasBlank {
				return nil, errorf("missing blank line before start of case")
			}
			if args == "" {
				return nil, errorf("missing %s URL", what)
			}
			cas := &case_{method: what, url: args, file: file, line: lineno}
			script.cases = append(script.cases, cas)
			current.Case = cas
			lastLineWasBlank = false
			continue
		}

		if lastLineWasBlank || current.Case == nil {
			return nil, errorf("missing GET/HEAD/POST/PUT/PATCH/DELETE at start of check")
		}

		if what == "reqheader" {
			k, v := splitOneField(args)
			current.Case.headers = append(current.Case.headers, [2]string{k, v})
			continue
		}
		if what == "reqcookie" {
			k, v := splitOneField(args)
			current.Case.cookies = append(current.Case.cookies, [2]string{k, v})
			continue
		}

		// Look for case metadata.
		var targ *string
		switch what {
		case "postbody":
			targ = &current.Case.postbody
		case "postquery":
			targ = &current.Case.postquery
		case "posttype":
			targ = &current.Case.posttype
		case "hint":
			targ = &current.Case.hint
		}
		if targ != nil {
			if strings.HasPrefix(what, "post") && current.Case.method != "POST" &&
				current.Case.method != "PUT" && current.Case.method != "PATCH" && current.Case.method != "DELETE" {
				return nil, errorf("need POST/PUT/PATCH/DELETE (not %v) for %v", current.Case.method, what)
			}
			if args != "" {
				*targ = args
			} else {
				current.Multiline = targ
			}
			continue
		}

		// Start a comparison check.
		chk := &cmpCheck{file: file, line: lineno, what: what}
		current.Case.checks = append(current.Case.checks, chk)
		switch what {
		case "body", "code", "redirect":
			// no WhatArg
		case "header", "cookie", "rawcookie":
			chk.whatArg, args = splitOneField(args)
			if chk.whatArg == "" {
				return nil, errorf("missing %s name", what)
			}
		}

		// Opcode, with optional leading "not"
		chk.op, args = splitOneField(args)
		switch chk.op {
		case "==", "!=", "~", "!~", "contains", "!contains", "json", "!json":
			// ok
		default:
			return nil, errorf("unknown check operator %q", chk.op)
		}

		if args != "" {
			chk.want = args
		} else {
			current.Multiline = &chk.want
		}
	}

	// Finish each case.
	// Compute body from POST/PUT/PATCH/DELETE query.
	// Check that each regexp compiles, and insert "code equals 200"
	// in each case that doesn't already have a code check.
	for _, cas := range script.cases {
		if cas.postquery != "" {
			if cas.postbody != "" {
				line = ""
				lineno = cas.line
				return nil, errorf("case has postbody and postquery")
			}
			for _, kv := range strings.Split(cas.postquery, "\n") {
				kv = strings.TrimSpace(kv)
				if kv == "" {
					continue
				}
				k, v, ok := cut(kv, "=")
				if !ok {
					lineno = cas.line // close enough
					line = kv
					return nil, errorf("postquery has non key=value line")
				}
				if cas.postbody != "" {
					cas.postbody += "&"
				}
				cas.postbody += url.QueryEscape(k) + "=" + url.QueryEscape(v)
			}
		}
		sawCode := false
		for _, chk := range cas.checks {
			if chk.what == "code" || chk.what == "redirect" {
				sawCode = true
			}
			if chk.op == "~" || chk.op == "!~" {
				re, err := regexp.Compile(`(?m)` + chk.want)
				if err != nil {
					lineno = chk.line
					line = chk.want
					return nil, errorf("invalid regexp: %s", err)
				}
				chk.wantRE = re
			} else if chk.op == "json" || chk.op == "!json" {
				var v any
				if err := json.Unmarshal([]byte(chk.want), &v); err != nil {
					lineno = chk.line
					line = chk.want
					return nil, errorf("invalid json: %s", err)
				}
				b, err := json.Marshal(v)
				if err != nil {
					lineno = chk.line
					line = chk.want
					return nil, errorf("invalid json: %s", err)
				}
				chk.wantJSON = string(b)
			}
		}
		if !sawCode {
			line := cas.line
			if len(cas.checks) > 0 {
				line = cas.checks[0].line
			}
			chk := &cmpCheck{file: cas.file, line: line, what: "code", op: "==", want: "200"}
			cas.checks = append(cas.checks, chk)
		}
	}
	return script, nil
}

// cut returns the result of cutting s around the first instance of sep.
func cut(s, sep string) (before, after string, ok bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// splitOneField splits text at the first space or tab
// and returns that first field and the remaining text.
func splitOneField(text string) (field, rest string) {
	i := strings.IndexAny(text, " \t")
	if i < 0 {
		return text, ""
	}
	return text[:i], strings.TrimLeft(text[i:], " \t")
}