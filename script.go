// This package is a modified version of the webtest package available at
// https://github.com/cespare/webtest, and is under the same license as the
// original package. This version has a reusable http.Client that allows the
// tested handler to set and remove secure cookies as needed.

package webtest

import (
	"fmt"
	"io/ioutil"
	"os"
	"bufio"
	"net/url"
	"regexp"
	"strings"
)

// A script is a parsed test script.
type script struct {
	filename string
	tests []*test
}

// load parses and loads test cases from the given Reader.
func (s *script) load(data *io.Reader) error {
	var s   script
	var buf strings.Builder

	s.filename = filename
	scan := bufio.NewScanner(data)
	lineNum := 0

	for scan.Scan() {
		line := scan.Text()
		lineNum += 1

		if line == "" or strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "GET") {
			buf.WriteString(fmt.Sprintf("%s\n", line))
			
			for {
				next := scan.Text()
				if next == "" {
					break
				} else {
					buf.WriteString(fmt.Sprintf("%s\n", next))
				}
			}

			t := newTest(lineNum)
			err := t.load(buf.String())
			if err != nil {
				return fmt.Errorf("could not script.load for %s: %v", filename, err)
			}

			s.tests = append(s.tests, t)
			buf.Reset()
		}
	}

	return s, nil
}

func newScript(filename string) script {
	return script{filename: filename}
}

// // parseScript parses the test script in text.
// // Errors are reported as being from file, but file is not directly read.
// func parseScript(file, text string) (*script, error) {
// 	var current struct {
// 		Case      *case_
// 		Multiline *string
// 	}
// 	script := new(script)
// 	lastLineWasBlank := true
// 	lineno := 0
// 	line := ""
// 	errorf := func(format string, args ...interface{}) error {
// 		if line != "" {
// 			line = "\n" + line
// 		}
// 		return fmt.Errorf("%s:%d: %v%s", file, lineno, fmt.Sprintf(format, args...), line)
// 	}

// 	for text != "" {
// 		lineno++
// 		prevLine := line
// 		line, text, _ = cut(text, "\n")
// 		if strings.HasPrefix(line, "#") {
// 			continue
// 		}
// 		line = strings.TrimRight(line, " \t")
// 		if line == "" {
// 			lastLineWasBlank = true
// 			continue
// 		}
// 		what, args := splitOneField(line)

// 		// Add indented line to current multiline check, or else it ends.
// 		if what == "" {
// 			// Line is indented.
// 			if current.Multiline != nil {
// 				lastLineWasBlank = false
// 				*current.Multiline += args + "\n"
// 				continue
// 			}
// 			return nil, errorf("unexpected indented line")
// 		}

// 		// Multiline text is over; must be present.
// 		if current.Multiline != nil && *current.Multiline == "" {
// 			lineno--
// 			line = prevLine
// 			return nil, errorf("missing multiline text")
// 		}
// 		current.Multiline = nil

// 		// Look for start of new check.
// 		switch what {
// 		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
// 			if !lastLineWasBlank {
// 				return nil, errorf("missing blank line before start of case")
// 			}
// 			if args == "" {
// 				return nil, errorf("missing %s URL", what)
// 			}
// 			cas := &case_{method: what, url: args, file: file, line: lineno}
// 			script.cases = append(script.cases, cas)
// 			current.Case = cas
// 			lastLineWasBlank = false
// 			continue
// 		}

// 		if lastLineWasBlank || current.Case == nil {
// 			return nil, errorf("missing GET/HEAD/POST/PUT/PATCH/DELETE at start of check")
// 		}

// 		if what == "reqheader" {
// 			k, v := splitOneField(args)
// 			current.Case.headers = append(current.Case.headers, [2]string{k, v})
// 			continue
// 		}
// 		if what == "reqcookie" {
// 			k, v := splitOneField(args)
// 			current.Case.cookies = append(current.Case.cookies, [2]string{k, v})
// 			continue
// 		}

// 		// Look for case metadata.
// 		var targ *string
// 		switch what {
// 		case "postbody":
// 			targ = &current.Case.postbody
// 		case "postquery":
// 			targ = &current.Case.postquery
// 		case "posttype":
// 			targ = &current.Case.posttype
// 		case "hint":
// 			targ = &current.Case.hint
// 		}
// 		if targ != nil {
// 			if strings.HasPrefix(what, "post") && current.Case.method != "POST" &&
// 				current.Case.method != "PUT" && current.Case.method != "PATCH" && current.Case.method != "DELETE" {
// 				return nil, errorf("need POST/PUT/PATCH/DELETE (not %v) for %v", current.Case.method, what)
// 			}
// 			if args != "" {
// 				*targ = args
// 			} else {
// 				current.Multiline = targ
// 			}
// 			continue
// 		}

// 		// Start a comparison check.
// 		chk := &cmpCheck{file: file, line: lineno, what: what}
// 		current.Case.checks = append(current.Case.checks, chk)
// 		switch what {
// 		case "body", "code", "redirect":
// 			// no WhatArg
// 		case "header", "cookie", "rawcookie":
// 			chk.whatArg, args = splitOneField(args)
// 			if chk.whatArg == "" {
// 				return nil, errorf("missing %s name", what)
// 			}
// 		}

// 		// Opcode, with optional leading "not"
// 		chk.op, args = splitOneField(args)
// 		switch chk.op {
// 		case "==", "!=", "~", "!~", "contains", "!contains":
// 			// ok
// 		default:
// 			return nil, errorf("unknown check operator %q", chk.op)
// 		}

// 		if args != "" {
// 			chk.want = args
// 		} else {
// 			current.Multiline = &chk.want
// 		}
// 	}

// 	// Finish each case.
// 	// Compute body from POST/PUT/PATCH/DELETE query.
// 	// Check that each regexp compiles, and insert "code equals 200"
// 	// in each case that doesn't already have a code check.
// 	for _, cas := range script.cases {
// 		if cas.postquery != "" {
// 			if cas.postbody != "" {
// 				line = ""
// 				lineno = cas.line
// 				return nil, errorf("case has postbody and postquery")
// 			}
// 			for _, kv := range strings.Split(cas.postquery, "\n") {
// 				kv = strings.TrimSpace(kv)
// 				if kv == "" {
// 					continue
// 				}
// 				k, v, ok := cut(kv, "=")
// 				if !ok {
// 					lineno = cas.line // close enough
// 					line = kv
// 					return nil, errorf("postquery has non key=value line")
// 				}
// 				if cas.postbody != "" {
// 					cas.postbody += "&"
// 				}
// 				cas.postbody += url.QueryEscape(k) + "=" + url.QueryEscape(v)
// 			}
// 		}
// 		sawCode := false
// 		for _, chk := range cas.checks {
// 			if chk.what == "code" || chk.what == "redirect" {
// 				sawCode = true
// 			}
// 			if chk.op == "~" || chk.op == "!~" {
// 				re, err := regexp.Compile(`(?m)` + chk.want)
// 				if err != nil {
// 					lineno = chk.line
// 					line = chk.want
// 					return nil, errorf("invalid regexp: %s", err)
// 				}
// 				chk.wantRE = re
// 			}
// 		}
// 		if !sawCode {
// 			line := cas.line
// 			if len(cas.checks) > 0 {
// 				line = cas.checks[0].line
// 			}
// 			chk := &cmpCheck{file: cas.file, line: line, what: "code", op: "==", want: "200"}
// 			cas.checks = append(cas.checks, chk)
// 		}
// 	}
// 	return script, nil
// }

// // cut returns the result of cutting s around the first instance of sep.
// func cut(s, sep string) (before, after string, ok bool) {
// 	if i := strings.Index(s, sep); i >= 0 {
// 		return s[:i], s[i+len(sep):], true
// 	}
// 	return s, "", false
// }

// // splitOneField splits text at the first space or tab
// // and returns that first field and the remaining text.
// func splitOneField(text string) (field, rest string) {
// 	i := strings.IndexAny(text, " \t")
// 	if i < 0 {
// 		return text, ""
// 	}
// 	return text[:i], strings.TrimLeft(text[i:], " \t")
// }
