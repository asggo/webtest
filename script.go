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
	var data      strings.Builder
	var test      *testCase
	var lineNum   int

	scan := bufio.NewReader(data)

	// Parse each line in our test case. Lines that begin with a `\t` are part
	// of the data for the most recently parsed line.
	for {
		lineNum += 1

		// Read one line from the file and process it.
		line, err := scan.ReadString("\n")
		if err != nil {
			return fmt.Errorf("could not script.load: line %d: %v", lineNum, err)
		}

		// Skip lines that start with #, these are comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// If we reach a new line and test is not nil we have reached the end
		// of a test case and need to add the completed test to the script.
		if line == "\n" {
			if test != nil {
				s.tests = append(s.tests, test)
			}

			test = nil
			continue
		}

		fields := string.Fields(line)

		cmd, fields := pop(fields)
		loc, fields := pop(fields)
		data = string.join(fields, " ")

		switch cmd {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
			test = &testCase{method: cmd, url: loc}
		case "modify":
			if loc == "body" {
				for {
					c, err := scan.Peek(1)
					if err != nil {
						return fmt.Errorf("could not script.load: line %d: %v", lineNum, err)
					}

					if c == "\t" {
						line := scan.ReadString("\n")
						data += strings.TrimPrefix(line, "\t")
					} else {
						break
					}
				}
			}

			err = test.addModifier(loc, data)
			if err != nil {
				return fmt.Errorf("could not script.load: line %d: %v", lineNum, err)
			}
		case "extract":
			err = test.addExtractor(loc, data)
			if err != nil {
				return fmt.Errorf("could not script.load: line %d: %v", lineNum, err)
			}
		case "compare":
			err = test.addComparison(loc, data)
			if err != nil {
				return fmt.Errorf("could not script.load: line %d: %v", lineNum, err)
			}
		default:
			return fmt.Errorf("could not script.load: line %d: unexpected cmd %s", lineNum, cmd)
		}
	}
}

func pop(fields []string) string {
	switch len(fields) {
	case 0:
		return "", []
	case 1:
		return fields[0], []
	default:
		return fields[0], fields[1:]
	}
}

func newScript(filename string) (script, error) {
	var s script

	data, err := os.Open(file)
	if err != nil {
		return s, fmt.Errorf("could not newScript: %v", err)
	}

	err := s.load(data)
	if err != nil {
		return s, fmt.Errorf("could not newScript: %v", err)
	}

	s.filename = filename

	return s, nil
}
