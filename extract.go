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

// extracted represents a piece of data extracted by an extractor.
type extracted struct {
	name string
	value string
}

// An extractor represents a single piece of data to extract from a response.
// The from field is used to identify where in the response the extracted
// data can be found. The valid options for the from field are: extheader,
// extcookie, and extbody. When from is either extcookie or extheader the name
// parameter is required to identify which header or cookie the data resides
// in. The into field defines the name by which the extracted data can be
// referenced in subsequent requests.  
type extractor struct {
	from string
	into string
	name string
	expr *regexp.Regexp
}

// newExtractor attempts to build a valid extractor based on the given data
// and value parameters. An error is returned if a valid extractor cannot be
// created.
func newExtractor(cmd, data string) (*extractor, error) {
	fields = strings.Fields(data)

	switch cmd {
	case "extheader":
		if len(fields) < 3 {
			return nil, fmt.Errorf("could not newExtractor: expected `extheader varname header regex`")
		}

		exprStr := strings.Join(fields[:2], " ")
		expr, err := regexp.Compile(fmt.Sprintf("(?m)%s", exprStr))
		if err != nil {
			return nil, fmt.Errorf("could not newExtractor: %v", err)
		}

		return &extractor{from: cmd, into: fields[0], name: fields[1], expr: expr}, nil

	case "extcookie":
		if len(fields) < 3 {
			return nil, fmt.Errorf("could not newExtractor: expected `extcookie varname header regex`")
		}

		exprStr := strings.Join(fields[:2], " ")
		expr, err := regexp.Compile(fmt.Sprintf("(?m)%s", exprStr))
		if err != nil {
			return nil, fmt.Errorf("could not newExtractor: %v", err)
		}

		return &extractor{from: cmd, into: fields[0], name: fields[1], expr: expr}, nil

	case "extbody":
		if len(fields) < 2 {
			return nil, fmt.Errorf("could not newExtractor: expected `extbody varname regex`")
		}

		exprStr := strings.Join(fields[:1], " ")
		expr, err := regexp.Compile(fmt.Sprintf("(?m)%s", exprStr))
		if err != nil {
			return nil, fmt.Errorf("could not newExtractor: %v", err)
		}

		return &extractor{from: cmd, into: fields[0], expr: expr}, nil

	default:
		return nil, fmt.Errorf("could not newExtractor: %s is not a valid value", cmd)
	}
}

// extract finds and returns data from an http.Response based on the criteria
// of the extractor. It returns the na
func (e *extractor) extract(rsp *http.Response, body string) extracted {
	var data string

	switch e.from {
	case "header":
		data = resp.Header.Get(e.name)
	case "cookie":
		for _, c := range resp.Cookies() {
			if c.Name == e.name {
				data = c.String()
				break
			}
		}
	default:
		data = body
	}

	value = e.expr.MatchString(data)

	return extracted{name: e.into, value: value}
}