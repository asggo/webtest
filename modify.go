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

// A modifier represents a single request modification. The what field is used
// to identify what part of the request to modify. The valid options for the
// what field are: reqheader, reqcookie, postbody, and posttype. When what is
// either reqheader or reqcookie, the name parameter is required to identify
// which header or cookie should be set. 
type modifier struct {
	what  string
	name  string
	value string
}

// newModifier attempts to build a valid modifier based on the given cmd and
// data parameters. An error is returned if a valid modifier cannot be
// created.
func newModifier(what, data string) (*modifier, error) {
	fields = strings.Fields(data)

	switch what {
	case "cookie":
		if len(fields) != 2 {
			return nil, fmt.Errorf("could not newModifier: expected `cookie name value`")
		}

		return &modifier{what: what, name: fields[0], value: fields[1]}, nil
	case "header":
		if len(fields) != 2 {
			return nil, fmt.Errorf("could not newModifier: expected `header name value`")
		}

		return &modifier{what: what, name: fields[0], value: fields[1]}, nil
	case "body":
		if data == "" {
			return nil, fmt.Errorf("could not newModifier: expected `body data`")
		}
		return &modifier{what: what, value: data}, nil
	case "type":
		if len(fields) != 1 {
			return nil, fmt.Errorf("could not newModifier: expected `type content-type")
		}

		return &modifier{what: what, value: fields[0]}, nil
	default:
		return nil, fmt.Errorf("could not newModifier: %s is not a valid modifier", what)
	}
}

// modify updates an http.Request based on the criteria of the modifier.
func (m *modifier) modify(req *http.Request) {
	switch m.what {
	case "header":
		req.Header.Set(m.name, m.value)
	case "cookie":
		req.AddCookie(&http.Cookie{Name: m.name, Value: m.value})
	case "body":
		req.Body = strings.NewReader(m.value)
	case "type":
		req.Header.Set("Content-Type", m.value)
	default:
	}
}