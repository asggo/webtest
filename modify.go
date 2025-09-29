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
func newModifier(cmd, data string) (*modifier, error) {
	fields = strings.Fields(data)

	switch cmd {
	case "reqcookie":
		if len(fields) != 2 {
			return nil, fmt.Errorf("could not newModifier: expected `cookie name value`")
		}

		return &modifier{what: cmd, name: fields[0], value: fields[1]}, nil
	case "reqheader":
		if len(fields) != 2 {
			return nil, fmt.Errorf("could not newModifier: expected `header name value`")
		}

		return &modifier{what: cmd, name: fields[0], value: fields[1]}, nil

	case "postbody":
		if data == "" {
			return nil, fmt.Errorf("could not newModifier: expected `postbody data`")
		}
		return &modifier{what: cmd, value: data}, nil

	case "posttype":
		if len(fields) != 1 {
			return nil, fmt.Errorf("could not newModifier: expected `posttype content-type")
		}

		return &modifier{what: cmd, value: fields[0]}, nil
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
	case "postbody":
		req.Body = strings.NewReader(m.value)
	case "posttype":
		req.Header.Set("Content-Type", m.value)
	default:
	}
}