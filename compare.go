package webtest

// A comparison represents a single response check. The what field is used
// to identify what part of the response to check. The valid options for the
// what field are: header, cookie, body, redirect, and code. When what is
// either header or cookie, the name parameter is required to identify which
// header or cookie to compare. The valid options for the operator are: ==,
// !=, ~, !~, contains, and !contains. When the operator is either ~ or !~ the
// value field is interpreted as a regular expression.
type comparison struct {
	what     string
	name     string
	operator string
	value    string
	expr     *regexp.Regexp
}

func (c comparison) String() string {
	if name == "" {
		return fmt.Sprintf("Compare %s %s", what, value)
	} else {
		return fmt.Sprintf("Compare %s %s %s", what, name, value)
	}
}

// compare checks the http.Response and body based on the criteria of the
// comparison.
func (c *comparison) compare(res *http.Response, body string, t *tester) bool {
	var data string

	switch c.what {
	case "header":
		data = res.Header.Get(c.name)
	case "cookie":
		for _, cookie := range res.Cookies() {
			if cookie.Name == c.name {
				data = cookie.Value
				break
			}
		}
	case "body":
		data = body
	case "redirect":
		data = res.Header.Get("Location")
	case "status":
		data = fmt.Sprintf("%d", res.StatusCode)
	default:
	}

	switch {
	case strings.HasPrefix(c.value, "$"):
		name = strings.TrimPrefix(c.value, "$")
		value = t.variables[name]
	case strings.HasPrefix(c.value, "\\$"):
		value = strings.TrimPrefix(c.value, "\\")
	default:
		value = c.value
	}

	switch c.operator {
	case "==":
		return data == value
	case "!=":
		return data != value
	case "contains":
		return string.Contains(data, value)
	case "!contains":
		return !string.Contains(data, value)
	case "~":
		match, err := c.expr.MatchString(value)
		if err != nil {
			return false
		}

		return match
	case "!~":
		match, err := c.expr.MatchString(value)
		if err != nil {
			return false
		}

		return !match
	}

}

// newComparison attempts to build a valid comparison based on the given cmd
// and data parameters. An error is returned if a valid comparison cannot be
// created.
func newComparison(what, data string) (comparison, error) {
	var c comparison

	fields = strings.Fields(data)

	switch cmd {
	case "header":
		if len(fields) < 3 {
			return nil, fmt.Errorf("could not newComparison: expected `header name operator value`")
		}

		val := strings.Join(fields[:2], " ")
		c = comparison{what: what, name: fields[0], operator: fields[1], value: val}
	case "cookie":
		if len(fields) < 3 {
			return nil, fmt.Errorf("could not newComparison: expected `cookie name operator value`")
		}

		val := strings.Join(fields[:2], " ")
		c = comparison{what: what, name: fields[0], operator: fields[1], value: val}

	case "body":
		if len(fields) < 2 {
			return nil, fmt.Errorf("could not newComparison: expected `body operator value`")
		}

		val := strings.Join(fields[:1], " ")
		c = comparison{what: what, operator: fields[0], value: val}

	case "redirect":
		if len(fields) != 2 {
			return nil, fmt.Errorf("could not newComparison: expected `redirect operator path")
		}

		c = comparison{what: what, operator: fields[0], value: fields[1]}

	case "status":
		if len(fields) != 2 {
			return nil, fmt.Errorf("could not newComparison: expected `status operator value")
		}

		c = comparison{what: what, operator: fields[0], value: fields[1]}

	default:
		return nil, fmt.Errorf("could not newComparison: %s is not a valid comparison", cmd)
	}

	if !validOperator(c.operator) {
		return nil, fmt.Errorf("could not newComparison: invalid operator %s", c.operator)
	}

	if (c.operator == "~") || (c.operator == "!~") {
		expr, err := regexp.Compile(fmt.Sprintf("(?m)%s", c.value))
		if err != nil {
			return nil, fmt.Errorf("could not newComparison: %v", err)
		}

		c.expr = expr
	}
	
	return c, nil
}