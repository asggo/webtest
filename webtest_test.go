// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package webtest

import (
	"fmt"
	"net/http"
	"testing"
)

func echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if h := r.Header.Get("Custom-Header"); h != "" {
		w.Header().Set("Custom-Header", h)
	}
	if ck, err := r.Cookie("custom-cookie"); err == nil {
		ck.Path = "/"
		ck.MaxAge = 30
		http.SetCookie(w, ck)
	}
	fmt.Fprintf(w, "%v %s\n", r.Method, r.URL)
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "parsing form: %v\n", err)
	}
	for k, v := range r.Form {
		fmt.Fprintf(w, "%q: %q\n", k, v)
	}
	if len(r.Form) == 0 {
		fmt.Fprintf(w, "no query\n")
	}
}

func TestEchoHandler(t *testing.T) {
	TestHandler(t, "testdata/echo.txt", http.HandlerFunc(echo))
}
