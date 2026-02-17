// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package lambda

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type testFakeWriter struct {
	header http.Header
}

func newTestFakeWriter() *testFakeWriter {
	var w testFakeWriter
	w.header = make(http.Header)
	return &w
}

func (w *testFakeWriter) Write(bytes []byte) (int, error) {
	return len(bytes), nil
}

func (w *testFakeWriter) WriteHeader(statusCode int) {
}

func (w *testFakeWriter) Header() http.Header {
	return w.header
}

// NewTestCtx helps creating tests. Caller can define headers and path variables.
func NewTestCtx(method string, rawurl string, header http.Header, vars map[string]string) context.Context {
	var r http.Request
	r.Method = method
	r.Header = header
	r.URL, _ = url.Parse(rawurl)
	return context.WithValue(context.Background(), ctxName, newLambda(newTestFakeWriter(), &r, vars))
}

// ResponseHeader return response header map to be sent.
// Usually used on testing.
func (l *Lambda) ResponseHeader() http.Header {
	return l.w.Header()
}

func TestRequestBodyQueryParameter_FormURLEncoded(t *testing.T) {
	body := "foo=bar&num=123&multi=a&multi=b"

	req, err := http.NewRequest(http.MethodPost, "http://example.com/test", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header = make(http.Header)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	l := newLambda(newTestFakeWriter(), req, nil)
	values := l.RequestBodyQueryParameter()
	if values == nil {
		t.Fatalf("expected non-nil values")
	}

	if got := values.Get("foo"); got != "bar" {
		t.Fatalf("foo: got %q, want %q", got, "bar")
	}
	if got := values.Get("num"); got != "123" {
		t.Fatalf("num: got %q, want %q", got, "123")
	}

	multi := values["multi"]
	if len(multi) != 2 || multi[0] != "a" || multi[1] != "b" {
		t.Fatalf("multi: got %#v, want []string{\"a\",\"b\"}", multi)
	}
}
