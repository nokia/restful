// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/url"
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
