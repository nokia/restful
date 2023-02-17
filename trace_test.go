// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
)

func TestClient(t *testing.T) {
	assert := assert.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(r.Header.Get("X-B3-Traceid"))
		assert.NotEmpty(r.Header.Get("X-B3-Spanid"))
		assert.NotEmpty(r.Header.Get("X-B3-Sampled"))
		assert.NotEmpty(r.Header.Get("B3"))
		assert.NotEmpty(r.Header.Get("Traceparent"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL)
	client.Get(context.Background(), "", nil)
}

func TestHandler(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/path", func(ctx context.Context) {
		assert.True(trace.SpanContextFromContext(ctx).HasSpanID())
		assert.True(trace.SpanContextFromContext(ctx).HasTraceID())
	})

	req, _ := http.NewRequest(http.MethodGet, "/path", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(http.StatusNoContent, rr.Code)
}
