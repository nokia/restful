// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestServerHandler(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/path", func(ctx context.Context) {
		assert.True(trace.SpanContextFromContext(ctx).HasSpanID())
		assert.True(trace.SpanContextFromContext(ctx).HasTraceID())
	})
	s := NewServer().Addr(":56789").Handler(r)
	go s.ListenAndServe()
	time.Sleep(time.Second)

	{
		resp, _ := http.Get("http://127.0.0.1:56789/path")
		assert.Equal(204, resp.StatusCode)
	}
}
