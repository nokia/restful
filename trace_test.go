// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func Test_Trace_ClientGenerates(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/DoesNotHaveTraceID", func(ctx context.Context) {
		spanCtx := trace.SpanContextFromContext(ctx)
		assert.True(spanCtx.HasSpanID())
		assert.True(spanCtx.HasTraceID())
	})
}

func Test_Trace_Propagate(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/HasTraceID", func(ctx context.Context) {
		_ = Get(ctx, "http://127.0.0.1:56789/HasTraceIDPropagated", nil)
	})
	r.HandleFunc("/HasTraceIDPropagated", func(ctx context.Context) {
		spanCtx := trace.SpanContextFromContext(ctx)
		assert.True(spanCtx.HasSpanID())
		assert.Equal("1234567890abcdef1234567890abcdef", spanCtx.TraceID().String())
		assert.True(spanCtx.IsSampled())
		assert.True(spanCtx.TraceFlags().IsSampled())

		b3 := strings.Split(L(ctx).RequestHeaderGet("B3"), "-")
		assert.Contains(b3[2], "d")
	})
	s := NewServer().Addr(":56789").Handler(r)
	go s.ListenAndServe()
	time.Sleep(time.Second)

	{ // B3, restful client
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:56789/HasTraceID", nil)
		req.Header.Set("B3", "1234567890abcdef1234567890abcdef-1234567890abcdef-d-fedcba0987654321")
		NewClient().Do(context.Background(), req)
	}

	{ // X-B3, http client
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:56789/HasTraceID", nil)
		req.Header.Set("X-B3-TraceId", "1234567890abcdef1234567890abcdef")
		req.Header.Set("X-B3-SpanId", "1234567890abcdef")
		req.Header.Set("X-B3-ParentId", "fedcba0987654321")
		req.Header.Set("X-B3-Flags", "1")
		http.DefaultClient.Do(req)
	}
}
