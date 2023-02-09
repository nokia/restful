// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRecvdParent(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01")
	trace := newTrace(r)
	assert.True(trace.received)
	assert.Equal("00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01", trace.string())
	span := trace.span().string()
	assert.Contains(span, "00-0af7651916cd43dd8448eb211c80319c-")
	assert.Equal(55, len(span))
}

func TestFakeParent(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("x-fake-traceparent", "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01")
	trace := newTrace(r)
	assert.False(trace.received)
	assert.Equal("00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01", trace.string())
	span := trace.span().string()
	assert.Contains(span, "00-0af7651916cd43dd8448eb211c80319c-")
	assert.Equal(55, len(span))
}

func TestRecvdBadParent(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", "FF-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01")
	trace := newTrace(r)
	assert.False(trace.received)
	assert.NotContains(trace.string(), "-0af7651916cd43dd8448eb211c80319c-")
}

func TestNoTrace(t *testing.T) {
	assert := assert.New(t)
	traceParent := traceParent{}
	assert.Equal("", traceParent.traceID())
	assert.Equal("", traceParent.spanID())

	trace := trace{}
	assert.Equal("", trace.traceID())
	assert.Equal("", trace.spanID())
}

func TestB3SingleLine(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	traceStr := "0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-1-deadbeef87654321"
	r.Header.Set("b3", traceStr)
	trace := newTrace(r)
	assert.True(trace.received)
	assert.Contains(trace.string(), "0af7651916cd43dd8448eb211c80319c")
	headers := http.Header{}
	trace.setHeader(headers)
	assert.Equal(traceStr, headers.Get("b3"))
}

func TestTracePropagation(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.TraceLevel) // That switches on trace generation and propagation

	// Server
	srvURL := ""
	traceid := ""
	prevSpanID := ""
	parents := make(map[string]bool)
	depth := 0
	const maxDepth = 5
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewRequestCtx(w, r)
		t := newTraceFromCtx(ctx)
		assert.True(t.received)
		if depth == 0 {
			traceid = t.traceID()
			prevSpanID = t.spanID()
			parents[t.string()] = true
			t.b3.sampled = "1"
			t.b3.requestID = "req"
			t.b3.spanCtx = "ctx"
		} else {
			assert.Equal(traceid, t.parent.traceID())
			assert.NotContains(parents, t.string())
			assert.Equal(t.parent.traceID(), t.b3.traceID)
			assert.Equal(t.parent.spanID(), t.b3.spanID)
			assert.Equal(prevSpanID, t.b3.parentSpanID)
			assert.Equal("1", t.b3.sampled)
			assert.Equal("req", t.b3.requestID)
			assert.Equal("ctx", t.b3.spanCtx)
			prevSpanID = t.spanID()
		}
		if depth < maxDepth {
			depth++
			err := Get(ctx, srvURL, nil)
			assert.NoError(err)
		}
		SendEmptyResponse(w, 200)
	})))
	defer srv.Close()
	srvURL = srv.URL

	assert.NoError(Get(context.Background(), srv.URL, nil))
	log.SetLevel(log.InfoLevel)
}
