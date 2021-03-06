// Copyright 2021 Nokia
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
	assert.NotContains(trace.string(), "00-0af7651916cd43dd8448eb211c80319c-")
	span := trace.span().string()
	assert.Equal(55, len(span))
}

func TestTracePropagation(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.TraceLevel) // That switches on trace propagation

	// Server
	srvURL := ""
	traceid := ""
	prevSpanID := ""
	parents := make(map[string]bool)
	depth := int64(0)
	const maxDepth = 5
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewRequestCtx(w, r)
		t := newTraceFromCtx(ctx)
		assert.True(t.received)
		if depth == 0 {
			traceid = t.parent.parent[1]
			prevSpanID = t.parent.parent[2]
			parents[t.string()] = true
			t.b3.sampled = "1"
			t.b3.requestID = "req"
			t.b3.spanCtx = "ctx"
		} else {
			assert.Equal(traceid, t.parent.parent[1])
			assert.NotContains(parents, t.string())
			assert.Equal(t.parent.parent[1], t.b3.traceID)
			assert.Equal(t.parent.parent[2], t.b3.spanID)
			assert.Equal(prevSpanID, t.b3.parentSpanID)
			assert.Equal("1", t.b3.sampled)
			assert.Equal("req", t.b3.requestID)
			assert.Equal("ctx", t.b3.spanCtx)
			prevSpanID = t.parent.parent[2]
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
