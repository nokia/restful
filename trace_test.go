// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTracePropagation(t *testing.T) {
	assert := assert.New(t)

	// Server
	srvURL := ""
	traceID := ""
	prevSpanID := ""
	parents := make(map[string]bool)
	depth := 0
	const maxDepth = 5
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewRequestCtx(w, r)
		t := newTraceFromCtx(ctx)
		assert.True(t.IsReceived())
		if depth == 0 {
			traceID = t.TraceID()
			prevSpanID = t.SpanID()
			parents[t.String()] = true
		} else {
			assert.Equal(traceID, t.TraceID())
			assert.Equal(traceID, L(ctx).TraceID())
			assert.NotContains(parents, t.String())
			assert.NotEqual(prevSpanID, t.SpanID())
			prevSpanID = t.SpanID()
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
}
