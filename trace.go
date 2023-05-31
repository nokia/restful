// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"

	"github.com/nokia/restful/trace/tracedata"
	"github.com/nokia/restful/trace/tracer"
)

var isTraced bool = true

// SetTrace can enable/disable tracing in restful. By default tracing is enabled
func SetTrace(b bool) {
	isTraced = b
}

// newTraceFromCtx creates new trace object, preferably from context. Never returns nil.
func newTraceFromCtx(ctx context.Context) tracedata.TraceData {
	l := L(ctx)
	if l == nil {
		return tracer.NewRandom()
	}

	if l.trace == nil {
		l.trace = tracer.NewRandom() // Updates trace in ctx via l.trace pointer.
	}

	return l.trace
}
