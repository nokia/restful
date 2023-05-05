// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"

	log "github.com/sirupsen/logrus"
)

var isTraced bool = true

// SetTrace can enable/disable tracing in restful. By default tracing is enabled
func SetTrace(b bool) {
	isTraced = b
}

type trace struct {
	parent   *traceParent
	b3       *traceB3
	received bool
}

// newTraceFromHeader creates new trace object. If no trace data, then create random. Never returns nil.
func newTraceFromHeader(r *http.Request) *trace {
	t := trace{parent: newTraceParent(r), b3: newTraceB3(r)}
	t.received = t.valid()

	if !t.received {
		return newTraceRandom()
	}

	return &t
}

func newTraceRandom() *trace {
	debug := log.IsLevelEnabled(log.TraceLevel)
	traceID := randStr32()
	return &trace{b3: newTraceB3WithID(traceID, debug)}
}

// newTraceFromCtx creates new trace object, preferably from context. Never returns nil.
func newTraceFromCtx(ctx context.Context) *trace {
	l := L(ctx)
	if l == nil {
		return newTraceRandom()
	}

	if !l.trace.valid() {
		l.trace = newTraceRandom() // Updates trace in ctx via l.trace pointer.
	}

	return l.trace
}

func (t *trace) valid() bool {
	return t.parent != nil || t.b3 != nil
}

func (t *trace) string() string {
	if t.b3 != nil {
		return t.b3.string()
	}
	if t.parent != nil {
		return t.parent.string()
	}
	return ""
}

func (t *trace) traceID() string {
	if t.b3 != nil {
		return t.b3.traceID
	}
	if t.parent != nil {
		return t.parent.traceID()
	}
	return ""
}

func (t *trace) spanID() string {
	if t.b3 != nil {
		return t.b3.spanID
	}
	if t.parent != nil {
		return t.parent.spanID()
	}
	return ""
}

func (t *trace) span() *trace {
	var newt trace
	spanID := randStr16()
	if t.parent != nil {
		newt.parent = t.parent.span(spanID)
	}
	if t.b3 != nil {
		newt.b3 = t.b3.span(spanID)
	}
	newt.received = t.received
	return &newt
}

func (t *trace) setHeader(headers http.Header) {
	if t.parent != nil {
		t.parent.setHeader(headers)
	}
	if t.b3 != nil {
		t.b3.setHeader(headers)
	}
}

func randStr16() string {
	return fmt.Sprintf("%016x", rand.Uint64()) // #nosec random is weak intentionally
}

func randStr32() string {
	return randStr16() + randStr16()
}

func setHeaderStr(headers http.Header, header, value string) {
	if value != "" {
		headers.Set(header, value)
	}
}
