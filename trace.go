// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type trace struct {
	parent   *traceParent
	b3       *traceB3
	received bool
}

// newTrace creates new trace object. Never returns nil.
func newTrace(r *http.Request) *trace {
	t := trace{parent: newTraceParent(r), b3: newTraceB3(r)}
	t.received = t.valid()

	if !t.received { // Create fake one. Saved to r (ctx.r), so that any client to be able to find it. Note: Logger may have created one already.
		t.parent = newTraceParentFromFake(r)
		if !t.valid() {
			return newTraceRandom()
		}
	}

	return &t
}

func newTraceRandom() *trace {
	if log.IsLevelEnabled(log.TraceLevel) {
		traceID := randStr32()
		return &trace{parent: newTraceParentWithID(traceID), b3: newTraceB3WithID(traceID, true)}
	}
	return &trace{b3: &traceB3{spanID: randStr16()}}
}

// newTraceFromCtx creates new trace object, preferably from context. Never returns nil.
func newTraceFromCtx(ctx context.Context) *trace {
	l := L(ctx)
	if l == nil || l.trace == nil {
		return newTraceRandom()
	}
	return l.trace
}

func (t *trace) valid() bool {
	return t.parent != nil || t.b3 != nil
}

func (t *trace) string() string {
	if t.parent != nil {
		return t.parent.string()
	}
	if t.b3 != nil {
		return t.b3.string()
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

func (t *trace) addHeader(headers http.Header) {
	if t.parent != nil {
		t.parent.addHeader(headers)
	}
	if t.b3 != nil {
		t.b3.addHeader(headers)
	}
}

func randStr16() string {
	return fmt.Sprintf("%016x", rand.Uint64()) // #nosec random is weak intentionally
}

func randStr32() string {
	return randStr16() + randStr16()
}

func addHeaderStr(headers http.Header, header, value string) {
	if value != "" {
		headers.Add(header, value)
	}
}
