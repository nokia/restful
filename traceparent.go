// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"fmt"
	"net/http"
	"strings"
)

/* This is a small trace header tool till project OpenTracing / OpenTelemetry mature.
Not designed to be stable, so not to be exposed outside of restful module.
See https://www.w3.org/TR/trace-context
*/

const (
	headerTraceParent     = "traceparent"
	headerTraceState      = "tracestate"
	headerFakeTraceParent = "x-fake-traceparent"
)

type traceParent struct {
	parent []string
	state  string
}

func newTraceParent(r *http.Request) *traceParent { // May return nil.
	return newTraceParentFromHeaderValue(r.Header.Get(headerTraceParent), r.Header.Get(headerTraceState))
}

func newTraceParentFromFake(r *http.Request) *traceParent {
	return newTraceParentFromHeaderValue(r.Header.Get(headerFakeTraceParent), "") // Our server logger may have faked one already.
}

func newTraceParentWithID(traceID string) *traceParent {
	return &traceParent{parent: []string{"00", traceID, fmt.Sprintf("%016x", 0) /*invalid, span resolves that*/, "00"}}
}

func newTraceParentFromHeaderValue(traceparent, tracestate string) *traceParent {
	parent := strings.Split(traceparent, "-")
	if len(parent) != 4 {
		return nil
	}
	if parent[0] != "00" {
		return nil
	}
	return &traceParent{parent: parent, state: tracestate}
}

func (p *traceParent) span(spanID string) *traceParent {
	newp := &traceParent{parent: p.parent, state: p.state}
	newp.parent[2] = spanID
	return newp
}

func (p *traceParent) addHeader(headers http.Header) {
	headers.Set(headerTraceParent, p.string())
	addHeaderStr(headers, headerTraceState, p.state)
}

func (p *traceParent) string() string {
	return strings.Join(p.parent, "-")
}

func (p *traceParent) traceID() string {
	if len(p.parent) >= 2 {
		return p.parent[1]
	}
	return ""
}

func (p *traceParent) spanID() string {
	if len(p.parent) >= 3 {
		return p.parent[2]
	}
	return ""
}
