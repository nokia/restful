// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"
	"strings"
)

/* This is a small trace header tool till project OpenTelemetry mature.
See https://www.w3.org/TR/trace-context
*/

const (
	headerTraceParent = "traceparent"
	headerTraceState  = "tracestate"
)

type traceParent struct {
	parent []string
	state  string
}

func newTraceParent(r *http.Request) *traceParent { // May return nil.
	return newTraceParentFromHeaderValue(r.Header.Get(headerTraceParent), r.Header.Get(headerTraceState))
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

func (p *traceParent) setHeader(headers http.Header) {
	headers.Set(headerTraceParent, p.string())
	setHeaderStr(headers, headerTraceState, p.state)
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
