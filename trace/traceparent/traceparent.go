// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package traceparent

import (
	"net/http"
	"strings"

	"github.com/nokia/restful/trace/tracecommon"
)

const (
	headerTraceParent = "traceparent"
	headerTraceState  = "tracestate"
)

// TraceParent HTTP trace object.
// See https://www.w3.org/TR/trace-context
type TraceParent struct {
	parent []string
	state  string
}

// NewFromRequest creates new TraceParent object. If there is no trace data in request, then returns nil.
func NewFromRequest(r *http.Request) *TraceParent {
	if r.Header == nil {
		return nil
	}

	return newTraceParentFromHeaderValue(r.Header.Get(headerTraceParent), r.Header.Get(headerTraceState))
}

func newTraceParentFromHeaderValue(traceparent, tracestate string) *TraceParent {
	parent := strings.Split(traceparent, "-")
	if len(parent) != 4 {
		return nil
	}
	if parent[0] != "00" {
		return nil
	}
	return &TraceParent{parent: parent, state: tracestate}
}

func (p *TraceParent) span() *TraceParent {
	span := &TraceParent{parent: make([]string, len(p.parent)), state: p.state}
	copy(span.parent, p.parent)
	span.parent[2] = tracecommon.NewSpanID()
	return span
}

// Span spans the existing trace data and puts that into the request.
// Returns the updated request and a trace string for logging.
// Does not change the input trace data.
func (p *TraceParent) Span(r *http.Request) (*http.Request, string) {
	span := p.span()
	span.SetHeader(r.Header)
	return r, span.String()
}

// SetHeader sets request headers according to the trace data.
// Input headers object must not be nil.
func (p *TraceParent) SetHeader(headers http.Header) {
	headers.Set(headerTraceParent, p.String())
	tracecommon.SetHeaderStr(headers, headerTraceState, p.state)
}

// IsReceived tells whether trace data was received (parsed from a request) or a random one.
func (p *TraceParent) IsReceived() bool {
	return true // Must have been created by NewFromRequest.
}

// String makes a log string from trace data.
func (p *TraceParent) String() string {
	return strings.Join(p.parent, "-")
}

// TraceID returns the trace ID of the trace data.
func (p *TraceParent) TraceID() string {
	if len(p.parent) >= 2 {
		return p.parent[1]
	}
	return ""
}

// SpanID returns the span ID of the trace data.
func (p *TraceParent) SpanID() string {
	if len(p.parent) >= 3 {
		return p.parent[2]
	}
	return ""
}
