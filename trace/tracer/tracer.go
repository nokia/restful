// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package tracer

import (
	"net/http"
	"reflect"

	"github.com/nokia/restful/trace/traceb3"
	"github.com/nokia/restful/trace/tracedata"
	"github.com/nokia/restful/trace/traceparent"
)

// Tracer is a HTTP trace handler of various kinds.
type Tracer struct {
	traceData tracedata.TraceData
	received  bool
}

// NewFromHeader creates new tracer object. If no trace data, then create random. Never returns nil.
func NewFromHeader(r *http.Request) *Tracer {
	var traceData tracedata.TraceData
	traceData = traceb3.NewFromRequest(r)
	if reflect.ValueOf(traceData).IsNil() {
		traceData = traceparent.NewFromRequest(r)
	}
	if reflect.ValueOf(traceData).IsNil() {
		return NewRandom()
	}
	t := Tracer{traceData: traceData, received: true}
	return &t
}

// NewRandom creates a tracer object with random data.
func NewRandom() *Tracer {
	return &Tracer{traceData: traceb3.NewRandom(), received: false}
}

// Span spans the existing trace data and puts that into the request.
// Does not change the input trace data.
func (t *Tracer) Span(r *http.Request) string {
	return t.traceData.Span(r)
}

// SetHeader sets request headers according to the trace data.
// Input headers object must not be nil.
func (t *Tracer) SetHeader(headers http.Header) {
	t.traceData.SetHeader(headers)
}

// IsReceived tells whether trace data was received (parsed from a request) or a random one.
func (t *Tracer) IsReceived() bool {
	return t.traceData.IsReceived()
}

// String makes a log string from trace data.
func (t *Tracer) String() string {
	return t.traceData.String()
}

// TraceID returns the trace ID of the trace data.
func (t *Tracer) TraceID() string {
	return t.traceData.TraceID()
}

// SpanID returns the span ID of the trace data.
func (t *Tracer) SpanID() string {
	return t.traceData.SpanID()
}
