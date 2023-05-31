// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package traceb3

import (
	"net/http"
	"strings"

	"github.com/nokia/restful/trace/tracecommon"
	log "github.com/sirupsen/logrus"
)

/* Zipkin (B3) and LightStep trace data.
   https://istio.io/latest/docs/tasks/observability/distributed-tracing/overview/
   https://github.com/openzipkin/b3-propagation
   https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html
*/

const (
	headerB3Single       = "b3"
	headerB3TraceID      = "X-B3-TraceId"
	headerB3ParentSpanID = "X-B3-ParentSpanId"
	headerB3SpanID       = "X-B3-SpanId"
	headerB3Sampled      = "X-B3-Sampled"
	headerB3Flags        = "X-B3-Flags"
	headerEnvoyRequestID = "X-Request-Id"
	headerLightStepSpanC = "X-Ot-Span-Context"
)

// TraceB3 HTTP trace object of B3 or X-B3 kind.
type TraceB3 struct {
	traceID, parentSpanID, spanID, sampled, flags, requestID, spanCtx string
	singleLine                                                        bool
	random                                                            bool
}

func newTraceB3FromSingleLine(r *http.Request) *TraceB3 {
	b3Str := r.Header.Get(headerB3Single)
	if b3Str == "" {
		return nil
	}

	b3Fields := strings.SplitN(b3Str, "-", 5)
	if len(b3Fields) > 4 || len(b3Fields) < 2 {
		return nil
	}

	b3 := TraceB3{
		traceID: b3Fields[0],
		spanID:  b3Fields[1],
	}

	if len(b3Fields) >= 3 {
		b3.sampled = b3Fields[2]
	}

	if len(b3Fields) >= 4 {
		b3.parentSpanID = b3Fields[3]
	}

	b3.singleLine = true
	return &b3
}

func newTraceB3FromMultiLine(r *http.Request) *TraceB3 {
	traceID := r.Header.Get(headerB3TraceID)
	if traceID == "" {
		return nil
	}

	return &TraceB3{
		traceID:      traceID,
		parentSpanID: r.Header.Get(headerB3ParentSpanID),
		spanID:       r.Header.Get(headerB3SpanID),
		sampled:      r.Header.Get(headerB3Sampled),
		flags:        r.Header.Get(headerB3Flags),
	}
}

// NewFromRequest creates new TraceB3 object. If there is no trace data in request, then returns nil.
func NewFromRequest(r *http.Request) *TraceB3 {
	if r.Header == nil {
		return nil
	}

	b3 := newTraceB3FromMultiLine(r)
	if b3 == nil {
		b3 = newTraceB3FromSingleLine(r)
		if b3 == nil {
			return nil
		}
	}

	b3.requestID = r.Header.Get(headerEnvoyRequestID)
	b3.spanCtx = r.Header.Get(headerLightStepSpanC)

	return b3
}

// NewRandom creates new TraceB3 object with random content.
func NewRandom() *TraceB3 {
	return newTraceB3WithID(tracecommon.NewTraceID(), log.IsLevelEnabled(log.TraceLevel))
}

func newTraceB3WithID(traceID string, debug bool) *TraceB3 {
	b3 := TraceB3{traceID: traceID, singleLine: true, random: true}
	if debug {
		b3.sampled = "d"
	}
	return &b3
}

func (b3 *TraceB3) span() *TraceB3 {
	newB3 := *b3
	newB3.parentSpanID = newB3.spanID
	newB3.spanID = tracecommon.NewSpanID()
	return &newB3
}

// Span spans the existing trace data and puts that into the request.
// Does not change the input trace data.
func (b3 *TraceB3) Span(r *http.Request) string {
	span := b3.span()
	span.SetHeader(r.Header)
	return span.String()
}

func (b3 *TraceB3) setHeaderSingleLine(headers http.Header) {
	b3Str := b3.traceID + "-" + b3.spanID
	if b3.sampled != "" {
		b3Str += "-" + b3.sampled
		if b3.parentSpanID != "" {
			b3Str += "-" + b3.parentSpanID
		}
	}
	headers.Set(headerB3Single, b3Str)
}

func (b3 *TraceB3) setHeaderMultiLine(headers http.Header) {
	tracecommon.SetHeaderStr(headers, headerB3TraceID, b3.traceID)
	tracecommon.SetHeaderStr(headers, headerB3ParentSpanID, b3.parentSpanID)
	tracecommon.SetHeaderStr(headers, headerB3SpanID, b3.spanID)
	tracecommon.SetHeaderStr(headers, headerB3Sampled, b3.sampled)
	tracecommon.SetHeaderStr(headers, headerB3Flags, b3.flags)
}

// SetHeader sets request headers according to the trace data.
// Input headers object must not be nil.
func (b3 *TraceB3) SetHeader(headers http.Header) {
	if b3.traceID == "" {
		return
	}

	if b3.singleLine {
		b3.setHeaderSingleLine(headers)
	} else {
		b3.setHeaderMultiLine(headers)
	}

	tracecommon.SetHeaderStr(headers, headerEnvoyRequestID, b3.requestID)
	tracecommon.SetHeaderStr(headers, headerLightStepSpanC, b3.spanCtx)
}

// IsReceived tells whether trace data was received (parsed from a request) or a random one.
func (b3 *TraceB3) IsReceived() bool {
	return !b3.random
}

// String makes a log string from trace data.
func (b3 *TraceB3) String() string {
	if b3.traceID != "" {
		return b3.traceID + "-" + b3.spanID
	}
	return b3.spanID
}

// TraceID returns the trace ID of the trace data.
func (b3 *TraceB3) TraceID() string {
	return b3.traceID
}

// SpanID returns the span ID of the trace data.
func (b3 *TraceB3) SpanID() string {
	return b3.spanID
}
