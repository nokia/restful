// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"
	"strings"
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

type traceB3 struct {
	traceID, parentSpanID, spanID, sampled, flags, requestID, spanCtx string
	singleLine                                                        bool
}

func newTraceB3FromSingleLine(r *http.Request) *traceB3 {
	b3Str := r.Header.Get(headerB3Single)
	if b3Str == "" {
		return nil
	}

	b3Fields := strings.SplitN(b3Str, "-", 5)
	if len(b3Fields) > 4 || len(b3Fields) < 2 {
		return nil
	}

	b3 := traceB3{
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

func newTraceB3FromMultiLine(r *http.Request) *traceB3 {
	traceID := r.Header.Get(headerB3TraceID)
	if traceID == "" {
		return nil
	}

	return &traceB3{
		traceID:      traceID,
		parentSpanID: r.Header.Get(headerB3ParentSpanID),
		spanID:       r.Header.Get(headerB3SpanID),
		sampled:      r.Header.Get(headerB3Sampled),
		flags:        r.Header.Get(headerB3Flags),
	}
}

func newTraceB3(r *http.Request) *traceB3 {
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

func newTraceB3WithID(traceID string, trace bool) *traceB3 {
	b3 := traceB3{traceID: traceID, singleLine: true}
	if trace {
		b3.sampled = "d"
	}
	return &b3
}

func (b3 *traceB3) span(spanID string) *traceB3 {
	newB3 := *b3
	newB3.parentSpanID = newB3.spanID
	newB3.spanID = spanID
	return &newB3
}

func (b3 *traceB3) addHeaderSingleLine(headers http.Header) {
	b3Str := b3.traceID + "-" + b3.spanID
	if b3.sampled != "" {
		b3Str += "-" + b3.sampled
		if b3.parentSpanID != "" {
			b3Str += "-" + b3.parentSpanID
		}
	}
	headers.Add(headerB3Single, b3Str)
}

func (b3 *traceB3) addHeaderMultiLine(headers http.Header) {
	addHeaderStr(headers, headerB3TraceID, b3.traceID)
	addHeaderStr(headers, headerB3ParentSpanID, b3.parentSpanID)
	addHeaderStr(headers, headerB3SpanID, b3.spanID)
	addHeaderStr(headers, headerB3Sampled, b3.sampled)
	addHeaderStr(headers, headerB3Flags, b3.flags)
}

func (b3 *traceB3) addHeader(headers http.Header) {
	if b3.traceID == "" {
		return
	}

	if b3.singleLine {
		b3.addHeaderSingleLine(headers)
	} else {
		b3.addHeaderMultiLine(headers)
	}

	addHeaderStr(headers, headerEnvoyRequestID, b3.requestID)
	addHeaderStr(headers, headerLightStepSpanC, b3.spanCtx)
}

func (b3 *traceB3) string() string {
	if b3.traceID != "" {
		return b3.traceID + "-" + b3.spanID
	}
	return b3.spanID
}
