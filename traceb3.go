// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import "net/http"

/* Zipkin (B3) and LightStep trace data.
   https://istio.io/latest/docs/tasks/observability/distributed-tracing/overview/
   https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html
*/

const (
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
}

func newTraceB3(r *http.Request) *traceB3 {
	b3 := traceB3{
		traceID:      r.Header.Get(headerB3TraceID),
		parentSpanID: r.Header.Get(headerB3ParentSpanID),
		spanID:       r.Header.Get(headerB3SpanID),
		sampled:      r.Header.Get(headerB3Sampled),
		flags:        r.Header.Get(headerB3Flags),
		requestID:    r.Header.Get(headerEnvoyRequestID),
		spanCtx:      r.Header.Get(headerLightStepSpanC),
	}

	if b3.traceID == "" {
		return nil
	}
	return &b3
}

func newTraceB3WithID(traceID string) *traceB3 {
	return &traceB3{traceID: traceID}
}

func (b3 *traceB3) span(spanID string) *traceB3 {
	newB3 := *b3
	newB3.parentSpanID = newB3.spanID
	newB3.spanID = spanID
	return &newB3
}

func (b3 *traceB3) addHeader(headers http.Header) {
	if b3.traceID == "" {
		return
	}
	addHeaderStr(headers, headerB3TraceID, b3.traceID)
	addHeaderStr(headers, headerB3ParentSpanID, b3.parentSpanID)
	addHeaderStr(headers, headerB3SpanID, b3.spanID)
	addHeaderStr(headers, headerB3Sampled, b3.sampled)
	addHeaderStr(headers, headerB3Flags, b3.flags)
	addHeaderStr(headers, headerEnvoyRequestID, b3.requestID)
	addHeaderStr(headers, headerLightStepSpanC, b3.spanCtx)
}

func (b3 *traceB3) string() string {
	if b3.traceID != "" {
		return b3.traceID + "-" + b3.spanID
	}
	return b3.spanID
}
