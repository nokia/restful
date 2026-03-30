// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
)

// loggingTransport is an http.RoundTripper that logs HTTP requests and responses
// at the transport level. It is inserted *inside* the OTel otelhttp wrapper so
// that by the time RoundTrip executes the active span on the context is already
// the real client span created by otelhttp — no extra spans are needed.
//
// With a Logrus OTel hook registered, the log.WithContext call automatically
// attaches trace_id and span_id to every log entry, enabling precise
// correlation between logs and the tcpdump/trace backend.
type loggingTransport struct {
	wrapped http.RoundTripper
}

// RoundTrip executes the request via the wrapped transport and emits
// structured debug log lines that carry the real OTel span ID.
func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return lt.wrapped.RoundTrip(req)
	}

	ctx := req.Context()

	// Derive a correlation string from the active span (set by otelhttp) or fall
	// back to the legacy semi-random trace ID stored in the context / request.
	spanCtx := trace.SpanFromContext(ctx).SpanContext()
	var correlationID string
	if spanCtx.IsValid() {
		correlationID = spanCtx.TraceID().String() + ":" + spanCtx.SpanID().String()
	} else {
		// Fallback: use the legacy trace helper so behaviour is unchanged when
		// OTel is disabled.
		t := traceFromContext(ctx)
		if t != nil {
			correlationID = t.String()
		} else {
			correlationID = req.Header.Get("X-B3-TraceId")
		}
	}

	log.WithContext(ctx).Debugf("[%s] Sent req: %s %s", correlationID, req.Method, req.URL.String())

	resp, err := lt.wrapped.RoundTrip(req)

	if err != nil {
		log.WithContext(ctx).Debugf("[%s] Fail req: %s %s", correlationID, req.Method, req.URL.String())
	} else {
		log.WithContext(ctx).Debugf("[%s] Recv rsp: %s", correlationID, resp.Status)
	}

	return resp, err
}
