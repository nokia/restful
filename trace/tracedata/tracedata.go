// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package tracedata

import (
	"net/http"
)

// Span is an object returned at creating a span.
// That must be closed after use.
type Span interface {
	// End ends a span.
	End()

	// String returns trace span ID string representation.
	String() string
}

// TraceData contains HTTP message tracing data of various kind.
type TraceData interface {
	// Span spans the existing trace data and puts that into the request.
	// Returns the updated request and a trace string for logging.
	// Does not change the input trace data.
	Span(r *http.Request) (*http.Request, Span)

	// IsReceived tells whether trace data was received (parsed from a request) or a random one.
	IsReceived() bool

	// String makes a log string from trace data.
	String() string

	// TraceID returns the trace ID of the trace data.
	TraceID() string

	// SpanID returns the span ID of the trace data.
	SpanID() string
}
