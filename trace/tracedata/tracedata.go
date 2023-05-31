// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package tracedata

import (
	"net/http"
)

// TraceData contains HTTP message tracing data of various kind.
type TraceData interface {
	// Span spans the existing trace data and puts that into the request.
	// Does not change the input trace data.
	Span(r *http.Request) string

	// SetHeader sets request headers according to the trace data.
	// Input headers object must not be nil.
	SetHeader(header http.Header)

	// IsReceived tells whether trace data was received (parsed from a request) or a random one.
	IsReceived() bool

	// String makes a log string from trace data.
	String() string

	// TraceID returns the trace ID of the trace data.
	TraceID() string

	// SpanID returns the span ID of the trace data.
	SpanID() string
}
