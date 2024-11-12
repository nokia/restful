// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package traceotel

import (
	"context"
	"net/http"

	"github.com/nokia/restful/trace/tracedata"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

// SetTraceProvider sets global Open Telemetry trace provider to be used.
func SetTraceProvider(tp *sdktrace.TracerProvider) {
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("")
}

// TraceOTel HTTP trace object.
type TraceOTel struct {
	ctx context.Context
}

// NewFromRequest creates new TraceOTel object. Returns nil if tracer not found in request.
//
// Warning: Does not return trace from request context.
func NewFromRequest(r *http.Request) *TraceOTel {
	return NewFromRequestWithContext(r.Context(), r)
}

// NewFromRequestWithContext creates new TraceOTel object derived from parentCtx. Returns nil if tracer not found in request.
//
// Warning: Does not return trace from request context.
func NewFromRequestWithContext(parentCtx context.Context, r *http.Request) *TraceOTel {
	ctx, ok := TraceHeadersToContext(parentCtx, r)
	if ok {
		return &TraceOTel{ctx: ctx}
	}
	return nil
}

// NewFromContext creates new TraceOTel object. Returns nil if tracer not found in context.
func NewFromContext(ctx context.Context) *TraceOTel {
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		return &TraceOTel{ctx: ctx}
	}
	return nil
}

// NewRandom creates new TraceOTel object.
func NewRandom() *TraceOTel {
	var span trace.Span
	ctx, span := tracer.Start(context.Background(), "client")
	span.End()
	return &TraceOTel{ctx: ctx}
}

// TraceHeadersToContext maps trace headers in request to context.
// If there were no tracing headers to be propagated, the original context is returned.
// Returns span found or nil.
func TraceHeadersToContext(parentCtx context.Context, r *http.Request) (context.Context, bool) {
	prop := b3.New()
	ctx := prop.Extract(parentCtx, propagation.HeaderCarrier(r.Header))
	span := trace.SpanFromContext(ctx)
	spanCtx := span.SpanContext()
	if spanCtx.IsValid() {
		return ctx, true
	}
	return parentCtx, false
}

// Span is a new span.
type Span struct {
	span trace.Span
	name string
}

// End ends a span.
func (s Span) End() {
	s.span.End()
}

// String returns trace span ID string representation.
func (s Span) String() string {
	return s.name
}

// Span spans the existing trace data and puts that into the request.
// Does not change the input trace data.
func (t *TraceOTel) Span(r *http.Request) (*http.Request, tracedata.Span) {
	// Get parent span from context
	ctx := r.Context()

	// Fallback: Get parent span from tracing data
	if ctx == nil || !trace.SpanContextFromContext(ctx).IsValid() {
		ctx = t.ctx
	}

	// Fallback 2: Get parent span from headers
	if !trace.SpanContextFromContext(ctx).IsValid() {
		ctx, _ = TraceHeadersToContext(r.Context(), r)
	}

	ctx, span := tracer.Start(ctx, "client")
	r = r.WithContext(ctx)
	return r, Span{span: span, name: span.SpanContext().TraceID().String()}
}

// IsReceived tells whether trace data was received (parsed from a request) or a random one.
func (t *TraceOTel) IsReceived() bool {
	return true
}

// String makes a log string from trace data.
func (t *TraceOTel) String() string {
	spanCtx := trace.SpanContextFromContext(t.ctx)
	return spanCtx.TraceID().String() + "-" + spanCtx.SpanID().String()
}

// TraceID returns the trace ID of the trace data.
func (t *TraceOTel) TraceID() string {
	return trace.SpanContextFromContext(t.ctx).TraceID().String()
}

// SpanID returns the span ID of the trace data.
func (t *TraceOTel) SpanID() string {
	return trace.SpanContextFromContext(t.ctx).SpanID().String()
}
