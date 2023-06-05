// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package traceotel

import (
	"context"
	"net/http"

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
	ctx, spanCtx := traceHeadersToContext(r)
	if spanCtx.IsValid() {
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

// traceHeadersToContext maps trace headers in request to context.
// Currently spanContext fails to include debug flag, but propagator sets that to ctx.
func traceHeadersToContext(r *http.Request) (context.Context, trace.SpanContext) {
	prop := b3.New()
	ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	spanCtx := trace.SpanContextFromContext(ctx)
	return ctx, spanCtx
}

// Span spans the existing trace data and puts that into the request.
// Does not change the input trace data.
func (t *TraceOTel) Span(r *http.Request) (*http.Request, string) {
	ctx := r.Context()
	spanCtx := trace.SpanContextFromContext(ctx)

	if ctx == nil || !spanCtx.IsValid() {
		ctx = t.ctx
		spanCtx = trace.SpanContextFromContext(ctx)
	}

	if spanCtx.IsValid() {
		ctx, span := tracer.Start(ctx, "client")
		spanCtx = span.SpanContext()
		span.End() // Note: span stored in ctx is completed. That is not right.
		r = r.WithContext(ctx)
	} else {
		// Check if req has tracing headers
		var newCtx context.Context
		newCtx, spanCtx = traceHeadersToContext(r)
		if !spanCtx.IsValid() {
			newCtx = NewRandom().ctx
		}
		r = r.WithContext(newCtx)
	}

	return r, spanCtx.TraceID().String() // Client transport overrides spanID created here, hence not to be logged.
}

// SetHeader sets request headers according to the trace data.
// This function is dummy, as headers are set at client transport.
func (t *TraceOTel) SetHeader(headers http.Header) {
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
