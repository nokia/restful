// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var isTraced bool = true
var serverName string = ""

// SetTrace can enable/disable HTTP tracing.
// By default trace header generation and propagation is enabled.
func SetTrace(b bool) {
	isTraced = b
}

// SetServerName allows settings a server name.
// That can be used at span name formatting.
func SetServerName(s string) {
	serverName = s
}

func spanNameFormatter(operation string, req *http.Request) string {
	if serverName != "" {
		return serverName + ":" + req.URL.Path
	}
	return req.URL.Path
}

func init() {
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, b3.New(), b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader))))
}

// traceHeadersToContext maps trace headers in request to context.
// Currently spanContext fails to include debug flag, but propagator sets that to ctx.
func traceHeadersToContext(req *http.Request) (context.Context, trace.SpanContext) {
	prop := b3.New()
	ctx := prop.Extract(req.Context(), propagation.HeaderCarrier(req.Header))
	spanCtx := trace.SpanContextFromContext(ctx)
	return ctx, spanCtx
}

// ensureTraceCtx makes sure context has some kind of tracing data.
func ensureTraceCtx(ctx context.Context, req *http.Request) (context.Context, trace.SpanContext) {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		// Check if req has tracing headers
		if newCtx, spanCtx := traceHeadersToContext(req); spanCtx.IsValid() {
			return newCtx, spanCtx
		}
		// New tracing
		newCtx, span := clientTracer.Start(ctx, "client")
		spanCtx = span.SpanContext()
		ctx = newCtx
		span.End()
	}
	return ctx, spanCtx
}
