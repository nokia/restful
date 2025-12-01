// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package tracer

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/nokia/restful/trace/traceb3"
	"github.com/nokia/restful/trace/tracedata"
	"github.com/nokia/restful/trace/traceotel"
	"github.com/nokia/restful/trace/traceparent"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

const unsetFraction = float64(-32.0)

// OtelEnabled tells if OpenTelemetry tracing was activated.
// If OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is set, then tracing is activated automatically.
// You may set OTEL_TRACES_SAMPLER and OTEL_TRACES_SAMPLER_ARG to set the sampling type and fraction.
// You may fine-tune batch exporting parameters with OTEL_BSP_* environment variables.
// See also
//   - https://opentelemetry.io/docs/specs/otel/protocol/exporter/
//   - https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/
var OtelEnabled = false

func init() {
	target := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if target == "" {
		target = os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	if target == "" {
		return
	}

	OtelEnabled = true

	if err := SetOTelGrpc(target, unsetFraction); err != nil {
		panic(err)
	}
}

// GetOTel returns if Open Telemetry is enabled.
// It may be enabled automatically if OTEL_ environment variables are set.
func GetOTel() bool {
	return OtelEnabled
}

// SetOTel enables/disables Open Telemetry.
// Tracer provider can be set with an exporter and collector endpoint you need.
func SetOTel(enabled bool, tp *sdktrace.TracerProvider) {
	OtelEnabled = enabled

	if enabled {
		if tp == nil {
			tp = sdktrace.NewTracerProvider()
		}
		traceotel.SetTraceProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, b3.New(), b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader))))
	} else {
		traceotel.SetTraceProvider(sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()), sdktrace.WithSpanProcessor(nil)))
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	}
}

func ensureScheme(target string) string {
	if strings.Contains(target, "://") {
		return target
	}

	// Add something. The exact scheme (grpc, https, http or even dns) is not important, it seems.
	return "http://" + target
}

// SetOTelGrpc enables Open Telemetry.
// Activates trace export to the OTLP gRPC collector target address defined.
// Port is 4317, unless defined otherwise in provided target string.
// E.g. "http://localhost:4317".
//
// Fraction tells the fraction of spans to report, unless the parent is sampled.
//   - Zero means no sampling.
//   - Greater or equal 1 means sampling all the messages.
//   - Else the sampling fraction, e.g. 0.01 for 1%.
func SetOTelGrpc(target string, fraction float64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	name := filepath.Base(os.Args[0])
	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceNameKey.String(name)))
	if err != nil {
		return err
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(ensureScheme(target)))
	if err != nil {
		return err
	}

	batchSpanProcessor := sdktrace.NewBatchSpanProcessor(exporter)

	var sampler sdktrace.Sampler = nil
	if fraction != unsetFraction {
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(fraction))
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler), // may be nil if fraction is unset, using env vars OTEL_TRACES_SAMPLER(_ARG) instead.
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(batchSpanProcessor),
	)

	SetOTel(true, tracerProvider)
	return nil
}

// Tracer is a HTTP trace handler of various kinds.
type Tracer struct {
	traceData tracedata.TraceData
	received  bool
}

// NewFromRequest creates new tracer object from request. Returns nil if not found.
func NewFromRequest(r *http.Request) *Tracer {
	var traceData tracedata.TraceData
	if OtelEnabled {
		traceData = traceotel.NewFromRequest(r)
	} else {
		traceData = traceb3.NewFromRequest(r)
		if reflect.ValueOf(traceData).IsNil() {
			traceData = traceparent.NewFromRequest(r)
		}
	}

	if traceData == nil || reflect.ValueOf(traceData).IsNil() {
		return nil
	}
	t := Tracer{traceData: traceData, received: true}
	return &t
}

// NewFromRequestWithContext creates new tracer object from request derived from parentCtx if otel. Returns nil if not found.
func NewFromRequestWithContext(parentCtx context.Context, r *http.Request) *Tracer {
	var traceData tracedata.TraceData
	if OtelEnabled {
		traceData = traceotel.NewFromRequestWithContext(parentCtx, r)
	} else {
		traceData = traceb3.NewFromRequest(r)
		if reflect.ValueOf(traceData).IsNil() {
			traceData = traceparent.NewFromRequest(r)
		}
	}

	if traceData == nil || reflect.ValueOf(traceData).IsNil() {
		return nil
	}
	t := Tracer{traceData: traceData, received: true}
	return &t
}

// NewFromRequestOrRandom creates new tracer object. If no trace data, then create random. Never returns nil.
//
// Warning: Does not return trace from request context.
func NewFromRequestOrRandom(r *http.Request) *Tracer {
	if t := NewFromRequest(r); t != nil {
		return t
	}

	return NewRandom()
}

// NewRandom creates a tracer object with random data.
func NewRandom() *Tracer {
	var randomTraceData tracedata.TraceData
	if OtelEnabled {
		randomTraceData = traceotel.NewRandom()
	} else {
		randomTraceData = traceb3.NewRandom()
	}
	return &Tracer{traceData: randomTraceData, received: false}
}

// Span spans the existing trace data and puts that into the request.
// Returns the updated request and a trace string for logging.
// Does not change the input trace data.
func (t *Tracer) Span(r *http.Request) (*http.Request, string, func()) {
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
