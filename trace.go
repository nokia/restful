// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"

	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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
