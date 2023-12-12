// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"

	"github.com/nokia/restful/trace/tracer"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var isTraced = true
var serverName = ""

// SetOTel enables/disables Open Telemetry. By default it is disabled.
// Trace provider can be set, when enabling.
func SetOTel(enabled bool, tp *sdktrace.TracerProvider) {
	tracer.SetOTel(enabled, tp)
	defaultClient = NewClient()
}

// SetOTelGrpc enables Open Telemetry.
// Activates trace export to the OTLP gRPC collector target address defined.
// Port is 4317, unless defined otherwise in provided target string.
func SetOTelGrpc(target string) error {
	return tracer.SetOTelGrpc(target)
}

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
