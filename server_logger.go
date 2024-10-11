// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type loggerCtxKey string

const loggerCtxName = loggerCtxKey("restfulLoggerTraceStr")

var (
	// HealthCheckPath is the path of health checking.
	// Handled automatically, 200 OK sent.
	// Similar to liveness endpoint, but sends `Connection: close` header as an extra in the response,
	// so that each invocation to check listening/accepting new connections.
	// Ignored at logging. By default "/healthz".
	HealthCheckPath = "/healthz"

	// LivenessProbePath is the path of liveness probes.
	// Handled automatically, 200 OK sent.
	// Ignored at logging. By default "/livez".
	LivenessProbePath = "/livez"

	// ReadinessProbePath is the path of readiess probes.
	// Not handled automatically. But a custom endpoint is needed.
	// Ignored at logging. By default "/readyz".
	ReadinessProbePath = "/readyz"
)

func loggerPost(w http.ResponseWriter, r *http.Request, statusCode int) {
	v := r.Context().Value(loggerCtxName)
	if v != nil {
		if traceStr, ok := v.(string); ok {
			log.Debugf("[%s] Sent rsp: %d", traceStr, statusCode)
		}
	}
}

func loggerPre(w http.ResponseWriter, r *http.Request) *http.Request {
	if r.URL.Path == LivenessProbePath {
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK) // No logs, stop processing.
	} else if r.URL.Path == HealthCheckPath {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK) // No logs, stop processing.
	} else if r.URL.Path != ReadinessProbePath && log.IsLevelEnabled(log.DebugLevel) { // If log won't be printed, then omit context and trace operations.
		trace := traceFromContextOrRequestOrRandom(r)
		traceStr := trace.String()
		r = r.WithContext(context.WithValue(r.Context(), loggerCtxName, traceStr)) // Add trace string to req context, to be retrieved at response logging.
		log.Debugf("[%s] Recv req: %s %s", traceStr, r.Method, r.URL.Path)
	}
	return r
}

// Logger wraps original handler and returns a handler that logs.
// Logs start with a semi-random trace ID to be able to match requests to responses.
// If path matches LivenessProbePath or HealthCheckPath then does not log and responds with 200 OK.
// If path matches ReadinessProbePath then does not log, but processed as usual.
func Logger(h http.Handler) http.Handler {
	return Monitor(h, loggerPre, loggerPost)
}
