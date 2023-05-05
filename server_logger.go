// Copyright 2021-2023 Nokia
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
	// HealthCheckPath is the path of health checking, such as liveness and readiness probes.
	// Handled by default, 200 OK sent.
	// Ignored at logging. By default "/healthz".
	HealthCheckPath = "/healthz"

	// LivenessProbePath is the path of liveness probes.
	// Handled by default, 200 OK sent.
	// Ignored at logging. By default "/livez".
	LivenessProbePath = "/livez"

	// ReadinessProbePath is the path of readiess probes.
	// Not handled.
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
	if r.URL.Path == LivenessProbePath || r.URL.Path == HealthCheckPath {
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK) // No logs, stop processing.
	} else if r.URL.Path != ReadinessProbePath {
		ctx := addRequestContextIfNotExists(w, r)                          // Adds tracing to the context, thus enables propagation.
		traceStr := newTraceFromCtx(ctx).string()                          // Get trace string from context.
		r = r.WithContext(context.WithValue(ctx, loggerCtxName, traceStr)) // Add trace string to req context, to be retrieved at response logging.
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
