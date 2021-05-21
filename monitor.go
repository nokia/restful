// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"
)

type monitor struct {
	pre  MonitorFuncPre
	post MonitorFuncPost
}

type monitors []monitor

func (m *monitors) append(pre MonitorFuncPre, post MonitorFuncPost) {
	*m = append(*m, monitor{pre: pre, post: post})
}

func (m monitors) wrap(h http.Handler) (monitored http.Handler) {
	monitored = h
	for _, monitor := range m {
		monitored = monitorHandler{origHandler: monitored, pre: monitor.pre, post: monitor.post}
	}
	return
}

// MonitorFuncPost is a type of user defined function to be called after the request was served.
// Handle ResponseWriter with care.
type MonitorFuncPost func(w http.ResponseWriter, r *http.Request, statusCode int)

// MonitorFuncPre is a type of user defined function to be called before the request is served.
// If calls WriteHeader, then serving is aborted, the original handler and monitor post functions are not called.
// Pre may modify the request, especially its context, and return the modified request, or nil if not modified.
type MonitorFuncPre func(w http.ResponseWriter, r *http.Request) *http.Request

type monitorWriter struct {
	writer     http.ResponseWriter
	statusCode *int
}

// Header returns the header map to be written.
func (w monitorWriter) Header() http.Header {
	return w.writer.Header()
}

// Write writes supplied bytes to HTTP response.
func (w monitorWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}

// WriteHeader sends HTTP status code.
func (w monitorWriter) WriteHeader(statusCode int) {
	*w.statusCode = statusCode
	w.writer.WriteHeader(statusCode)
}

type monitorHandler struct {
	origHandler http.Handler
	pre         MonitorFuncPre
	post        MonitorFuncPost
}

// ServeHTTP serves HTTP request.
func (c monitorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.pre != nil {
		var statusCode int
		newR := c.pre(monitorWriter{writer: w, statusCode: &statusCode}, r)
		if statusCode != 0 { // Do not process any further.
			return
		}
		if newR != nil {
			r = newR
		}
	}

	var statusCode int
	c.origHandler.ServeHTTP(monitorWriter{writer: w, statusCode: &statusCode}, r)

	if c.post != nil {
		c.post(w, r, statusCode)
	}
}

// Monitor wraps http.Handler, adding user defined pre and post ReporterFunc call after the handler is served.
// You may prefer Server's or Router's Monitor functions.
func Monitor(h http.Handler, pre MonitorFuncPre, post MonitorFuncPost) http.Handler {
	return monitorHandler{origHandler: h, pre: pre, post: post}
}
