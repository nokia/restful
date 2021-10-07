// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
)

type ctxKey string

const ctxName = ctxKey("restfulRequestData")

// Lambda is lambda class.
// Usually it is available via lambda function context and provides data for header manipulation.
// Often accessed as restful.L(ctx).
type Lambda struct {
	r      *http.Request
	w      http.ResponseWriter
	status int
	trace  *trace
	vars   map[string]string
}

func newLambda(w http.ResponseWriter, r *http.Request, vars map[string]string) *Lambda {
	return &Lambda{w: w, r: r, trace: newTrace(r), vars: vars}
}

// NewRequestCtx adds request related data to r.Context().
// You may use this at traditional http handler functions, and that is what happens at Lambda functions automatically.
// Returns new derived context. That can be used at client functions, silently propagating tracing headers.
//
// E.g. ctx := NewRequestCtx(w, r)
func NewRequestCtx(w http.ResponseWriter, r *http.Request) context.Context {
	return context.WithValue(r.Context(), ctxName, newLambda(w, r, mux.Vars(r)))
}

// L returns lambda-related data from context.
func L(ctx context.Context) *Lambda {
	v := ctx.Value(ctxName)
	if v == nil {
		return nil
	}
	if l, ok := v.(*Lambda); ok {
		return l
	}
	return nil
}

// RequestURL returns URL of received HTTP request.
func (l *Lambda) RequestURL() *url.URL {
	return l.r.URL
}

// RequestPathParameters returns all the path parameters of received HTTP request.
//
// Deprecated: Use RequestVars instead.
func (l *Lambda) RequestPathParameters() map[string]string {
	return l.RequestVars()
}

// RequestVars returns all the named path or query parameters of received HTTP request.
func (l *Lambda) RequestVars() map[string]string {
	if l.vars == nil {
		l.vars = make(map[string]string)
	}
	return l.vars
}

// RequestQueryStringParameter returns value of given path parameter of received HTTP request.
func (l *Lambda) RequestQueryStringParameter(parameter string) string {
	return l.r.URL.Query().Get(parameter)
}

// RequestMethod returns request method
func (l *Lambda) RequestMethod() string {
	return l.r.Method
}

// RequestHeader returns the header map of received HTTP request.
func (l *Lambda) RequestHeader() http.Header {
	return l.r.Header
}

// RequestHeaderGet returns value of header in received HTTP request.
func (l *Lambda) RequestHeaderGet(header string) string {
	return l.r.Header.Get(header)
}

// RequestHeaderValues returns all the values of header in received HTTP request.
func (l *Lambda) RequestHeaderValues(header string) []string {
	return l.r.Header.Values(header)
}

// RequestBasicAuth returns the username and password provided in the request's Authorization header.
// Returned flag ok indicates if the header is received fine.
// That way one can tell if the header was received with empty strings or not.
func (l *Lambda) RequestBasicAuth() (username, password string, ok bool) {
	return l.r.BasicAuth()
}

// ResponseStatus sets HTTP status code to be sent.
// Use that if you want to set positive (non-error) status code.
//    restful.L(ctx).ResponseStatus(http.StatusAccepted)
// Has no effect if lambda returns a non-nil error. In such case status is taken from the error (see restful.NewError), or 500 is returned.
func (l *Lambda) ResponseStatus(status int) {
	l.status = status
}

// ResponseHeaderSet sets an HTTP header to the response to be sent.
func (l *Lambda) ResponseHeaderSet(header, value string) {
	l.w.Header().Set(header, value)
}

// ResponseHeaderAdd adds an HTTP header to the response to be sent.
func (l *Lambda) ResponseHeaderAdd(header, value string) {
	l.w.Header().Add(header, value)
}

// ResponseHeaderAddAs adds an HTTP header to the response to be sent.
// Header is set as provided, not changed to canonical form.
// As long as there is no specific reason, use ResponseHeaderAdd instead.
func (l *Lambda) ResponseHeaderAddAs(header, value string) {
	h := l.w.Header()
	h[header] = append(h[header], value)
}
