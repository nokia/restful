// Copyright 2021-2025 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"

	"github.com/gorilla/mux"
)

var (
	// OwnTLSCert is the own TLS certificate used by server on StartTLS. Default is "/etc/own-tls/tls.crt".
	OwnTLSCert string = "/etc/own-tls/tls.crt"

	// OwnTLSKey is the own TLS private key used by servert on StartTLS. Default is "/etc/own-tls/tls.key".
	OwnTLSKey string = "/etc/own-tls/tls.key"

	// ClientCAs is a path of client certificate authorities, to be verified by the server on StartTLS on mTLS. Default is "/etc/clientcas".
	ClientCAs string = "/etc/clientcas"

	// AddrHTTP is the listening address / port of HTTP for Start / StartTLS. Default is ":8080"
	AddrHTTP = ":8080"

	// AddrHTTPS is the listening address / port of HTTPS for StartTLS. Default is ":8443"
	AddrHTTPS = ":8443"
)

// Router routes requests to lambda functions.
type Router struct {
	router   *mux.Router
	monitors monitors
}

// NewRouter creates new Router instance.
func NewRouter() *Router {
	return &Router{router: mux.NewRouter()}
}

// Monitor wraps handler function, creating a middleware in a safe and convenient fashion.
// It adds pre and post functions to be called on serving a request.
func (r *Router) Monitor(pre MonitorFuncPre, post MonitorFuncPost) *Router {
	r.monitors.append(pre, post)
	return r
}

// DisallowUnknownFields instructs JSON decoder to fail if unknown field in found in the received message.
// By default unknown fields are ignored.
// See also JSON schema and OpenAPI Specification `additionalProperties: false`.
func (r *Router) DisallowUnknownFields() *Router {
	return r.Monitor(disallowUnknownFieldsToCtx, nil)
}

// MethodNotAllowedHandler sets the handler invoked when a request matches a route path but not its HTTP method.
// Caution: if same path is set for multiple handlerfunction with different Methods, setting MethodNotAllowedHandler is not advised.
func (r *Router) MethodNotAllowedHandler(handler http.Handler) *Router {
	r.router.MethodNotAllowedHandler = handler
	return r
}

// HandleFunc assigns an HTTP path to a function.
// The function can be compatible with type http.HandlerFunc or a restful's Lambda.
// E.g. r.HandleFunc("/users/{id:[0-9]+}", myFunc)
func (r *Router) HandleFunc(path string, f any) *Route {
	return r.Handle(path, LambdaWrap(f))
}

// Handle adds traditional http.Handler to route.
// Cannot use Lambda here.
func (r *Router) Handle(path string, handler http.Handler) *Route {
	wrapped := r.monitors.wrap(handler)
	return newRoute(r.router.Handle(path, wrapped), nil)
}

// Get returns the route registered with the given name, or nil.
func (r *Router) Get(name string) *Route {
	return newRoute(r.router.Get(name), r.monitors)
}

// Host registers a new route with a matcher for the URL host regex.
// E.g. r.Host("{subdomain:[a-z]+}.example.com")
func (r *Router) Host(hostRegex string) *Route {
	return newRoute(r.router.Host(hostRegex), r.monitors)
}

// Methods registers a new route with a matcher for HTTP methods.
// E.g. r.Methods(http.MethodPost, http.MethodPut)
func (r *Router) Methods(methods ...string) *Route {
	return newRoute(r.router.Methods(methods...), r.monitors)
}

// Name registers a new route with a name.
// That name can be used to query route.
func (r *Router) Name(name string) *Route {
	return newRoute(r.router.Name(name), r.monitors)
}

// Path registers a new route with a matcher for the URL path template.
// E.g. r.Path("/users/{id:[0-9]+}")
func (r *Router) Path(pathTemplate string) *Route {
	return newRoute(r.router.Path(pathTemplate), r.monitors)
}

// PathPrefix registers a new route with a matcher for the URL path template prefix.
func (r *Router) PathPrefix(pathTemplate string) *Route {
	return newRoute(r.router.PathPrefix(pathTemplate), r.monitors)
}

// Queries registers a new route with a matcher for URL query values.
//
//	router.Queries("id", "{id:[0-9]+}")
//
// The odd (1st, 3rd, etc) string is the query parameter.
// The even (2nd, 4th, etc) string is the variable name and optional regex pattern.
func (r *Router) Queries(pairs ...string) *Route {
	return newRoute(r.router.Queries(pairs...), r.monitors)
}

// Schemes registers a new route with a matcher for URL schemes.
func (r *Router) Schemes(schemes ...string) *Route {
	return newRoute(r.router.Schemes(schemes...), r.monitors)
}

// Start starts router on port 8080 (AddrHTTP).
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
// Handles connections gracefully on TERM/INT signals.
func (r *Router) Start() error {
	return NewServer().Addr(AddrHTTP).Handler(r).Graceful(0).ListenAndServe()
}

// StartTLS starts router for TLS on port 8443 (AddrHTTPS) and for cleartext on port 8080 (AddrHTTP), if allowed.
// TLS cert must be at OwnTLSCert and key at OwnTLSKey.
// If mutualTLS=true, then client certs must be provided; see variable ClientCAs.
// If loadSystemCerts is true, clients with CA from system CA pool are accepted, too.
// As the role of mTLS is to authorize certain clients to connect, enable system CAs only if those are reasonable for auth.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
// Handles connections gracefully on TERM/INT signals.
func (r *Router) StartTLS(cleartext, mutualTLS bool, loadSystemCerts bool) error {
	if cleartext {
		go r.Start()
	}

	s := NewServer().Addr(AddrHTTPS).Handler(r).Graceful(0).TLSServerCert(OwnTLSCert, OwnTLSKey)
	if mutualTLS {
		s = s.TLSClientCert(ClientCAs, loadSystemCerts)
	}
	return s.ListenAndServe()
}

// ListenAndServe starts router listening on given address.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func (r *Router) ListenAndServe(addr string) error {
	return ListenAndServe(addr, r)
}

// ListenAndServeTLS starts router listening on given address.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func (r *Router) ListenAndServeTLS(addr, certFile, keyFile string) error {
	return ListenAndServeTLS(addr, certFile, keyFile, r)
}

// ListenAndServeMTLS starts router listening on given address.
// Parameter clientCerts is a PEM cert file or a directory of PEM cert files case insensitively matching *.pem or *.crt.
// If loadSystemCerts is true, clients with CA from system CA pool are accepted, too.
// As the role of mTLS is to authorize certain clients to connect, enable system CAs only if those are reasonable for auth.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func (r *Router) ListenAndServeMTLS(addr, certFile, keyFile, clientCerts string, loadSystemCerts bool) error {
	return ListenAndServeMTLS(addr, certFile, keyFile, clientCerts, loadSystemCerts, r)
}

// ServeHTTP serves HTTP request with matching handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.router.ServeHTTP(w, req)
}
