// Copyright 2021 Nokia
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
	router  *mux.Router
	monitor monitor
}

// NewRouter creates new Router instance.
func NewRouter() *Router {
	return &Router{router: mux.NewRouter()}
}

// Monitor sets monitor functions for the router.
// These functions are called pre / post serving each request.
func (r *Router) Monitor(pre MonitorFuncPre, post MonitorFuncPost) *Router {
	r.monitor.pre = pre
	r.monitor.post = post
	return r
}

// HandleFunc assigns an HTTP path to a function.
// The function can be compatible with type http.HandlerFunc or a restful's Lambda.
// E.g. r.HandleFunc("/users/{id:[0-9]+}", myFunc)
func (r *Router) HandleFunc(path string, f interface{}) *Route {
	return r.Handle(path, LambdaWrap(f))
}

// Handle adds traditional http.Handler to route.
// Cannot use Lambda here.
func (r *Router) Handle(path string, handler http.Handler) *Route {
	monitorHandler := Monitor(handler, r.monitor.pre, r.monitor.post)
	return (*Route)(r.router.Handle(path, monitorHandler))
}

// Get returns the route registered with the given name, or nil.
func (r *Router) Get(name string) *Route {
	return (*Route)(r.router.Get(name))
}

// Host registers a new route with a matcher for the URL host regex.
// E.g. r.Host("{subdomain:[a-z]+}.example.com")
func (r *Router) Host(hostRegex string) *Route {
	return (*Route)(r.router.Host(hostRegex))
}

// Methods registers a new route with a matcher for HTTP methods.
// E.g. r.Methods(http.MethodPost, http.MethodPut)
func (r *Router) Methods(methods ...string) *Route {
	return (*Route)(r.router.Methods(methods...))
}

// Name registers a new route with a name.
// That name can be used to query route.
func (r *Router) Name(name string) *Route {
	return (*Route)(r.router.Name(name))
}

// Path registers a new route with a matcher for the URL path template.
// E.g. r.Path("/users/{id:[0-9]+}")
func (r *Router) Path(pathTemplate string) *Route {
	return (*Route)(r.router.Path(pathTemplate))
}

// PathPrefix registers a new route with a matcher for the URL path template prefix.
func (r *Router) PathPrefix(pathTemplate string) *Route {
	return (*Route)(r.router.PathPrefix(pathTemplate))
}

// Schemes registers a new route with a matcher for URL schemes.
func (r *Router) Schemes(schemes ...string) *Route {
	return (*Route)(r.router.Schemes(schemes...))
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
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
// Handles connections gracefully on TERM/INT signals.
func (r *Router) StartTLS(cleartext, mutualTLS bool) error {
	if cleartext {
		go r.Start()
	}

	s := NewServer().Addr(AddrHTTPS).Handler(r).Graceful(0).TLSServerCert(OwnTLSCert, OwnTLSKey)
	if mutualTLS {
		s = s.TLSClientCert(ClientCAs)
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
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func (r *Router) ListenAndServeMTLS(addr, certFile, keyFile, clientCerts string) error {
	return ListenAndServeMTLS(addr, certFile, keyFile, clientCerts, r)
}

// ServeHTTP serves HTTP request with matching handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.router.ServeHTTP(w, req)
}
