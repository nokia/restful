// Copyright 2021-2025 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

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
	router              *mux.Router
	monitors            monitors
	userNotFoundHandler http.Handler // optional caller-supplied handler for genuine 404s
}

// NewRouter creates new Router instance.
// By default, requests whose path matches a registered route but whose HTTP method
// does not receive 405 Method Not Allowed (with an Allow header) instead of 404.
func NewRouter() *Router {
	r := &Router{router: mux.NewRouter()}
	// mux's NotFoundHandler/MethodNotAllowedHandler point at our dispatchers.
	// These are NOT the same as r.userNotFoundHandler (the caller override).
	r.router.NotFoundHandler = http.HandlerFunc(r.handleNoRouteMatch)
	r.router.MethodNotAllowedHandler = http.HandlerFunc(r.handleMethodNotAllowed)
	return r
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

// MethodNotAllowedHandler overrides the default handler invoked when a request matches a
// route path but not its HTTP method. The default returns 405 with an Allow header.
// Caution: if same path is set for multiple handlerfunction with different Methods, setting MethodNotAllowedHandler is not advised.
func (r *Router) MethodNotAllowedHandler(handler http.Handler) *Router {
	r.router.MethodNotAllowedHandler = handler
	return r
}

// NotFoundHandler sets the handler invoked when no route matches the request path
// (a genuine 404). If the path matches a route with a different method, 405 is
// returned instead and this handler is NOT called.
func (r *Router) NotFoundHandler(handler http.Handler) *Router {
	r.userNotFoundHandler = handler
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

var pathRegexpCache sync.Map // map[string]*regexp.Regexp

func compileCached(pattern string) *regexp.Regexp {
	if cached, ok := pathRegexpCache.Load(pattern); ok {
		return cached.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	actual, _ := pathRegexpCache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp)
}

func (r *Router) allowedMethodsForPath(path string) []string {
	allowed := make([]string, 0, 9)
	_ = r.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			return nil
		}
		re, err := route.GetPathRegexp()
		if err != nil {
			return nil
		}
		if compileCached(re).MatchString(path) {
			allowed = append(allowed, methods...)
		}
		return nil
	})
	sort.Strings(allowed)
	return slices.Compact(allowed)
}

func (r *Router) handleNoRouteMatch(w http.ResponseWriter, req *http.Request) {
	allowed := r.allowedMethodsForPath(req.URL.Path)
	if len(allowed) > 0 && !slices.Contains(allowed, req.Method) {
		write405(w, allowed)
		return
	}
	if r.userNotFoundHandler != nil {
		r.userNotFoundHandler.ServeHTTP(w, req)
		return
	}
	http.NotFound(w, req)
}

func (r *Router) handleMethodNotAllowed(w http.ResponseWriter, req *http.Request) {
	write405(w, r.allowedMethodsForPath(req.URL.Path))
}

func write405(w http.ResponseWriter, allowed []string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
