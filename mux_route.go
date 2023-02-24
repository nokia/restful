// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Route ...
type Route struct {
	route    *mux.Route
	monitors monitors
}

func newRoute(route *mux.Route, monitors monitors) *Route {
	return &Route{route: route, monitors: monitors}
}

// GetError returns if building route failed.
func (route *Route) GetError() error {
	return route.route.GetError()
}

// Handler sets a handler for a route.
// Note: Cannot use Lambda here. Router's Monitor does not apply here.
func (route *Route) Handler(handler http.Handler) *Route {
	route.route = route.route.Handler(handler)
	return route
}

// HandlerFunc sets a handler function or lambda for a route.
func (route *Route) HandlerFunc(f interface{}) *Route {
	wrapped := route.monitors.wrap(LambdaWrap(f))
	route.route = route.route.Handler(wrapped)
	return route
}

// Methods defines on which HTTP methods to call your function.
//
//	r.Methods(http.MethodPost, http.MethodPut)
func (route *Route) Methods(methods ...string) *Route {
	route.route = route.route.Methods(methods...)
	return route
}

// Name sets a name for a route.
func (route *Route) Name(name string) *Route {
	route.route = route.route.Name(name)
	return route
}

// Path registers a new route with a matcher for the URL path template.
//
//	r.Path("/users/{id:[0-9]+}")
func (route *Route) Path(pathTemplate string) *Route {
	route.route = route.route.Path(pathTemplate)
	return route
}

// PathPrefix adds a matcher for the URL path template prefix.
func (route *Route) PathPrefix(pathTemplate string) *Route {
	route.route = route.route.PathPrefix(pathTemplate)
	return route
}

// Queries adds a matcher for URL query values.
//
//	route.Queries("id", "{id:[0-9]+}")
//
// The odd (1st, 3rd, etc) string is the query parameter.
// The even (2nd, 4th, etc) string is the variable name and optional regex pattern.
func (route *Route) Queries(pairs ...string) *Route {
	route.route = route.route.Queries(pairs...)
	return route
}

// Schemes adds a matcher for URL schemes.
func (route *Route) Schemes(schemes ...string) *Route {
	route.route = route.route.Schemes(schemes...)
	return route
}

// Subrouter creates a new sub-router for the route.
//
//	r := restful.NewRouter()
//	s := r.PathPrefix("/api/v1/").Subrouter()
//	s.HandleFunc("/users", handleAllUsers)
//
// Subrouter takes the existing Monitors of the parent route and apply them to the handle functions.
func (route *Route) Subrouter() *Router {
	return &Router{router: route.route.Subrouter(), monitors: route.monitors}
}
