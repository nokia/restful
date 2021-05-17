// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Route ...
type Route mux.Route

// GetError returns if building route failed.
func (route *Route) GetError() error {
	return (*mux.Route)(route).GetError()
}

// Handler sets a handler for a route.
// Note: Cannot use Lambda here. Router's Monitor does not apply here.
func (route *Route) Handler(handler http.Handler) *Route {
	return (*Route)((*mux.Route)(route).Handler(handler))
}

// HandlerFunc sets a handler function or lambda for a route.
// Note: Router's Monitor does not apply here.
func (route *Route) HandlerFunc(f interface{}) *Route {
	return (*Route)((*mux.Route)(route).Handler(LambdaWrap(f)))
}

// Methods defines on which HTTP methods to call your function.
//  r.Methods(http.MethodPost, http.MethodPut)
func (route *Route) Methods(methods ...string) *Route {
	return (*Route)((*mux.Route)(route).Methods(methods...))
}

// Name sets a name for a route.
func (route *Route) Name(name string) *Route {
	return (*Route)((*mux.Route)(route).Name(name))
}

// Path registers a new route with a matcher for the URL path template.
//  r.Path("/users/{id:[0-9]+}")
func (route *Route) Path(pathTemplate string) *Route {
	return (*Route)((*mux.Route)(route).Path(pathTemplate))
}

// PathPrefix adds a matcher for the URL path template prefix.
func (route *Route) PathPrefix(pathTemplate string) *Route {
	return (*Route)((*mux.Route)(route).PathPrefix(pathTemplate))
}

// Schemes adds a matcher for URL schemes.
func (route *Route) Schemes(schemes ...string) *Route {
	return (*Route)((*mux.Route)(route).Schemes(schemes...))
}

// Subrouter creates a new sub-router for the route.
//  r := restful.NewRouter()
//  s := r.PathPrefix("/api/v1/").Subrouter()
//  s.HandleFunc("/users", handleAllUsers)
func (route *Route) Subrouter() *Router {
	return &Router{router: ((*mux.Route)(route)).Subrouter()}
}
