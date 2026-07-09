// Copyright 2021-2025 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestNoRouteMatch_SubrouterRealPrefix_WrongMethod_Returns405(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	s := r.PathPrefix("/api/v1").Subrouter()
	s.HandleFunc("/notify", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/notify", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusMethodNotAllowed, rr.Code)
	assert.Equal("POST", rr.Header().Get("Allow"))
}

func TestNoRouteMatch_SubrouterRootPrefix_WrongMethod_Returns405(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	s := r.PathPrefix("/").Subrouter()
	s.HandleFunc("/nnef-location/v1/event-notify", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPatch, "/nnef-location/v1/event-notify", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusMethodNotAllowed, rr.Code)
	assert.Equal("POST", rr.Header().Get("Allow"))
}

func TestNoRouteMatch_NestedSubrouters_WrongMethod_Returns405(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	outer := r.PathPrefix("/3gpp-monitoring-event/v1").Subrouter()
	inner := outer.PathPrefix("/{afId}").Subrouter()
	inner.HandleFunc("/subscriptions", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPut, "/3gpp-monitoring-event/v1/afid/subscriptions", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusMethodNotAllowed, rr.Code)
	assert.Equal("POST", rr.Header().Get("Allow"))
}

func TestNoRouteMatch_FlatRoute_WrongMethod_Returns405WithAllow(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/foo", okHandler).Methods(http.MethodGet, http.MethodPost)

	req := httptest.NewRequest(http.MethodDelete, "/foo", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusMethodNotAllowed, rr.Code)
	assert.Equal("GET, POST", rr.Header().Get("Allow"))
}

func TestNoRouteMatch_UnknownPath_Returns404(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/foo", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPost, "/bar", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusNotFound, rr.Code)
}

func TestNoRouteMatch_CustomNotFoundHandler_InvokedForGenuine404(t *testing.T) {
	assert := assert.New(t)

	customBody := "custom not found"
	r := NewRouter().NotFoundHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(customBody))
	}))
	r.HandleFunc("/foo", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPost, "/bar", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusNotFound, rr.Code)
	assert.Equal(customBody, rr.Body.String())
}

func TestNoRouteMatch_CustomNotFoundHandler_NotInvokedForWrongMethod(t *testing.T) {
	assert := assert.New(t)

	customBody := "custom not found"
	r := NewRouter().NotFoundHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(customBody))
	}))
	r.HandleFunc("/foo", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusMethodNotAllowed, rr.Code)
	assert.Empty(rr.Body.String())
}

func TestNoRouteMatch_ValidRequest_Returns200(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	s := r.PathPrefix("/").Subrouter()
	s.HandleFunc("/notify", okHandler).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPost, "/notify", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(http.StatusOK, rr.Code)
}
