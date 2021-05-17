// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type strint struct {
	S string
	I int
}

func dupCtx(ctx context.Context, si strint) (strint, error) {
	ssii := strint{S: si.S + si.S, I: si.I * 2}
	L(ctx).ResponseHeaderAdd("request-method", L(ctx).RequestMethod())
	L(ctx).ResponseHeaderAdd("request-url", L(ctx).RequestURL().String())
	L(ctx).ResponseHeaderAdd("request-path-id", L(ctx).RequestPathParameters()["id"])
	L(ctx).ResponseHeaderAdd("request-content-type", L(ctx).RequestHeaderGet("content-type"))
	L(ctx).ResponseHeaderSet("hello", "world")

	//lint:ignore SA1008 this header name is intentionally non-canonical
	if _, ok := L(ctx).RequestHeader()["CONTENT-TYPE"]; ok {
		return ssii, errors.New("should not be present all capitalized, even though legal")
	}

	return ssii, nil
}

func ctxOnly(ctx context.Context) error {
	L(ctx).ResponseHeaderAdd("request-method", L(ctx).RequestMethod())
	L(ctx).ResponseHeaderAdd("request-path-id", L(ctx).RequestPathParameters()["id"])
	L(ctx).ResponseHeaderAddAs("request-param-q", L(ctx).RequestQueryStringParameter("q"))
	L(ctx).ResponseHeaderSet("hello", "world")
	return nil
}

func dup(si strint) (strint, error) {
	ssii := strint{S: si.S + si.S, I: si.I * 2}
	return ssii, nil
}

func ptr(si *strint) (*strint, error) {
	ssii := strint{S: si.S + si.S, I: si.I * 2}
	return &ssii, nil
}

func err(si *strint) (*strint, error) {
	return nil, NewError(errors.New("err"), 409, "pretty confused")
}

func nop() error {
	return nil
}

func htp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(204)
}

func TestNonContext(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/dup", dup).Methods(http.MethodHead, http.MethodPost, http.MethodPut)
	r.HandleFunc("/ptr", ptr).Methods(http.MethodGet)
	r.HandleFunc("/err", err)
	r.HandleFunc("/nop", nop)
	r.HandleFunc("/htp", htp)

	reqBody := []byte(`{"s":"s","i":2}`)

	{ // Scalar
		req, err := http.NewRequest("POST", "/dup", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		assert.Nil(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		respBody := rr.Body.String()
		assert.Equal(200, rr.Code)
		assert.Equal(`{"S":"ss","I":4}`, respBody)
	}
	{ // Scalar bad method
		req, err := http.NewRequest("GET", "/dup", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		assert.Nil(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		respBody := rr.Body.String()
		assert.Equal(405, rr.Code)
		assert.Equal(``, respBody)
	}
	{ // Pointer
		req, err := http.NewRequest("GET", "/ptr", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		assert.Nil(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		respBody := rr.Body.String()
		assert.Equal(200, rr.Code)
		assert.Equal(`{"S":"ss","I":4}`, respBody)
	}
	{ // Error
		req, err := http.NewRequest("POST", "/err", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		assert.Nil(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		respBody := rr.Body.String()
		assert.Equal(409, rr.Code)
		assert.Contains(respBody, `pretty confused`)
	}
	{ // Nop
		req, err := http.NewRequest("GET", "/nop", nil)
		assert.Nil(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(204, rr.Code)
	}
	{ // HTTP, not lambda
		req, err := http.NewRequest("GET", "/htp", nil)
		assert.Nil(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(204, rr.Code)
	}
}

func TestContext(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	route := r.Methods(http.MethodPost).Name("Hello").Path("/context/{id:[0-9]+}").Schemes("http").HandlerFunc(dupCtx)
	assert.NoError(route.GetError())

	{ // Context
		reqBody := []byte(`{"s":"s","i":2}`)
		req, err := http.NewRequest("POST", "/context/42", bytes.NewReader(reqBody))
		assert.NoError(err)
		req.Header.Set("Content-Type", "application/json")
		req.URL.RawQuery = "q=hello%20world"
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		respBody := rr.Body.String()
		assert.Equal(200, rr.Code)
		assert.Equal("world", rr.Header().Get("hello"))
		assert.Equal("application/json", rr.Header().Get("Request-Content-Type"))
		assert.Equal("POST", rr.Header().Get("Request-method"))
		assert.Contains(rr.Header().Get("Request-URL"), "/context/42?q=hello%20world")
		assert.Equal("42", rr.Header().Get("Request-path-id"))
		assert.Equal(`{"S":"ss","I":4}`, respBody)
	}
	{ // Context; without http layer
		headers := make(http.Header)
		headers.Set("Content-type", "application/json")
		vars := make(map[string]string)
		vars["id"] = "42"
		ctx := NewTestCtx("POST", "/context/42", headers, vars)
		resp, err := dupCtx(ctx, strint{S: "s", I: 2})
		assert.NoError(err)
		assert.Equal("application/json", L(ctx).ResponseHeader().Get("Request-Content-Type"))
		assert.Equal("POST", L(ctx).ResponseHeader().Get("Request-Method"))
		assert.Equal("42", L(ctx).ResponseHeader().Get("Request-Path-Id"))
		assert.Equal("ss", resp.S)
		assert.Equal(4, resp.I)
	}
}

func TestContextOnly(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/context/{id}", ctxOnly).Methods(http.MethodPost)

	{ // Context-only
		req, err := http.NewRequest("POST", "/context/42", nil)
		assert.NoError(err)
		req.URL.RawQuery = "q=hello%20world"
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		respBody := rr.Body.String()
		assert.Equal(204, rr.Code)
		assert.Equal("POST", rr.Header().Get("Request-method"))
		assert.Equal("hello world", rr.Header()["request-param-q"][0]) //lint:ignore SA1008 I want to check non-canonical stuff.
		assert.Equal("42", rr.Header().Get("Request-path-id"))
		assert.Equal(``, respBody)
	}
	{ // Context-only; without http layer
		vars := make(map[string]string)
		vars["id"] = "42"
		ctx := NewTestCtx("POST", "/context/42?q=hello%20world", nil, vars)
		err := ctxOnly(ctx)
		assert.NoError(err)
		assert.Equal("POST", L(ctx).ResponseHeader().Get("Request-Method"))
		assert.Equal("hello world", L(ctx).ResponseHeader()["request-param-q"][0]) //lint:ignore SA1008 I want to check non-canonical stuff.
		assert.Equal("42", L(ctx).ResponseHeader().Get("Request-Path-Id"))
	}
}

func TestContextTracing(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	assert := assert.New(t)
	traceparent := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recvdTraceparent := r.Header.Get("traceparent")
		assert.Equal(55, len(traceparent))
		assert.Contains(recvdTraceparent, traceparent[0:35])
		assert.NotEqual(traceparent, recvdTraceparent)
		assert.Equal("margit=neni", r.Header.Get("tracestate"))
		w.WriteHeader(204)
	}))
	defer srv.Close()

	r := NewRouter()
	r.HandleFunc("/myapi", func(ctx context.Context, si strint) error {
		assert.Nil(Get(ctx, srv.URL, nil))
		return nil
	})

	reqBody := []byte(`{"s":"s","i":2}`)
	req, err := http.NewRequest("POST", "/myapi", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", traceparent)
	req.Header.Set("tracestate", "margit=neni")
	assert.Nil(err)
	rr := httptest.NewRecorder()
	l := Logger(r)
	l.ServeHTTP(rr, req)
	assert.Equal(204, rr.Code)
}

func TestDefaultRouter(t *testing.T) {
	assert := assert.New(t)

	HandleFunc("/dup", dup)

	reqBody := []byte(`{"s":"s","i":2}`)
	req, err := http.NewRequest("POST", "/dup", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	assert.Nil(err)
	rr := httptest.NewRecorder()
	DefaultServeMux.router.ServeHTTP(rr, req)
	respBody := rr.Body.String()
	assert.Equal(200, rr.Code)
	assert.Equal(`{"S":"ss","I":4}`, respBody)
}

func TestBadCT(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/dup", dup)

	reqBody := []byte(`{"s":"s","i":2}`)
	req, err := http.NewRequest("POST", "/dup", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/funny")
	req.Header.Set("Accept", "application/funny")
	req.Header.Add("Accept", "application/problem+json")
	req.Header.Add("Accept", "application/json")
	assert.Nil(err)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	respBody := rr.Body.String()
	assert.Equal(400, rr.Code)
	assert.NotEmpty(rr.Header().Get("Content-type"))
	assert.Contains(respBody, `"unexpected`)
}

func TestRouterGarbage(t *testing.T) {
	assert.Panics(t, func() { NewRouter().HandleFunc("", t) })
	r := NewRouter()
	r.Host("")
	r.Name("bela")
	r.Path("/path")
	r.PathPrefix("/path/")
	r.Schemes("http")
	assert.NotNil(t, r.Get("bela"))
}

func TestRouteGarbage(t *testing.T) {
	assert.Panics(t, func() { NewRouter().Methods().PathPrefix("").HandlerFunc(t) })
}
