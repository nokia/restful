// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendResponse(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://me/path")
		var a structType
		a.Str = "hello"
		SendJSONResponse(w, 201, &a, true)
	})))
	defer srv.Close()

	var a strType
	resp, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, nil, &a)
	assert.Nil(err)
	assert.Equal(http.StatusCreated, resp.StatusCode)
	assert.Equal("application/json", resp.Header.Get("Content-type"))
	location, err := resp.Location()
	assert.Nil(err)
	assert.NotNil(location)
	assert.Equal("https://me/path", location.String())
	assert.Equal("hello", a.Str)
	assert.Equal(int64(15), resp.ContentLength)
}

func TestSendEmptyResponse(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://me")
		SendEmptyResponse(w, 200)
	}))
	defer srv.Close()

	resp, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, nil, nil)
	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	assert.Equal("https://me", resp.Header.Get("Location"))
	assert.Equal(int64(0), resp.ContentLength)
}

func TestSendLocationResponse(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SendLocationResponse(w, "https://me")
	}))
	defer srv.Close()

	resp, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, nil, nil)
	assert.Nil(err)
	assert.Equal(http.StatusCreated, resp.StatusCode)
	assert.Equal("https://me", resp.Header.Get("Location"))
	assert.Equal(int64(0), resp.ContentLength)
}

func TestSendRespEmbeddedError(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := NewError(errors.New("embedded"), 400, "error")
		SendResp(w, r, err, nil)
	})))
	defer srv.Close()

	err := NewClient().Get(context.Background(), srv.URL, nil)
	assert.Equal(`{"detail":"error: embedded"}`, err.Error())
}

func TestSendRespCustomError(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invalidParam := InvalidParam{Param: "name", Reason: "missing"}
		body, err := json.Marshal(invalidParam)
		assert.NoError(err)
		assert.Equal(ContentTypeApplicationJSON, r.Header.Get("Accept"))

		err = NewErrorWithBody(nil, http.StatusBadRequest, ContentTypeApplicationJSON, body)
		assert.True(acceptContentType(r, ContentTypeApplicationJSON))
		SendResp(w, r, err, nil)
		assert.Equal(ContentTypeApplicationJSON, w.Header().Get("content-type"))
	})))
	defer srv.Close()

	err := NewClient().Get(context.Background(), srv.URL, nil)
	assert.Equal(http.StatusBadRequest, GetErrStatusCode(err))
	contentType, body := GetErrBody(err)
	assert.Equal(ContentTypeApplicationJSON, contentType)
	assert.Equal(`{"param":"name","reason":"missing"}`, string(body))
}

func TestSendRespCustomErrorCTAny(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invalidParam := InvalidParam{Param: "name", Reason: "missing"}
		body, err := json.Marshal(invalidParam)
		assert.NoError(err)
		r.Header.Set(AcceptHeader, ContentTypeAny)

		err = NewErrorWithBody(nil, http.StatusBadRequest, ContentTypeApplicationJSON, body)
		assert.True(acceptContentType(r, ContentTypeApplicationJSON))
		SendResp(w, r, err, nil)
		assert.Equal(ContentTypeApplicationJSON, w.Header().Get("content-type"))
	})))
	defer srv.Close()

	err := NewClient().Get(context.Background(), srv.URL, nil)
	assert.Equal(http.StatusBadRequest, GetErrStatusCode(err))
	contentType, body := GetErrBody(err)
	assert.Equal(ContentTypeApplicationJSON, contentType)
	assert.Equal(`{"param":"name","reason":"missing"}`, string(body))
}

func TestSendRespCustomErrorWithoutAccept(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invalidParam := InvalidParam{Param: "name", Reason: "missing"}
		body, err := json.Marshal(invalidParam)
		assert.NoError(err)
		r.Header.Del("Accept")

		err = NewErrorWithBody(nil, http.StatusBadRequest, ContentTypeApplicationJSON, body)
		assert.True(acceptContentType(r, ContentTypeApplicationJSON))
		SendResp(w, r, err, nil)
		assert.Equal(ContentTypeApplicationJSON, w.Header().Get("content-type"))
	})))
	defer srv.Close()

	err := NewClient().Get(context.Background(), srv.URL, nil)
	assert.Equal(http.StatusBadRequest, GetErrStatusCode(err))
	contentType, body := GetErrBody(err)
	assert.Equal(ContentTypeApplicationJSON, contentType)
	assert.Equal(`{"param":"name","reason":"missing"}`, string(body))
}

func TestSendRespCustomErrorWithoutCT(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invalidParam := InvalidParam{Param: "name", Reason: "missing"}
		body, err := json.Marshal(invalidParam)
		assert.NoError(err)

		err = NewErrorWithBody(nil, http.StatusBadRequest, "", body)
		assert.False(acceptContentType(r, ""))
		SendResp(w, r, err, nil)
		assert.Equal("", w.Header().Get("content-type"))
	})))
	defer srv.Close()

	err := NewClient().Get(context.Background(), srv.URL, nil)
	assert.Equal(http.StatusBadRequest, GetErrStatusCode(err))
	contentType, body := GetErrBody(err)
	assert.Equal("", contentType)
	assert.Equal(``, string(body))
}
