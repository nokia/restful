// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type strType struct {
	Str string
}

type structType struct {
	Str    string `json:"str,omitempty"`
	Struct struct {
		S string            `json:"s,omitempty"`
		A []byte            `json:"a"`
		M map[string]string `json:"m"`
	}
}

func TestMethods(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a strType
		err := GetRequestData(r, 0, &a)
		assert.Nil(err)

		// Answer
		w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"str":"b"}`))
		} else if r.Method == http.MethodHead {
			w.Header().Set("LastModified", "1970-01-01T00:00:00")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		} else if r.Method == http.MethodPost {
			assert.Equal("b", a.Str)
			w.Header().Set("Location", "/users/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"str":"b"}`))
		} else { // PUT / PATCH
			assert.Equal("b", a.Str)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"str":"b"}`))
		}
	}))
	defer srv.Close()

	reqData := strType{Str: "b"}
	respData := strType{}
	ctx := context.Background()
	client := NewClient().Root(srv.URL).SanitizeJSON()
	location, err := client.Post(ctx, "/users", &reqData, &respData)
	assert.Nil(err)
	locationStr := location.String()
	assert.Equal(srv.URL+"/users/1", locationStr)
	assert.EqualValues(reqData, respData)

	_, err = Post(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	_, err = client.Put(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)
	_, err = Put(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	err = client.Patch(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)
	err = Patch(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	err = client.Get(ctx, locationStr, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)
	err = Get(ctx, locationStr, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	headers, err := client.Head(ctx, locationStr)
	assert.Nil(err)
	assert.Equal("1970-01-01T00:00:00", headers["Lastmodified"][0])

	v := url.Values{}
	v.Set("Str", "b")
	_, err = client.PostForm(ctx, "/users", v, &respData)
	assert.NoError(err)
	assert.EqualValues(reqData, respData)

	err = client.Delete(ctx, locationStr)
	assert.Nil(err)
	err = Delete(ctx, locationStr)
	assert.Nil(err)
}

func TestGetTooLongAnswer(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer
		w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"str":"b"}`))
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL)
	client.SetMaxBytesToParse(5) // Small enough
	var empty struct{}
	err := client.Get(context.Background(), "/", &empty)
	assert.NotNil(err)
}

func TestRetry(t *testing.T) {
	assert := assert.New(t)

	// Server
	reqCount := 0
	retries := 4
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("hello", r.Header.Get("User-Agent"))
		if reqCount < retries { // r * fail
			w.WriteHeader(http.StatusGatewayTimeout)
			w.Write([]byte(`{"time" :"` + time.Now().String() + `"}`))
		} else {
			w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"time" :"` + time.Now().String() + `"}`))
		}
		reqCount++
	}))
	defer srv.Close()

	respData := strType{}
	client := NewClient().Root(srv.URL).Retry(retries, 10*time.Millisecond, 0).UserAgent("hello")
	err := client.Get(context.Background(), "/", &respData)
	assert.Nil(err)
	assert.Equal(http.StatusOK, GetErrStatusCode(err))
	assert.Equal(http.StatusOK, GetErrStatusCodeElse(err, 0))
	assert.Equal(retries+1, reqCount)
}

func TestMethodsError(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SendProblemResponse(w, r, http.StatusNotFound, "nope")
	}))
	defer srv.Close()

	reqData := strType{Str: "b"}
	respData := strType{}
	ctx := context.Background()
	client := NewClient().Root(srv.URL).SanitizeJSON()
	client.SetMaxBytesToParse(100000)
	location, err := client.Post(ctx, "/users", &reqData, &respData)
	assert.NotNil(err)
	assert.Nil(location)
	locationStr := "/users/1"

	_, err = client.Put(ctx, locationStr, &reqData, &respData)
	assert.NotNil(err)

	err = client.Patch(ctx, locationStr, &reqData, &respData)
	assert.NotNil(err)

	err = client.Get(ctx, locationStr, &respData)
	assert.NotNil(err)

	_, err = client.Head(ctx, locationStr)
	assert.NotNil(err)

	err = client.Delete(ctx, locationStr)
	assert.NotNil(err)
}

func TestGetBadURL(t *testing.T) {
	assert := assert.New(t)
	respData := strType{}
	err := NewClient().Retry(3000, time.Second, 0).Get(context.Background(), ":::", &respData)
	assert.NotNil(err)
}

func TestGet500(t *testing.T) {
	assert := assert.New(t)
	const problem = `{"title":"Configuration error"}`

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acc := r.Header["Accept"]
		assert.Equal(2, len(acc)) // json and problem+json
		SendResp(w, r, NewError(nil, 500, problem), nil)
	}))
	defer srv.Close()

	err := Get(context.Background(), srv.URL, nil)
	assert.Error(err)
	assert.NotEmpty(err.Error())
	assert.Equal(problem, err.Error())
	assert.Equal(http.StatusInternalServerError, GetErrStatusCode(err))
	assert.Equal(http.StatusInternalServerError, GetErrStatusCodeElse(err, 0))
}

func TestGet500Details(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acc := r.Header["Accept"]
		assert.Equal(2, len(acc)) // json and problem+json
		err := NewDetailedError(nil, 500,
			ProblemDetails{
				Title:         "title",
				Detail:        "descr",
				InvalidParams: map[string]string{"param1": "error text"},
			})

		SendResp(w, r, err, nil)
	}))
	defer srv.Close()

	err := Get(context.Background(), srv.URL, nil)
	assert.Error(err)
	assert.NotEmpty(err.Error())
	assert.Equal("{\"title\":\"title\",\"detail\":\"descr\",\"invalidParams\":{\"param1\":\"error text\"}}", err.Error())
	assert.Equal(http.StatusInternalServerError, GetErrStatusCode(err))
	assert.Equal(http.StatusInternalServerError, GetErrStatusCodeElse(err, 0))
}

func TestSendRecv2xxBadCT(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-type", "nuku")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"str":"b"}`))
	}))
	defer srv.Close()

	var empty struct{}
	_, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, nil, &empty) // Resp body gets parsed.
	assert.NotNil(err)
	assert.Equal(http.StatusInternalServerError, GetErrStatusCode(err)) // Fake error code
	assert.Equal(0, GetErrStatusCodeElse(err, 0))
}

func TestSendRecv2xxNoDataNoCT(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var empty struct{}
	_, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, &empty, &empty) // Req and resp body gets parsed, as not nil.
	assert.Nil(err)
}

func TestH2CFailed(t *testing.T) {
	assert := assert.New(t)
	respData := strType{}
	client := NewH2CClient().Root("http://127.0.0.1:0")
	err := client.Get(context.Background(), "/", &respData)
	assert.NotNil(err)
}

func TestCalcBackoff(t *testing.T) {
	assert := assert.New(t)
	c := NewClient().Retry(255, 1*time.Second, 0)
	assert.Equal((1<<0)*time.Second, c.calcBackoff(0))
	assert.Equal((1<<7)*time.Second, c.calcBackoff(7))
	assert.Equal((1<<7)*time.Second, c.calcBackoff(255))

	c = NewClient().Retry(255, 1*time.Second, 2*time.Second)
	assert.Equal((1<<0)*time.Second, c.calcBackoff(0))
	assert.Equal((1<<1)*time.Second, c.calcBackoff(7))
	assert.Equal((1<<1)*time.Second, c.calcBackoff(255))
}

func TestBroadcastRequest(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.BroadcastRequest(ctx, "GET", "/", nil, nil)
	assert.NoError(err)
}

func TestBroadcastRequestUnknown(t *testing.T) {
	assert := assert.New(t)
	err := NewClient().BroadcastRequest(context.Background(), "GET", "http://", nil, nil)
	assert.Error(err)
}

func TestBroadcastBadURL(t *testing.T) {
	assert := assert.New(t)
	err := NewClient().BroadcastRequest(context.Background(), "GET", ":::-1", nil, nil)
	assert.Error(err)
}
