// Copyright 2021-2026 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSendRecvFirst2xxParallelOK(t *testing.T) {
	assert := assert.New(t)

	type respType struct {
		ID int `json:"id"`
	}

	type reqType struct {
		Hello string `json:"hello"`
	}

	const timeout = 100 * time.Millisecond

	srvs := make([]*httptest.Server, 25)
	srvURLs := make([]string, len(srvs))
	for i := 0; i < len(srvs); i++ {
		srvs[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recvd, err := io.ReadAll(r.Body)
			assert.NoError(err)
			assert.Equal(`{"hello":"Hello"}`, string(recvd))
			id := strings.TrimPrefix(r.URL.Path, "/")
			if id == "1" {
				time.Sleep(2 * timeout)
				w.WriteHeader(http.StatusNotFound)
				t.Log(t.Name(), "- Respond: ", id)
			} else if id[len(id)-1:] == "5" {
				w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id":` + id + `}`))
				t.Log(t.Name(), "+ Respond: ", id)
			} else {
				SendResp(w, r, NewError(nil, http.StatusNotFound, ""), nil)
				t.Log(t.Name(), "- Respond: ", id)
			}
		}))
		defer srvs[i].Close()
		srvURLs[i] = srvs[i].URL + "/" + strconv.FormatInt(int64(i), 10)
		t.Log(t.Name(), "Servers: ", srvURLs[i])
	}

	c := NewClient()
	var respData respType
	reqData := reqType{Hello: "Hello"}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := c.SendRecvListFirst2xxParallel(ctx, "POST", srvURLs, nil, &reqData, &respData)
	assert.NoError(err)
	assert.Equal(200, resp.StatusCode)
	t.Log(t.Name(), ">>> Received: ", respData.ID)
	assert.True(respData.ID >= 0 && respData.ID < len(srvs))
}

func TestSendRecvFirst2xxParallelNoPositive(t *testing.T) {
	assert := assert.New(t)

	const timeout = 100 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient()
	var respData struct{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := c.SendRecvResolveFirst2xxParallel(ctx, "GET", srv.URL, nil, nil, &respData)
	assert.Error(err)
	assert.Nil(resp)
}

func TestSendRecvFirst2xxParallelTimeout(t *testing.T) {
	assert := assert.New(t)

	const timeout = 100 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * timeout)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient()
	var respData struct{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := c.SendRecvResolveFirst2xxParallel(ctx, "GET", srv.URL, nil, nil, &respData)
	assert.Error(err)
	assert.Nil(resp)
}

func TestSendRecvFirst2xxParallelNoTarget(t *testing.T) {
	_, err := NewClient().SendRecvResolveFirst2xxParallel(context.Background(), "GET", "", nil, nil, nil)
	assert.Error(t, err)
}

func TestSendRecvFirst2xxParallelMultiple2xxDoesNotHang(t *testing.T) {
	assert := assert.New(t)

	const n = 12
	srvs := make([]*httptest.Server, n)
	srvURLs := make([]string, n)
	for i := 0; i < n; i++ {
		id := i
		srvs[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":` + strconv.Itoa(id) + `}`))
		}))
		defer srvs[i].Close()
		srvURLs[i] = srvs[i].URL
	}

	c := NewClient()
	headers := http.Header{"X-Test": []string{"parallel"}}

	type respType struct {
		ID int `json:"id"`
	}
	var respData respType

	done := make(chan struct{})
	var resp *http.Response
	var err error
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err = c.SendRecvListFirst2xxParallel(ctx, "GET", srvURLs, headers, nil, &respData)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendRecvListFirst2xxParallel hung with concurrent 2xx responses")
	}

	assert.NoError(err)
	if assert.NotNil(resp) {
		assert.Equal(200, resp.StatusCode)
	}
	assert.True(respData.ID >= 0 && respData.ID < n)
}

func TestSendRecvFirst2xxParallelMixedStatusDoesNotHang(t *testing.T) {
	assert := assert.New(t)

	const n = 8
	srvs := make([]*httptest.Server, n)
	srvURLs := make([]string, n)
	for i := 0; i < n; i++ {
		ok := i%2 == 0
		srvs[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
			if ok {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":1}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"missing"}`))
		}))
		defer srvs[i].Close()
		srvURLs[i] = srvs[i].URL
	}

	c := NewClient()

	var respData struct {
		ID int `json:"id"`
	}

	done := make(chan struct{})
	var resp *http.Response
	var err error
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err = c.SendRecvListFirst2xxParallel(ctx, "GET", srvURLs, nil, nil, &respData)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendRecvListFirst2xxParallel hung with mixed 2xx and non-2xx responses")
	}

	assert.NoError(err)
	if assert.NotNil(resp) {
		assert.Equal(200, resp.StatusCode)
	}
	assert.Equal(1, respData.ID)
}

func TestTarget2URLs_IPv6WithPort(t *testing.T) {
	orig := netLookupIP
	netLookupIP = func(host string) ([]net.IP, error) {
		assert.Equal(t, "example.com", host)
		return []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}, nil
	}
	defer func() { netLookupIP = orig }()

	got, err := NewClient().target2URLs("http://example.com:8080/path?q=1")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"http://[2001:db8::1]:8080/path?q=1",
		"http://[2001:db8::2]:8080/path?q=1",
	}, got)
}

func TestTarget2URLs_IPv6NoPort(t *testing.T) {
	orig := netLookupIP
	netLookupIP = func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}, nil
	}
	defer func() { netLookupIP = orig }()

	got, err := NewClient().target2URLs("http://example.com/path")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"http://[2001:db8::1]/path",
		"http://[2001:db8::2]/path",
	}, got)
}

func TestTarget2URLs_IPv4WithPort(t *testing.T) {
	orig := netLookupIP
	netLookupIP = func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, nil
	}
	defer func() { netLookupIP = orig }()

	got, err := NewClient().target2URLs("http://example.com:8080/path")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"http://192.0.2.1:8080/path",
		"http://192.0.2.2:8080/path",
	}, got)
}
