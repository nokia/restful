// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"io"
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
