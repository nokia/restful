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

	"github.com/stretchr/testify/assert"
)

func TestSendRecvFirst2xxSequentialOK(t *testing.T) {
	assert := assert.New(t)

	type respType struct {
		ID int `json:"id"`
	}

	type reqType struct {
		Hello string `json:"hello"`
	}

	srvs := make([]*httptest.Server, 5)
	srvURLs := make([]string, len(srvs))
	for i := 0; i < len(srvs); i++ {
		srvs[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recvd, err := io.ReadAll(r.Body)
			assert.NoError(err)
			assert.Equal(`{"hello":"Hello"}`, string(recvd))
			id := strings.TrimPrefix(r.URL.Path, "/")
			if id == "3" {
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
	ctx := context.Background()
	resp, err := c.SendRecvListFirst2xxSequential(ctx, "POST", srvURLs, nil, &reqData, &respData)
	assert.NoError(err)
	assert.Equal(200, resp.StatusCode)
	t.Log(t.Name(), ">>> Received: ", respData.ID)
	assert.Equal(3, respData.ID)
}

func TestSendRecvFirst2xxSequentialNoPositive(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SendResp(w, r, NewError(nil, http.StatusNotFound, ""), nil)
	}))
	defer srv.Close()

	c := NewClient()
	var respData struct{}
	ctx := context.Background()
	_, err := c.SendRecvListFirst2xxSequential(ctx, "GET", []string{srv.URL, srv.URL}, nil, nil, &respData)
	assert.Error(err)
	_, err = c.SendRecvResolveFirst2xxSequential(ctx, "GET", srv.URL, nil, nil, &respData)
	assert.Error(err)
}
