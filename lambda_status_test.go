// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ret0(ctx context.Context) {
	L(ctx).ResponseStatus(202)
}

func ret1(ctx context.Context) error {
	L(ctx).ResponseStatus(202)
	return nil
}

func ret2p(ctx context.Context) (*strType, error) {
	L(ctx).ResponseStatus(202)
	return nil, nil
}

func ret2i(ctx context.Context) (int, error) {
	L(ctx).ResponseStatus(202)
	return 42, nil
}

func TestStatus(t *testing.T) {
	assert := assert.New(t)

	r := NewRouter()
	r.HandleFunc("/ret0", ret0)
	r.HandleFunc("/ret1", ret1)
	r.HandleFunc("/ret2p", ret2p)
	r.HandleFunc("/ret2i", ret2i)

	{
		req, err := http.NewRequest("GET", "/ret0", nil)
		assert.NoError(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(202, rr.Code)
		assert.Equal(0, rr.Body.Len())
		assert.Equal("", rr.Header().Get("content-type"))
	}
	{
		req, err := http.NewRequest("GET", "/ret1", nil)
		assert.NoError(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(202, rr.Code)
		assert.Equal(0, rr.Body.Len())
		assert.Equal("", rr.Header().Get("content-type"))
	}
	{
		req, err := http.NewRequest("GET", "/ret2p", nil)
		assert.NoError(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(202, rr.Code)
		assert.Equal(0, rr.Body.Len())
		assert.Equal("", rr.Header().Get("content-type"))
	}
	{
		req, err := http.NewRequest("GET", "/ret2i", nil)
		assert.NoError(err)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(202, rr.Code)
		assert.Equal("42", rr.Body.String())
		assert.Equal("application/json", rr.Header().Get("content-type"))
	}
}
