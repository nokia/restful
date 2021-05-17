// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type abs struct {
	A string
	B []string
}

func TestDataGetQuery(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ab abs
		GetRequestData(r, 0, &ab)
		assert.Equal("a", ab.A)
		assert.Equal("b", ab.B[0])
		assert.Equal("B", ab.B[1])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Client
	{
		req, err := http.NewRequest("GET", srv.URL, nil)
		assert.Nil(err)
		q := url.Values{"a": {"a"}, "b": {"b", "B"}}
		req.URL.RawQuery = q.Encode()
		_, err = NewClient().Do(context.Background(), req)
		assert.Nil(err)
	}
}

func TestDataPostForm(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ab abs
		GetRequestData(r, 0, &ab)
		assert.Equal("a", ab.A)
		assert.Equal("b", ab.B[0])
		assert.Equal("B", ab.B[1])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Client
	{
		f := url.Values{"a": {"a"}, "b": {"b", "B"}}
		req, err := http.NewRequest("POST", srv.URL, strings.NewReader(f.Encode()))
		assert.Nil(err)
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
		_, err = NewClient().Do(context.Background(), req)
		assert.Nil(err)
	}
}
