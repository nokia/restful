// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPSServer(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	addr := ":18443"
	server := NewServer().Addr(addr)
	server.TLSServerCert("test_certs/tls.crt", "test_certs/tls.key")
	server.TLSClientCert("test_certs", false)
	go server.ListenAndServe()

	c := NewClient().TLSRootCerts("test_certs", false)
	err := c.Get(context.Background(), "https://localhost"+addr, nil)
	assert.Equal(t, 500, GetErrStatusCode(err))

	c.TLSOwnCerts("test_certs")
	err = c.Get(context.Background(), "https://localhost"+addr, nil)
	assert.Nil(t, err)
	server.Close()
}

func TestHTTPSServerNoOOP(t *testing.T) {
	ListenAndServeTLS(":-1", "test_certs/tls.crt", "test_certs/tls.key", nil)
	ListenAndServeMTLS(":-1", "test_certs/tls.crt", "test_certs/tls.key", "test_certs", false, nil)
}
