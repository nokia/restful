// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPSServer(t *testing.T) {
	http.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	addr := ":18443"
	server := NewServer().Addr(addr)
	server.TLSServerCert("test_certs/tls.crt", "test_certs/tls.key")
	server.TLSClientCert("test_certs", false)
	go server.ListenAndServe()
	defer server.Close()

	c := NewClient().TLSRootCerts("test_certs", false)
	err := c.Get(context.Background(), "https://localhost"+addr+"/a", nil)
	assert.Equal(t, 500, GetErrStatusCode(err))

	c.TLSOwnCerts("test_certs")
	err = c.Get(context.Background(), "https://localhost"+addr+"/a", nil)
	assert.Nil(t, err)
}

func TestHTTPSServerCRL(t *testing.T) {
	http.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	addr := ":18443"

	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	ch := make(chan error)
	go func() {
		for {
			err := <-ch
			t.Log(err)
		}
	}()
	server := NewServer().Addr(addr)
	server.TLSServerCert("test_certs/tls.crt", "test_certs/tls.key")
	server.TLSClientCert("test_certs", false)
	opt := CRLOptions{
		Ctx:              ctx,
		StatusChan:       ch,
		CRLLocation:      "test_certs/ca.crl",
		ReadInterval:     time.Minute,
		FileExistTimeout: time.Minute,
	}
	server.CRL(opt)
	go server.ListenAndServe()
	defer server.Close()

	c := NewClient().TLSRootCerts("test_certs", false).TLSOwnCerts("test_certs")

	err := c.Get(context.Background(), "https://localhost"+addr+"/b", nil)
	assert.Error(t, err)
	server.setCRL(nil, time.Time{}, true)
	err = c.Get(context.Background(), "https://localhost"+addr+"/b", nil)
	assert.Error(t, err) //revocation list pass
	server.setCRL(nil, time.Time{}, false)
}
func TestHTTPSServerNoOOP(t *testing.T) {
	ListenAndServeTLS(":-1", "test_certs/tls.crt", "test_certs/tls.key", nil)
	ListenAndServeMTLS(":-1", "test_certs/tls.crt", "test_certs/tls.key", "test_certs", false, nil)
}
