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

func TestHTTPSServerH2(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/h2", func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "expected HTTP/2, got "+r.Proto, http.StatusHTTPVersionNotSupported)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	addr := "127.0.0.1:18444"
	server := NewServer().Addr(addr).Handler(mux).TLSServerCert("test_certs/tls.crt", "test_certs/tls.key")
	go server.ListenAndServe()
	defer server.Close()

	client := NewH2Client().TLSRootCerts("test_certs", false)
	err := client.Get(context.Background(), "https://localhost:18444/h2", nil)
	assert.NoError(t, err)
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
	assert.Error(t, err) // cert has been revoked
	server.setCRL(nil, time.Now().Add(-10*time.Second), true)
	err = c.Get(context.Background(), "https://localhost"+addr+"/b", nil)
	assert.Error(t, err) //revocation list out of date
	server.setCRL(nil, time.Time{}, false)
	err = c.Get(context.Background(), "https://localhost"+addr+"/b", nil)
	assert.NoError(t, err)
}
func TestHTTPSServerNoOOP(t *testing.T) {
	ListenAndServeTLS(":-1", "test_certs/tls.crt", "test_certs/tls.key", nil)
	ListenAndServeMTLS(":-1", "test_certs/tls.crt", "test_certs/tls.key", "test_certs", false, nil)
}
