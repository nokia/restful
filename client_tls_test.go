// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testCertSerial = "1000"

func TestHTTPS(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cert, err := tls.LoadX509KeyPair("test_certs/tls.crt", "test_certs/tls.key")
	assert.Nil(err)
	srv.TLS.Certificates = []tls.Certificate{cert}
	srv.URL = strings.ReplaceAll(srv.URL, "127.0.0.1", "localhost")
	defer srv.Close()

	client := NewClient().Root(srv.URL).TLSRootCerts("test_certs", false).HTTPS(nil)
	err = client.Get(context.Background(), "/NEF", nil)
	assert.Nil(err)
}

func TestHTTPSMTLS(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cert, err := tls.LoadX509KeyPair("test_certs/tls.crt", "test_certs/tls.key")
	assert.Nil(err)
	srv.TLS.Certificates = []tls.Certificate{cert}
	srv.TLS.ClientCAs = NewCertPool("test_certs", true)
	srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert

	srv.URL = strings.ReplaceAll(srv.URL, "127.0.0.1", "localhost")
	defer srv.Close()

	assert.NoError(NewClient().Root(srv.URL).TLSRootCerts("test_certs", false).TLSOwnCerts("test_certs").Get(context.Background(), "/NEF", nil)) // Own cert set
	assert.Error(NewClient().Root(srv.URL).TLSRootCerts("test_certs", false).Get(context.Background(), "/NEF", nil))                             // Own cert not set
}

func TestClientCertificateRevoked(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cert, err := tls.LoadX509KeyPair("test_certs/tls.crt", "test_certs/tls.key")
	assert.Nil(err)
	srv.TLS.Certificates = []tls.Certificate{cert}
	srv.TLS.ClientCAs = NewCertPool("test_certs", true)
	srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert

	srv.URL = strings.ReplaceAll(srv.URL, "127.0.0.1", "localhost")
	defer srv.Close()
	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	ch := make(chan error)
	opt := CRLOptions{
		Ctx:              ctx,
		ErrChan:          ch,
		CRLLocation:      "test_certs/ca.crl",
		ReadInterval:     time.Minute,
		FileExistTimeout: time.Minute,
	}
	c := NewClient().Root(srv.URL).TLSRootCerts("test_certs", false).TLSOwnCerts("test_certs").CRL(opt)

	err = c.Get(context.Background(), "/NEF", nil)

	assert.Error(err) // Own cert set
	assert.Contains(err.Error(), "certificate "+testCertSerial+" is revoked")
	c.setCRL(nil, time.Time{}, false)
	assert.NoError(c.Get(context.Background(), "/NEF", nil))
}

func TestCertificateURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crlBytes, _ := os.ReadFile("test_certs/ca.crl")
		w.Write(crlBytes)
	}))
	defer srv.Close()
	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	opt := CRLOptions{
		Ctx:              ctx,
		CRLLocation:      "test_certs/ca.crl",
		ReadInterval:     time.Minute,
		FileExistTimeout: time.Minute,
	}
	c := NewClient().Root(srv.URL).TLSRootCerts("test_certs", false).TLSOwnCerts("test_certs").CRL(opt)

	assert.Equal(t, map[string]struct{}{"4096": {}}, c.crl.serials)
}

func TestHTTPSMTLSServer(t *testing.T) {
	assert := assert.New(t)

	OwnTLSCert = "test_certs/tls.crt"
	OwnTLSKey = "test_certs/tls.key"
	ClientCAs = "test_certs"
	HandleFunc("/NEF", func() {})
	go StartTLS(false, true, false)
	time.Sleep(10 * time.Millisecond)

	assert.NoError(NewClient().Root("https://127.0.0.1:8443").TLSRootCerts("test_certs", false).TLSOwnCerts("test_certs").Get(context.Background(), "/NEF", nil)) // Own cert set
	assert.Error(NewClient().Root("https://127.0.0.1:8443").TLSRootCerts("test_certs", false).Get(context.Background(), "/NEF", nil))                             // Own cert not set
}

func TestHTTPSInsecure(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("big/nothing", r.Header.Get("Content-type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL).Insecure()
	headers := make(http.Header)
	headers.Set(ContentTypeHeader, "big/nothing")
	_, err := client.SendRecv(context.Background(), http.MethodGet, "/NEF", headers, nil, nil)
	assert.Nil(err)
}

func TestHTTPSCertFail(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewH2Client().Root(srv.URL)
	assert.Equal("h2", client.Kind)
	client.TLS(nil)
	client.TLS(&tls.Config{})
	client.TLSRootCerts("", false)
	client.TLSRootCerts("/nonexisting", false)
	client.TLSRootCerts(".", false) // finds ./test_certs/
	client.TLSOwnCerts("/nonexisting")
	client.TLSOwnCerts("./test_certs")
	err := client.Get(context.Background(), "/NEF", nil)
	assert.NotNil(err)
	_, err = client.SendRecv(context.Background(), http.MethodGet, "/NEF", nil, nil, nil)
	assert.NotNil(err)
}

func TestAppendCert(t *testing.T) {
	appendCert("kutyafüle", nil)
	appendCert("client_tls_test.go", nil)
}
