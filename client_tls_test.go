// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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

func TestSetCipherSuites(t *testing.T) {
	assert := assert.New(t)

	client := NewClient()
	cipherSuites := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	client.SetCipherSuites(cipherSuites)

	tlsConfig := client.haveTLSClientConfig()
	assert.Equal(cipherSuites, tlsConfig.CipherSuites)
}

func TestSetTLSMaxVersion(t *testing.T) {
	assert := assert.New(t)

	client := NewClient()
	maxVersion := uint16(tls.VersionTLS13)
	client.SetTLSMaxVersion(maxVersion)

	tlsConfig := client.haveTLSClientConfig()
	assert.Equal(maxVersion, tlsConfig.MaxVersion)
}

func TestSetTLSMinVersion(t *testing.T) {
	assert := assert.New(t)

	client := NewClient()
	minVersion := uint16(tls.VersionTLS12)
	client.SetTLSMinVersion(minVersion)

	tlsConfig := client.haveTLSClientConfig()
	assert.Equal(minVersion, tlsConfig.MinVersion)
}
