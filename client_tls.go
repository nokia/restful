// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
)

// TLS sets TLS setting for client. Returns object instance, just in case you need that.
// Use if specific config is needed, e.g. server cert or whether to accept untrusted certs.
// You may use it this way: client := New().TLS(...) or just client.TLS(...)
func (c *Client) TLS(tlsConfig *tls.Config) *Client {
	if transport, ok := c.Client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = tlsConfig
	} else {
		c.Client.Transport = otelhttp.NewTransport(&http.Transport{TLSClientConfig: tlsConfig})
	}
	return c
}

func appendCert(path string, pool *x509.CertPool) {
	pem, err := os.ReadFile(path) // #nosec
	if err != nil {
		log.Errorf("Error reading CA from '%s': %v", path, err)
		return
	}
	if !pool.AppendCertsFromPEM(pem) {
		log.Errorf("Error parsing CA at '%s': %v", path, err)
	}
	log.Debugf("Appended cert from '%s'", path)
}

// NewCertPool loads PEM certificates from given path and returns them in a way that is usable at TLS() as RootCAs.
// If path is a directory then scans for files recursively. If path is not set then defaults to /etc.
// File name should match *.crt or *.pem.
func NewCertPool(path string) *x509.CertPool {
	pool := x509.NewCertPool()

	if path == "" {
		path = "/etc"
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(info.Name()))
			if ext == ".pem" || ext == ".crt" {
				appendCert(path, pool)
			}
		}
		return err
	}

	err := filepath.Walk(path, walkFn)
	if err != nil {
		log.Errorf("Error finding CA files at '%s': %v", path, err)
	}

	return pool
}

func (c *Client) haveTLSClientConfig() *tls.Config {
	// HTTP2
	if transport2, ok := c.Client.Transport.(*http2.Transport); ok {
		if transport2.TLSClientConfig == nil {
			transport2.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return transport2.TLSClientConfig
	}

	// HTTP 1.x
	transport, ok := c.Client.Transport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
		c.Client.Transport = transport
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{} // #nosec G402 -- false positive, see below
	}

	transport.TLSClientConfig.MinVersion = tls.VersionTLS12 // TLS 1.2 is the minimum supported.

	return transport.TLSClientConfig
}

// TLSRootCerts loads PEM certificates from given path and sets TLS config accordingly.
// Cert can be Root CA or self-signed server cert, so that client can authenticate servers.
// If path is a directory then scans for files recursively. If path is not set then defaults to /etc.
// File name should match *.crt or *.pem.
func (c *Client) TLSRootCerts(path string) *Client {
	c.haveTLSClientConfig().RootCAs = NewCertPool(path)
	return c
}

// TLSOwnCerts loads PEM certificate + key from given directory and sets TLS config accordingly.
// Cert + key is used at mutual TLS (mTLS) connection when client authenticates itself.
// File names should be tls.crt and tls.key (see `kubectl create secret tls`).
func (c *Client) TLSOwnCerts(dir string) *Client {
	cert, err := tls.LoadX509KeyPair(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		log.Errorf("Cannot load client cert+key: %v", err)
	} else {
		c.haveTLSClientConfig().Certificates = []tls.Certificate{cert}
	}
	return c
}

// Insecure makes client skip server name checking.
func (c *Client) Insecure() *Client {
	c.haveTLSClientConfig().InsecureSkipVerify = true
	return c
}
