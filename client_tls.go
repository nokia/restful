// Copyright 2021-2024 Nokia
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
		if isTraced {
			c.Client.Transport = otelhttp.NewTransport(&http.Transport{TLSClientConfig: tlsConfig})
		} else {
			c.Client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
		}
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

// NewCertPool adds PEM certificates from given path in a way that is usable at TLS() as RootCAs.
// If path is a directory then scans for files recursively. If path is not set then defaults to /etc.
// If loadSystemCerts is true, the given client certificates are complemented with system root certificates.
// File name should match *.crt or *.pem.
func NewCertPool(path string, loadSystemCerts bool) *x509.CertPool {
	pool, err := initialCertPool(loadSystemCerts)
	if err != nil {
		log.Fatalf("Failed to init certificate pool: %v", err)
	}

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

	err = filepath.Walk(path, walkFn)
	if err != nil {
		log.Errorf("Error finding CA files at '%s': %v", path, err)
	}

	return pool
}

func initialCertPool(loadSystemCerts bool) (*x509.CertPool, error) {
	if loadSystemCerts {
		return x509.SystemCertPool()
	}
	return x509.NewCertPool(), nil
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
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12 // TLS 1.2 is the minimum supported.
	}

	return transport.TLSClientConfig
}

// TLSRootCerts loads PEM certificates from given path and sets TLS config accordingly.
// Cert can be Root CA or self-signed server cert, so that client can authenticate servers.
// If loadSystemCerts is true, the client accepts server CAs from system settings, too.
// If path is a directory then scans for files recursively. If path is not set then defaults to /etc.
// File name should match *.crt or *.pem.
func (c *Client) TLSRootCerts(path string, loadSystemCerts bool) *Client {
	c.haveTLSClientConfig().RootCAs = NewCertPool(path, loadSystemCerts)
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

// SetTLSMinVersion sets the minimum TLS version for the client.
// The tlsMinVersion parameter specifies the minimum version of TLS that is acceptable.
// It returns the client instance to allow for method chaining.
//
// Parameters:
//   - tlsMinVersion: The minimum TLS version to be set.
//
// Returns:
//   - *Client: The client instance with the updated TLS minimum version.
func (c *Client) SetTLSMinVersion(tlsMinVersion uint16) *Client {
	c.haveTLSClientConfig().MinVersion = tlsMinVersion
	return c
}

// SetTLSMaxVersion sets the maximum TLS version for the client.
// The tlsMaxVersion parameter specifies the maximum version of TLS that is acceptable.
// It returns the client instance to allow for method chaining.
//
// Parameters:
//   - tlsMaxVersion: The maximum TLS version to be set.
//
// Returns:
//   - *Client: The client instance with the updated TLS maximum version.
func (c *Client) SetTLSMaxVersion(tlsMaxVersion uint16) *Client {
	c.haveTLSClientConfig().MaxVersion = tlsMaxVersion
	return c
}

// SetCipherSuites sets the list of cipher suites for the client.
// The cipherSuites parameter specifies the list of cipher suites to be used.
// It returns the client instance to allow for method chaining.
//
// Parameters:
//   - cipherSuites: The list of cipher suites to be set.
//
// Returns:
//   - *Client: The client instance with the updated cipher suites.
func (c *Client) SetCipherSuites(cipherSuites []uint16) *Client {
	c.haveTLSClientConfig().CipherSuites = cipherSuites
	return c
}
