// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	if transport2, ok := c.Client.Transport.(*http2.Transport); ok {
		transport2.TLSClientConfig = tlsConfig
		return c
	}
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

func (c *Client) verifyPeerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificate provided")
	}

	// Parse leaf certificate
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %v", err)
	}

	// Parse intermediates (if any)
	intermediates := x509.NewCertPool()
	for _, certDER := range rawCerts[1:] {
		if cert, err := x509.ParseCertificate(certDER); err == nil {
			intermediates.AddCert(cert)
		}
	}

	// Prepare verification options
	opts := x509.VerifyOptions{
		Roots: c.haveTLSClientConfig().RootCAs,
	}
	if c.haveTLSClientConfig().ServerName != "" {
		opts.DNSName = c.haveTLSClientConfig().ServerName // enables hostname verification
	}

	// Run standard cert verification
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	if c.crl != nil {
		c.crlMu.RLock()
		defer c.crlMu.RUnlock()

		// Check revocation
		if _, ok := c.crl[leaf.SerialNumber.String()]; ok {
			return fmt.Errorf("certificate %s is revoked", leaf.SerialNumber.String())
		}
	}

	return nil
}

// CRL sets the CRL (Certificate Revocation List) path used by the client
// Peer certificates are checked against this list when it's set.
// The file can be PEM encoded or straight ASN.1 DER encoded
func (c *Client) CRL(path string) error {
	crlBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read CRL: %v", err)
	}

	// Handle optional PEM decoding
	if block, _ := pem.Decode(crlBytes); block != nil {
		crlBytes = block.Bytes
	}
	revList, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return err
	}

	c.crlMu.Lock()
	defer c.crlMu.Unlock()

	c.crl = make(map[string]struct{})
	for _, rc := range revList.RevokedCertificateEntries {
		c.crl[rc.SerialNumber.String()] = struct{}{}
	}
	c.haveTLSClientConfig().VerifyPeerCertificate = c.verifyPeerCert

	return nil

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
			transport2.TLSClientConfig = &tls.Config{
				MinVersion:            tls.VersionTLS12,
				VerifyPeerCertificate: c.verifyPeerCert,
			}
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
		transport.TLSClientConfig = &tls.Config{
			VerifyPeerCertificate: c.verifyPeerCert,
		} // #nosec G402 -- false positive, see below
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
