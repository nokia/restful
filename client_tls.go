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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// TLS sets TLS setting for client. Returns object instance, just in case you need that.
// Use if specific config is needed, e.g. server cert or whether to accept untrusted certs.
// You may use it this way: client := New().TLS(...) or just client.TLS(...)
func (c *Client) TLS(tlsConfig *tls.Config) *Client {
	// Transport settings are stored in nonTracedTransport, as OTEL's wrapper does not allow retrieving the original transport settings.
	if transport2, ok := c.nonTracedTransport.(*http2.Transport); ok {
		transport2.TLSClientConfig = tlsConfig
	} else if transport1, ok := c.nonTracedTransport.(*http.Transport); ok {
		transport1.TLSClientConfig = tlsConfig
	} else { // most probably nil
		c.SetTransport(&http.Transport{TLSClientConfig: tlsConfig})
	}
	return c
}

// CRL sets up Certificate Revocation List watching for the Client.
// CRL cert is read from *path*, re-read every *readInterval* and has to exist until *fileExistTimeout*.
// Errors are delivered through *errChan*
func (c *Client) CRL(o CRLOptions) *Client {
	setCRL(c, o)
	c.haveTLSClientConfig().VerifyPeerCertificate = verifyPeerCert(c.crl)
	return c
}

func (c *Client) getCRL() *crl {
	return c.crl
}

func (c *Client) setCRL(serials map[string]struct{}, nextUpdate time.Time, strict bool) {
	if c.crl == nil {
		c.crl = &crl{
			mu:         sync.RWMutex{},
			serials:    map[string]struct{}{},
			nextUpdate: time.Time{},
		}
	}

	c.crl.mu.Lock()
	defer c.crl.mu.Unlock()

	c.crl.serials = serials
	c.crl.nextUpdate = nextUpdate
	c.crl.strictCheck = strict
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
	if transport2, ok := c.nonTracedTransport.(*http2.Transport); ok {
		if transport2.TLSClientConfig == nil {
			transport2.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		return transport2.TLSClientConfig
	}

	// HTTP 1.x
	transport, ok := c.nonTracedTransport.(*http.Transport)
	if !ok { // most probably nil
		transport = &http.Transport{}
		c.SetTransport(transport)
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

// TLSOwnCertOpts allows specifying custom file paths for client certificate and private key.
type TLSOwnCertOpts struct {
	Certificate string
	PrivateKey  string // #nosec G117: exported, so that the client can specify the private key path
}

func catDirFile(dir, file string) string {
	dirEndsWithSlash := strings.HasSuffix(dir, "/")
	if dir != "" && !dirEndsWithSlash && !strings.HasPrefix(file, "/") {
		return dir + "/" + file
	}
	return dir + file
}

// TLSOwnCerts loads PEM certificate + key from given directory and sets TLS config accordingly.
// That allows the client to authenticate itself using mutual TLS (mTLS).
//
// If only the dir is specified, then looks for tls.crt and tls.key files in that dir.
// You may also specify custom file names by using TLSOwnCertOpts.
// In that case the key and cert file paths are appended to the provided directory.
//
// Example usages:
//
//	client = client.TLSOwnCerts("/path/to/certs")
//
//	client = client.TLSOwnCerts("/path/to/certs", TLSOwnCertOpts{Certificate: "mycert.crt", PrivateKey:  "mykey.key"})
//
//	client.TLSOwnCerts("/path/to/certs", TLSOwnCertOpts{Certificate: "/certs/mycert.pem", PrivateKey:  "/key/mykey.pem"})
func (c *Client) TLSOwnCerts(dir string, opts ...TLSOwnCertOpts) *Client {
	var certificateFile, privateKeyFile string
	if len(opts) > 0 {
		if opts[0].Certificate == "" {
			opts[0].Certificate = "tls.crt"
		}
		certificateFile = catDirFile(dir, opts[0].Certificate)
		if opts[0].PrivateKey == "" {
			opts[0].PrivateKey = "tls.key"
		}
		privateKeyFile = catDirFile(dir, opts[0].PrivateKey)
	} else {
		certificateFile = catDirFile(dir, "tls.crt")
		privateKeyFile = catDirFile(dir, "tls.key")
	}

	cert, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
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
