// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// TLSConfig returns raw TLS config used by the server
func (s *Server) TLSConfig() *tls.Config {
	return s.server.TLSConfig
}

// TLSClientCert adds client certs to server, enabling mutual TLS (mTLS).
// If path is a directory then scans for files recursively. If path is not set then defaults to /etc.
// If loadSystemCerts is true, clients with CA from system CA pool are accepted, too.
// As the role of mTLS is to authorize certain clients to connect, enable system CAs only if those are reasonable for auth.
// File names should match *.crt or *.pem.
func (s *Server) TLSClientCert(path string, loadSystemCerts bool) *Server {
	if s.server.TLSConfig == nil {
		s.server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	s.server.TLSConfig.ClientCAs = NewCertPool(path, loadSystemCerts)
	s.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return s
}

// TLSServerCert sets server cert + key.
func (s *Server) TLSServerCert(certFile, keyFile string) *Server {
	s.certFile = certFile
	s.keyFile = keyFile
	return s
}

// ListenAndServeTLS acts like standard http.ListenAndServeTLS().
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func ListenAndServeTLS(addr, certFile, keyFile string, handler http.Handler) error {
	return NewServer().Addr(addr).Handler(handler).TLSServerCert(certFile, keyFile).ListenAndServe()
}

// ListenAndServeMTLS acts like standard http.ListenAndServeTLS(). Just authenticates client.
// Parameter clientCerts is a PEM cert file or a directory of PEM cert files case insensitively matching *.pem or *.crt.
// If loadSystemCerts is true, clients with CA from system CA pool are accepted, too.
// As the role of mTLS is to authorize certain clients to connect, enable system CAs only if those are reasonable for auth.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func ListenAndServeMTLS(addr, certFile, keyFile, clientCerts string, loadSystemCerts bool, handler http.Handler) error {
	return NewServer().Addr(addr).Handler(handler).TLSServerCert(certFile, keyFile).TLSClientCert(clientCerts, loadSystemCerts).ListenAndServe()
}

// CRL sets up Certificate Revocation List watching for the Server.
// CRL cert is read from *path*, re-read every *readInterval* and has to exist until *fileExistTimeout*.
// Errors are delivered through *errChan*
func (s *Server) CRL(o CRLOptions) *Server {
	setCRL(s, o)
	s.server.TLSConfig.VerifyPeerCertificate = verifyPeerCert(s.crl)
	return s
}

func (s *Server) getCRL() *crl {
	return s.crl
}

func (s *Server) setCRL(serials map[string]struct{}, nextUpdate time.Time, strict bool) {
	if s.crl == nil {
		s.crl = &crl{
			mu:         sync.RWMutex{},
			serials:    map[string]struct{}{},
			nextUpdate: time.Time{},
		}
	}

	s.crl.mu.Lock()
	defer s.crl.mu.Unlock()

	s.crl.serials = serials
	s.crl.nextUpdate = nextUpdate
	s.crl.strictCheck = strict
}
