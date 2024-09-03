// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

// DefaultServeMux is the default HTTP mux served.
var DefaultServeMux = NewRouter()

// HandleFunc assigns an HTTP path template to a function.
func HandleFunc(path string, f any) *Route {
	return DefaultServeMux.HandleFunc(path, f)
}

// Start starts serving on port 8080 (AddrHTTP).
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
// Handles connections gracefully on TERM/INT signals.
func Start() error {
	return DefaultServeMux.Start()
}

// StartTLS starts serving for TLS on port 8443 (AddrHTTPS) and for cleartext on port 8080 (AddrHTTP), if allowed.
// TLS cert must be at OwnTLSCert and key at OwnTLSKey.
// If mutualTLS=true, then client certs must be provided; see variable ClientCAs.
// If loadSystemCerts is true, clients with CA from system CA pool are accepted, too.
// As the role of mTLS is to authorize certain clients to connect, enable system CAs only if those are reasonable for auth.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
// Handles connections gracefully on TERM/INT signals.
func StartTLS(cleartext, mutualTLS bool, loadSystemCerts bool) error {
	return DefaultServeMux.StartTLS(cleartext, mutualTLS, loadSystemCerts)
}
