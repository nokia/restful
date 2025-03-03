// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nokia/restful/trace/tracer"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Server represents a server instance.
type Server struct {
	server      *http.Server
	serverMutex sync.Mutex
	certFile    string
	keyFile     string
	graceful    bool
	restarting  bool
	gracePeriod time.Duration
	monitors    monitors
}

// ServerReadHeaderTimeout is the amount of time allowed to read request headers.
var ServerReadHeaderTimeout = 5 * time.Second

// ServerReadTimeout is the amount of time allowed to read request body.
// Default 60s is quite liberal.
var ServerReadTimeout = 60 * time.Second

// NewServer creates a new Server instance.
func NewServer() *Server {
	server := Server{server: &http.Server{ReadHeaderTimeout: ServerReadHeaderTimeout, ReadTimeout: ServerReadTimeout}}
	return &server
}

// Graceful enables graceful shutdown.
// Awaits TERM/INT signals and exits when http shutdown completed, i.e. clients are served.
// Caller may define gracePeriod to wait before shutting down listening point.
// Client connection shutdown awaited indefinitely.
func (s *Server) Graceful(gracePeriod time.Duration) *Server {
	s.graceful = true
	s.gracePeriod = gracePeriod
	return s
}

// Addr sets address to listen on. E.g. ":8080".
// If not set then transport specific port (80/443) is listened on any interface.
func (s *Server) Addr(addr string) *Server {
	s.server.Addr = addr
	return s
}

// Monitor sets monitor functions for the server.
// These functions are called pre / post serving each request.
func (s *Server) Monitor(pre MonitorFuncPre, post MonitorFuncPost) *Server {
	s.monitors.append(pre, post)
	if s.server.Handler != nil {
		s.server.Handler = s.monitors.wrap(s.server.Handler)
		s.monitors = nil
	}
	return s
}

// Handler defines handlers for server.
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func (s *Server) Handler(handler http.Handler) *Server {
	if handler == nil {
		DefaultServeMux.PathPrefix("/").HandlerFunc(http.DefaultServeMux.ServeHTTP) // In case http.HandleFunc() was used.
		handler = DefaultServeMux
	}
	s.server.Handler = Logger(s.monitors.wrap(handler))
	if isTraced && tracer.GetOTel() {
		s.server.Handler = otelhttp.NewHandler(s.server.Handler, "", otelhttp.WithSpanNameFormatter(spanNameFormatter))
	}
	s.monitors = nil
	return s
}

// ListenAndServe starts listening and serves requests, blocking the caller.
// Uses HTTPS if server key+cert is set, otherwise HTTP.
// Port is set according to scheme, if listening address is not set.
// When Graceful() is used it may return nil.
func (s *Server) ListenAndServe() error {
	if !s.graceful {
		return s.listenAndServe()
	}

	stopErrCh := make(chan error)

	go func() {
		if err := s.listenAndServe(); err != http.ErrServerClosed {
			stopErrCh <- err
		} else {
			stopErrCh <- nil
		}
	}()

	go waitForSignal(stopErrCh)

	if err := <-stopErrCh; err != nil {
		return err
	}

	if s.gracePeriod > 0 {
		log.Debug("Waiting grace period: ", s.gracePeriod)
		time.Sleep(s.gracePeriod) // Still accept new connections.
		log.Debug("Grace period over")
	} else {
		time.Sleep(10 * time.Millisecond) // Clients just connected to be served. E.g. K8s endpoint just deleted.
	}
	log.Debug("Waiting client connections to shut down")
	err := s.server.Shutdown(context.Background())
	log.Debug("Shutdown completed")
	return err
}

func waitForSignal(c chan error) {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGTERM, syscall.SIGINT)
	log.Info("Signal received: ", <-signalChannel)
	c <- nil
}

func (s *Server) listenAndServe() error {
	if s.server.Handler == nil {
		s.Handler(http.DefaultServeMux)
	}

	for {
		var err error
		if s.keyFile != "" && s.certFile != "" {
			err = s.server.ListenAndServeTLS(s.certFile, s.keyFile)
		} else {
			err = s.server.ListenAndServe()
		}

		if !s.restarting {
			return err
		}
		s.restarting = false

		s.serverMutex.Lock() // ListenAndServe routines and Close are executed in parallel.
		s.server = &http.Server{Handler: s.server.Handler, Addr: s.server.Addr, ReadHeaderTimeout: ServerReadHeaderTimeout, ReadTimeout: ServerReadTimeout}
		s.serverMutex.Unlock()
	}
}

// Restart restarts the server abruptly.
// During restart active connections are dropped and there may be an outage.
func (s *Server) Restart() {
	s.restarting = true
	if err := s.server.Close(); err != nil {
		log.Errorf("restart close incomplete: %v", err)
	}
}

// Close immediately closes all connections.
func (s *Server) Close() error {
	s.serverMutex.Lock()
	defer s.serverMutex.Unlock()
	return s.server.Close()
}

// Shutdown closes all connections gracefully.
// E.g. server.Shutdown(context.Background())
func (s *Server) Shutdown(ctx context.Context) error {
	s.serverMutex.Lock()
	defer s.serverMutex.Unlock()
	return s.server.Shutdown(ctx)
}

// ListenAndServe acts like standard http.ListenAndServe().
// Logs, except for automatically served LivenessProbePath and HealthCheckPath.
func ListenAndServe(addr string, handler http.Handler) error {
	return NewServer().Addr(addr).Handler(handler).ListenAndServe()
}
