// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGracefulZero(t *testing.T) {
	s := NewServer().Graceful(0).Addr(":8080")
	go func() {
		time.Sleep(time.Millisecond)
		syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()
	assert.NoError(t, s.ListenAndServe())
}

func TestGracefulNonzero(t *testing.T) {
	s := NewServer().Addr("127.0.0.1:0").Graceful(time.Millisecond)
	go func() {
		time.Sleep(time.Millisecond)
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}()
	err := s.ListenAndServe()
	assert.True(t, err == nil || strings.Contains(err.Error(), "deadline"))
}

func TestGracefulBadAddr(t *testing.T) {
	s := NewServer().Graceful(0).Addr(":-1")
	assert.Error(t, s.ListenAndServe())
}

func TestRestart(t *testing.T) {
	assert := assert.New(t)
	s := NewServer().Addr("127.0.0.1:0")

	// Logger
	logs := make([]string, 0)
	logchn := make(chan string, 6)
	var wgLogs sync.WaitGroup
	wgLogs.Add(1)
	go func() {
		for s := range logchn {
			logs = append(logs, s)
		}
		wgLogs.Done()
	}()

	// Listen - Restart - Close
	var err error
	var wgServer sync.WaitGroup
	wgServer.Add(3)
	go func() {
		logchn <- "listen"
		err = s.ListenAndServe()
		logchn <- "listened"
		wgServer.Done()
	}()
	go func() {
		time.Sleep(10 * time.Millisecond)
		logchn <- "restart"
		s.Restart()
		logchn <- "restarted"
		wgServer.Done()
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
		logchn <- "close"
		s.Close()
		logchn <- "closed"
		wgServer.Done()
	}()
	wgServer.Wait()
	assert.True(errors.Is(err, http.ErrServerClosed))

	close(logchn)
	wgLogs.Wait()
	assert.Contains(strings.Join(logs, ", "), "listen, restart, restarted, close")
	assert.Contains(logs, "closed")
	assert.Contains(logs, "listened")
}

func TestHTTPServerBadAddrNilHandler(t *testing.T) {
	assert.Error(t, ListenAndServe(":-1", nil))
}
