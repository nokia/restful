// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGracefulZero(t *testing.T) {
	s := NewServer().Graceful(0)
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

func TestHTTPServerBadAddrNilHandler(t *testing.T) {
	assert.Error(t, ListenAndServe(":-1", nil))
}
