// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewError(t *testing.T) {
	assert := assert.New(t)
	err := NewError(errors.New("err"), 400, "what?")
	assert.Equal(400, GetErrStatusCode(err))
	assert.Equal(400, GetErrStatusCodeElse(err, 501))
	assert.Equal("what?: err", err.Error())

	err = DetailError(err, "when?")
	assert.Equal(400, GetErrStatusCode(err))
	assert.Equal("when?: what?: err", err.Error())

	err = errors.Unwrap(err)
	assert.Equal("what?: err", err.Error())
}

func TestNewErrorNoDescription(t *testing.T) {
	assert := assert.New(t)
	err := NewError(errors.New("err"), 400)
	assert.Equal(400, GetErrStatusCode(err))
	assert.Equal("err", err.Error())
}

func TestErrGettersForNonRestError(t *testing.T) {
	assert := assert.New(t)
	err := errors.New("err")
	assert.Equal(500, GetErrStatusCode(err))
	assert.Equal(501, GetErrStatusCodeElse(err, 501))
	assert.True(IsConnectError(err))
}

func TestErrGettersForNil(t *testing.T) {
	assert := assert.New(t)
	var err error
	assert.Equal(200, GetErrStatusCode(err))
	assert.Equal(200, GetErrStatusCodeElse(err, 501))
	assert.False(IsConnectError(err))
}

func TestErrConnect(t *testing.T) {
	assert := assert.New(t)
	assert.False(IsConnectError(NewError(nil, 400, "")))
	assert.False(IsConnectError(NewError(nil, 500, "")))
	assert.False(IsConnectError(NewError(nil, 511, "")))

	assert.True(IsConnectError(NewError(nil, 502, "")))
	assert.True(IsConnectError(NewError(nil, 503, "")))
	assert.True(IsConnectError(NewError(nil, 504, "")))
}

func TestErrNoBase(t *testing.T) {
	err := NewError(nil, 404, "hello")
	assert.Equal(t, "hello", err.Error())
}
