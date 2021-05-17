// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Sanitize(t *testing.T) {
	type myType struct {
		A1 []string
		A2 []string
		M1 map[string]string
		M2 map[string]string
		P1 *int
		P2 *int `json:"p2"`
		P3 *int `json:"p3,omitempty"`
	}

	i := 1
	v := myType{A1: []string{"a1"}, M1: map[string]string{"m1": "M1"}, P1: &i}

	assert := assert.New(t)
	b, err := json.Marshal(&v)
	assert.NoError(err)
	bSan := string(SanitizeJSONBytes(b))

	assert.Equal(`{"A1":["a1"],"M1":{"m1":"M1"},"P1":1}`, bSan)
}
