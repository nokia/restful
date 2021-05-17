// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseContentType(t *testing.T) {
	assert := assert.New(t)

	inputTable := []struct {
		expected string
		input    string
	}{
		{ContentTypeApplicationJSON, "application/json"},
		{ContentTypeApplicationJSON, "application/JSON"},
		{ContentTypeApplicationJSON, "aPpLiCaTiOn/JsOn"},
		{ContentTypeApplicationJSON, "application/json;charset=ISO-8859-1"},
		{ContentTypeProblemJSON, "application/problem+JSON"},
		{ContentTypePatchJSON, "application/json-patch+json"},
		{ContentTypeMergeJSON, "application/merge-patch+json;hello"},
		{"whatever/contenttype", "whatEVER/ContentType"},
		{"", ""},
		{"", ";"},
	}

	for _, test := range inputTable {
		assert.Equal(test.expected, BaseContentType(test.input))
	}
}
