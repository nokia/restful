// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"regexp"
	"strings"
)

var reNull = regexp.MustCompile(`"[^"]+":null,?`)
var reEmptyArray = regexp.MustCompile(`"[^"]+":\[\],?`)
var reEmptyStruct = regexp.MustCompile(`"[^"]+":{},?`)
var reEmptyString = regexp.MustCompile(`"[^"]+":"",?`)

// SanitizeJSONString clears empty entries from string of JSON.
// Note that normally one should use "omitempty" in structures, and use pointers for arrays and structs.
// So sanitizing is not really needed.
// Deprecated.
func SanitizeJSONString(s string) string {
	s = reNull.ReplaceAllString(s, "$1")
	s = reEmptyArray.ReplaceAllString(s, "")
	s = reEmptyString.ReplaceAllString(s, "")

	var slen int
	for {
		slen = len(s)
		s = reEmptyStruct.ReplaceAllString(s, "")
		if slen == len(s) {
			break
		}
	}

	return strings.ReplaceAll(s, ",}", "}")
}

// SanitizeJSONBytes clears empty entries from byte array of JSON.
// Deprecated.
func SanitizeJSONBytes(b []byte) []byte {
	return []byte(SanitizeJSONString(string(b)))
}
