// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"net/http"
	"strings"
)

// ContentType strings
const (
	AcceptHeader               = "Accept"
	ContentTypeHeader          = "Content-type"
	ContentTypeAny             = "*/*"
	ContentTypeApplicationAny  = "application/*"
	ContentTypeApplicationJSON = "application/json"
	ContentTypeProblemJSON     = "application/problem+json"     // RFC 7807
	ContentTypePatchJSON       = "application/json-patch+json"  // RFC 6902
	ContentTypeMergeJSON       = "application/merge-patch+json" // RFC 7386
	ContentTypeForm            = "application/x-www-form-urlencoded"
	ContentTypeMsgPack         = "application/msgpack"
	ContentTypeMultipartForm   = "multipart/form-data"
)

// BaseContentType returns the MIME type of the Content-Type header as lower-case string
// E.g.: "application/JSON; charset=ISO-8859-1" --> "application/json"
func BaseContentType(contentType string) string {
	return strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
}

// GetBaseContentType returns base content type from HTTP header.
// E.g.: "Content-Type: application/JSON; charset=ISO-8859-1" --> "application/json"
func GetBaseContentType(headers http.Header) string {
	return BaseContentType(headers.Get(ContentTypeHeader))
}

func isJSONContentType(baseCT string) bool {
	return strings.HasSuffix(baseCT, "json")
}
