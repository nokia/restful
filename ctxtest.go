// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"

	"github.com/nokia/restful/lambda"
)

// NewTestCtx helps creating tests. Caller can define headers and path variables.
func NewTestCtx(method string, rawurl string, header http.Header, vars map[string]string) context.Context {
	return lambda.NewTestCtx(method, rawurl, header, vars)
}
