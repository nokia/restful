// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

/* There are numerous Lambda context functions to query request data and set response.
 * It would be easy to expose http.ResponseWriter and *http.Request.
 * Here, instead, separate functions are defined. That might help if a serverless environment is to be supported later.
 */

package restful

import (
	"context"
	"net/http"

	"github.com/nokia/restful/lambda"
)

// NewRequestCtx adds request related data to r.Context().
// You may use this at traditional http handler functions, and that is what happens at Lambda functions automatically.
// Returns new derived context. That can be used at client functions, silently propagating tracing headers.
//
// E.g. ctx := NewRequestCtx(w, r)
func NewRequestCtx(w http.ResponseWriter, r *http.Request) context.Context {
	return lambda.NewRequestCtx(w, r)
}

// L returns lambda-related data from context.
func L(ctx context.Context) *lambda.Lambda {
	return lambda.L(ctx)
}
