// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"net/http"
	"reflect"
	"unsafe"
)

// LambdaMaxBytesToParse defines the maximum length of request content allowed to be parsed.
// If zero then no limits imposed.
var LambdaMaxBytesToParse = 0

// LambdaSanitizeJSON defines whether to sanitize JSON of Lambda return or SendResp.
// See SanitizeJSONString for details.
var LambdaSanitizeJSON = false

// LambdaWrap wraps a Lambda function and makes it a http.HandlerFunc.
// This function is rarely needed, as restful's Router wraps handler functions automatically.
// You might need it if you want to wrap a standard http.HandlerFunc.
func LambdaWrap(f interface{}) http.HandlerFunc {
	if httpHandler, ok := f.(func(w http.ResponseWriter, r *http.Request)); ok {
		return httpHandler
	}
	if httpHandler, ok := f.(http.HandlerFunc); ok {
		return httpHandler
	}

	t := reflect.TypeOf(f)
	if t.Kind() != reflect.Func {
		panic("function expected")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var reqData reflect.Value
		var params []reflect.Value
		t := reflect.TypeOf(f)
		if t.NumIn() > 0 {
			reqDataIdx := 0

			// Handle context parameter
			if t.In(0).ConvertibleTo(reflect.TypeOf((*context.Context)(nil)).Elem()) {
				ctx := NewRequestCtx(w, r)
				r = r.WithContext(ctx)
				params = append(params, reflect.ValueOf(ctx))
				reqDataIdx = 1
			}

			// Handle other parameter
			if reqDataIdx < t.NumIn() {
				var err error
				reqDataType := t.In(reqDataIdx)
				if reqDataType.Kind() == reflect.Ptr {
					reqData = reflect.New(reqDataType.Elem())
					err = GetRequestData(r, LambdaMaxBytesToParse, reqData.Interface())
				} else {
					reqData = reflect.New(reqDataType).Elem()
					err = GetRequestData(r, LambdaMaxBytesToParse, reqData.Addr().Interface())
				}

				if err != nil {
					_ = SendResp(w, r, err, nil)
					return
				}
				params = append(params, reqData)
			}
		}

		res := reflect.ValueOf(f).Call(params)

		if len(res) <= 0 {
			status := http.StatusOK
			l := L(r.Context())
			if l != nil && l.status > 0 {
				status = l.status
			}
			SendEmptyResponse(w, status)
		} else if len(res) == 1 {
			if resErr, ok := res[0].Interface().(error); ok {
				_ = SendResp(w, r, resErr, nil)
			} else {
				l := L(r.Context())
				if l != nil && l.status > 0 {
					_ = SendResp(w, r, NewError(nil, l.status), res[0].Interface())
				}
				_ = SendResp(w, r, nil, res[0].Interface())
			}
		} else {
			var err error
			if resErr, ok := res[1].Interface().(error); ok {
				err = resErr
			} else {
				l := L(r.Context())
				if l != nil && l.status > 0 {
					err = NewError(nil, l.status)
				}
			}
			if res[0].Kind() == reflect.Ptr {
				/* #nosec G103 */
				if unsafe.Pointer(res[0].Pointer()) == nil {
					_ = SendResp(w, r, err, nil)
					return
				}
				res[0] = res[0].Elem()
			}
			_ = SendResp(w, r, err, res[0].Interface())
		}
	}
}
