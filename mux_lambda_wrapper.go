// Copyright 2021-2023 Nokia
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

func lambdaHandleRes0(l *Lambda) (err error) {
	if l != nil && l.status > 0 {
		err = NewError(nil, l.status)
	}
	return
}

func lambdaHandleRes1(l *Lambda, res reflect.Value) (interface{}, error) {
	if err, ok := res.Interface().(error); ok {
		return nil, err
	}

	if l != nil && l.status > 0 {
		return res.Interface(), NewError(nil, l.status)
	}
	return res.Interface(), nil
}

func lambdaGetStatus(l *Lambda, res reflect.Value) error {
	if err, ok := res.Interface().(error); ok {
		return err
	}
	if l != nil && l.status > 0 {
		return NewError(nil, l.status)
	}
	return nil
}

func lambdaHandleRes2(l *Lambda, res []reflect.Value) (interface{}, error) {

	err := lambdaGetStatus(l, res[1])

	if res[0].Kind() == reflect.Ptr {
		/* #nosec G103 */
		if unsafe.Pointer(res[0].Pointer()) == nil {
			return nil, err
		}
		res[0] = res[0].Elem()
	}
	return res[0].Interface(), err
}

func lambdaHandleRes(w http.ResponseWriter, r *http.Request, res []reflect.Value) {
	var data interface{}
	var err error
	if len(res) <= 0 {
		err = lambdaHandleRes0(L(r.Context()))
	} else if len(res) == 1 {
		data, err = lambdaHandleRes1(L(r.Context()), res[0])
	} else {
		data, err = lambdaHandleRes2(L(r.Context()), res)
	}
	_ = SendResp(w, r, err, data)
}

var contextType = reflect.TypeOf((*context.Context)(nil)).Elem()

func lambdaGetParams(w http.ResponseWriter, r *http.Request, f interface{}) ([]reflect.Value, *http.Request, error) {
	t := reflect.TypeOf(f)
	params := make([]reflect.Value, t.NumIn())
	if t.NumIn() > 0 {
		reqDataIdx := 0

		// Handle context parameter
		if t.In(0).Implements(contextType) {
			ctx := NewRequestCtx(w, r)
			r = r.WithContext(ctx)
			params[0] = reflect.ValueOf(ctx)
			reqDataIdx = 1
		}

		// Handle body parameter
		if reqDataIdx < t.NumIn() {
			var err error
			var reqData reflect.Value
			reqDataType := t.In(reqDataIdx)
			if reqDataType.Kind() == reflect.Ptr {
				reqData = reflect.New(reqDataType.Elem())
				err = GetRequestData(r, LambdaMaxBytesToParse, reqData.Interface())
			} else {
				reqData = reflect.New(reqDataType).Elem()
				err = GetRequestData(r, LambdaMaxBytesToParse, reqData.Addr().Interface())
			}

			if err != nil {
				return nil, r, err
			}
			params[reqDataIdx] = reqData
		}
	}
	return params, r, nil
}

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
		params, r, err := lambdaGetParams(w, r, f)
		if err != nil {
			_ = SendResp(w, r, err, nil)
			return
		}
		res := reflect.ValueOf(f).Call(params)
		lambdaHandleRes(w, r, res)
	}
}
