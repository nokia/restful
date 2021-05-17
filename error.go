// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"errors"
	"net/http"
	"strings"
)

type restError struct {
	err         error
	description string
	statusCode  int
}

// Error returns error string.
func (e *restError) Error() string {
	errStr := ""
	if e.err != nil {
		errStr = e.err.Error()
	}

	if e.description == "" {
		return errStr
	}
	if errStr == "" {
		return e.description
	}
	return e.description + ": " + errStr
}

// Unwrap returns wrapped error.
// https://blog.golang.org/go1.13-errors
func (e *restError) Unwrap() error {
	return e.err
}

// NewError creates a new error that contains HTTP status code.
// Coupling HTTP status code to error makes functions return values clean. And controls what Lambda sends on errors.
//
// if err != nil {return restful.NewError(err, http.StatusBadRequest)}
//
// Parameter description is optional, caller may provide extra description, appearing at the beginning of the error string.
//
// if err != nil {return restful.NewError(err, http.StatusBadRequest, "bad data")}
//
// Parameter err may be nil, if there is no error to wrap or original error text is better not to be propagated.
//
// if err != nil {return restful.NewError(nil, http.StatusBadRequest, "bad data")}
func NewError(err error, statusCode int, description ...string) error {
	return &restError{err: err, statusCode: statusCode, description: strings.Join(description, " ")}
}

// DetailError adds further description to the error. Useful when cascading return values.
// Can be used on any error, though mostly used on errors created by restful.NewError().
// E.g. restful.DetailError(err, "db query failed")
func DetailError(err error, description string) error {
	return &restError{err: err, statusCode: GetErrStatusCodeElse(err, 0), description: description}
}

// GetErrStatusCode returns status code of error response.
// If err is nil then http.StatusOK returned.
// If no status stored (e.g. unexpected content-type received) then http.StatusInternalServerError returned.
func GetErrStatusCode(err error) int {
	status := GetErrStatusCodeElse(err, -1)
	if status <= 0 {
		return http.StatusInternalServerError
	}
	return status
}

// GetErrStatusCodeElse returns status code of error response, if available.
// Else retuns the one the caller provided. Probably transport error happened and no HTTP response was received.
// If err is nil then http.StatusOK returned.
func GetErrStatusCodeElse(err error, elseStatusCode int) int {
	if err != nil {
		var e *restError
		if errors.As(err, &e) {
			return e.statusCode
		}
		return elseStatusCode
	}
	return http.StatusOK
}

// IsConnectError determines if error is due to failed connection.
// I.e. does not contain HTTP status code, or 502 / 503 / 504.
func IsConnectError(err error) bool {
	status := GetErrStatusCodeElse(err, 502)
	return status >= 502 && status <= 504
}
