// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type restError struct {
	err            error
	statusCode     int
	problemDetails ProblemDetails
}

// ProblemDetails is a structure defining fields for RFC 7807 error responses.
type ProblemDetails struct {
	Type          string            `json:"type,omitempty"`
	Title         string            `json:"title,omitempty"`
	Detail        string            `json:"detail,omitempty"`
	Instance      string            `json:"instance,omitempty"`
	Status        int               `json:"status,omitempty"`
	InvalidParams map[string]string `json:"invalidParams,omitempty"`
}

// String makes string of ProblemDetails.
func (e ProblemDetails) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}

// ProblemDetails adds ProblemDetails data to error.
func (e *restError) ProblemDetails(pd ProblemDetails) error {
	e.problemDetails = pd
	return e
}

// Error returns error string.
func (e restError) Error() string {
	errStr := ""
	if e.err != nil {
		errStr = e.err.Error()
	}

	if e.problemDetails.Detail == "" {
		return errStr
	}
	if errStr == "" {
		return e.problemDetails.Detail
	}
	return e.problemDetails.Detail + ": " + errStr
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
	return &restError{err: err, statusCode: statusCode, problemDetails: ProblemDetails{Detail: strings.Join(description, " ")}}
}

// NewDetailedError creates a new error with specified problem details JSON structure (RFC7807)
func NewDetailedError(err error, status int, pd ProblemDetails) error {
	return &restError{err: err, statusCode: status, problemDetails: pd}
}

// DetailError adds further description to the error. Useful when cascading return values.
// Can be used on any error, though mostly used on errors created by restful.NewError() / NewDetailedError()
// E.g. restful.DetailError(err, "db query failed")
func DetailError(err error, description string) error {
	return &restError{err: err, statusCode: GetErrStatusCodeElse(err, 0), problemDetails: ProblemDetails{Detail: description}}
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
