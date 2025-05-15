// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// ErrorBodyMaxLen is the maximum length of the body
// that is stored to the error object in case of an 4xx or 5xx response.
const ErrorBodyMaxLen = 4096

var (
	// ErrNonHTTPSURL means that using non-https URL not allowed.
	ErrNonHTTPSURL = errors.New("non-https URL not allowed")

	// ErrUnexpectedContentType is returned if content-type is unexpected.
	// It may be wrapped, so use errors.Is() for checking.
	ErrUnexpectedContentType = errors.New("unexpected Content-Type")
)

type restError struct {
	err            error
	statusCode     int
	problemDetails ProblemDetails
	contentType    string
	body           []byte
}

// InvalidParam is the common InvalidParam object defined in 3GPP TS 29.571
type InvalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// ProblemDetails is a structure defining fields for RFC 7807 error responses.
type ProblemDetails struct {
	Type          string         `json:"type,omitempty"`
	Title         string         `json:"title,omitempty"`
	Detail        string         `json:"detail,omitempty"`
	Cause         string         `json:"cause,omitempty"`
	Instance      string         `json:"instance,omitempty"`
	Status        int            `json:"status,omitempty"`
	InvalidParams []InvalidParam `json:"invalidParams,omitempty"`
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
//	if err != nil {return restful.NewError(err, http.StatusBadRequest)}
//
// Parameter description is optional, caller may provide extra description, appearing at the beginning of the error string.
//
//	if err != nil {return restful.NewError(err, http.StatusBadRequest, "bad data")}
//
// Parameter err may be nil, if there is no error to wrap or original error text is better not be propagated.
//
//	if err != nil {return restful.NewError(nil, http.StatusBadRequest, "bad data")}
func NewError(err error, statusCode int, description ...string) error {
	if _, ok := err.(*restError); ok {
		return err
	}
	return &restError{err: err, statusCode: statusCode, problemDetails: ProblemDetails{Detail: strings.Join(description, " ")}}
}

// NewErrorWithBody creates new error with custom HTTP status code, content-type and payload body.
func NewErrorWithBody(err error, statusCode int, contentType string, body []byte) error {
	if len(body) > ErrorBodyMaxLen {
		return &restError{err: err, statusCode: statusCode}
	}
	return &restError{err: err, statusCode: statusCode, contentType: contentType, body: body}
}

// NewDetailedError creates a new error with specified problem details JSON structure (RFC7807)
func NewDetailedError(err error, status int, pd ProblemDetails) error {
	return &restError{err: err, statusCode: status, problemDetails: pd}
}

// DetailError adds further description to the error. Useful when cascading return values.
// Can be used on any error, though it is mostly used on errors created by restful.NewError() / NewDetailedError()
// E.g. restful.DetailError(err, "db query failed")
func DetailError(err error, description string) error {
	if err == nil {
		return nil
	}
	return &restError{err: err, statusCode: GetErrStatusCodeElse(err, 0), problemDetails: ProblemDetails{Detail: description}}
}

// GetErrStatusCode determines the HTTP status code associated with a given error.
// If err is nil then http.StatusOK returned.
// If no HTTP status is found, then http.StatusInternalServerError (500) is returned.
func GetErrStatusCode(err error) int {
	status := GetErrStatusCodeElse(err, -1)
	if status <= 0 {
		return http.StatusInternalServerError
	}
	return status
}

// GetErrStatusCodeElse returns the HTTP status code associated with the given error.
// If no HTTP status code found in the error, then returns the one the caller provided.
// For example, in case of a transport error no HTTP status code is received.
// If the error is nil, it returns http.StatusOK.
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

// IsConnectError determines if the given error corresponds to a connection-related issue.
// I.e. non-nil, does not contain HTTP status code, or the status code is 502 / 503 / 504.
func IsConnectError(err error) bool {
	status := GetErrStatusCodeElse(err, 502)
	return status >= 502 && status <= 504
}

// GetErrBody returns the content-type and raw body stored within the given error.
// Note that the body may be chopped if too long. See ErrorBodyMaxLen.
//
//	err := restful.Get()
//	contentType, Body := restful.GetErrBody(err)
//	if body != nil {fmt.Print(string(body))}
func GetErrBody(err error) (string, []byte) {
	if err != nil {
		var e *restError
		if errors.As(err, &e) {
			if e.body != nil {
				return e.contentType, e.body
			}
			if e.problemDetails.Detail != "" {
				return ContentTypeProblemJSON, []byte(e.problemDetails.Detail)
			}
		}
	}
	return "", nil
}
