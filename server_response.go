// Copyright 2021-2023 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

func getJSONBody(data interface{}, sanitizeJSON bool) ([]byte, error) {
	if data == nil {
		return nil, nil // Otherwise "null" (4 bytes) would be returned.
	}

	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if sanitizeJSON {
		body = SanitizeJSONBytes(body)
		if len(body) == 2 && body[0] == '{' && body[1] == '}' {
			return nil, nil
		}
	}

	return body, nil
}

// SendJSONResponse sends an HTTP response with an optionally sanitized JSON data.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
func SendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}, sanitizeJSON bool) (err error) {
	body, err := getJSONBody(data, sanitizeJSON)
	if body != nil {
		w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
		w.WriteHeader(statusCode)
		_, err = w.Write(body)
	} else {
		w.WriteHeader(statusCode)
	}
	return err
}

// SendResponse sends an HTTP response with a JSON data.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
func SendResponse(w http.ResponseWriter, statusCode int, data interface{}) error {
	return SendJSONResponse(w, statusCode, data, false)
}

func getOkStatus(w http.ResponseWriter, r *http.Request, data interface{}) int {
	status := http.StatusOK
	if data == nil {
		status = http.StatusNoContent
	}
	if r.Method == http.MethodPost && w.Header().Get("Location") != "" {
		status = http.StatusCreated
	}
	return status
}

// SendResp sends an HTTP response with data.
// On no error 200/201/204 sent according to the request.
// On error send response depending on whether the error is created by NewError and the client supports RFC 7807.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
func SendResp(w http.ResponseWriter, r *http.Request, err error, data interface{}) error {
	if err == nil {
		return SendJSONResponse(w, getOkStatus(w, r, data), data, LambdaSanitizeJSON)
	}

	if errStr := err.Error(); errStr != "" { // In some cases status like 404 does not indicate error, just a plain result. E.g. on a distributed cache query.
		log.Error(errStr)
	}

	body, _ := getJSONBody(data, LambdaSanitizeJSON)
	if body == nil {
		return SendProblemDetails(w, r, err)
	}
	w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
	w.WriteHeader(GetErrStatusCode(err))
	_, err = w.Write(body)
	return err
}

// SendEmptyResponse sends an empty HTTP response.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
func SendEmptyResponse(w http.ResponseWriter, statusCode int) {
	w.WriteHeader(statusCode)
}

// SendLocationResponse sends an empty "201 Created" HTTP response with Location header.
func SendLocationResponse(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	SendEmptyResponse(w, http.StatusCreated)
}

func getProblemContentType(r *http.Request) string {
	ct := ContentTypeApplicationJSON
	accepts := r.Header.Values(AcceptHeader)
	for i := range accepts {
		baseCT := BaseContentType(accepts[i])
		if baseCT == ContentTypeProblemJSON || baseCT == ContentTypeApplicationAny || baseCT == ContentTypeAny {
			ct = ContentTypeProblemJSON
			break
		}
	}
	return ct
}

// SendProblemResponse sends response with problem text, and extends it to problem+json format if it is a plain string.
func SendProblemResponse(w http.ResponseWriter, r *http.Request, statusCode int, problem string) (err error) {
	if problem == "" {
		SendEmptyResponse(w, statusCode)
		return nil
	}

	if problem != "" && problem[0] != '{' {
		problem = `{"detail":"` + strings.ReplaceAll(problem, `"`, "'") + `"}`
	}

	w.Header().Set(ContentTypeHeader, getProblemContentType(r))
	w.WriteHeader(statusCode)
	if len(problem) > 0 {
		_, err = w.Write([]byte(problem))
	}
	return
}

// SendProblemDetails adds detailed problem description to JSON body, if available. See RFC 7807.
func SendProblemDetails(w http.ResponseWriter, r *http.Request, err error) error {
	if err, ok := err.(*restError); ok {
		d := err.problemDetails.Detail
		// check in case it is somehow already filled with JSON text...
		if d != "" && d[0] != '{' {
			if err.err != nil {
				if embeddedStr := err.err.Error(); embeddedStr != "" {
					err.problemDetails.Detail += ": " + embeddedStr
				}
			}
			return SendProblemResponse(w, r, GetErrStatusCode(err), err.problemDetails.String())
		}
	}
	return SendProblemResponse(w, r, GetErrStatusCode(err), err.Error())
}
