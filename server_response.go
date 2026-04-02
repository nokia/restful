// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nokia/restful/messagepack"
	log "github.com/sirupsen/logrus"
)

func getJSONBody(data any) ([]byte, error) {
	if data == nil {
		return nil, nil // Otherwise "null" (4 bytes) would be returned.
	}

	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// SendJSONResponse sends an HTTP response with a JSON data.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
//
// Warning: The last boolean parameter is ignored. It is there for temporary backward compatibility only.
// It will be removed in the near-future.
func SendJSONResponse(w http.ResponseWriter, statusCode int, data any, _ ...bool) (err error) {
	body, err := getJSONBody(data)
	if body != nil {
		w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
		w.WriteHeader(statusCode)
		_, err = w.Write(body) // #nosec G705: false positive; no user input
	} else {
		w.WriteHeader(statusCode)
	}
	return err
}

func sendResponse(w http.ResponseWriter, r *http.Request, data any) (err error) {
	okStatus := getOkStatus(w, r, data)

	if data == nil {
		w.WriteHeader(okStatus)
		return nil
	}

	useMsgPack := false
	writeHeaders := w.Header()
	if writeHeaders == nil || writeHeaders.Get(ContentTypeHeader) == "" {
		useMsgPack = acceptsMsgPack(r)
	} else if isMsgPackContentType(GetBaseContentType(writeHeaders)) {
		useMsgPack = true
	}

	if useMsgPack {
		b, err := messagepack.Marshal(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}
		w.Header().Set(ContentTypeHeader, ContentTypeMsgPack)
		w.WriteHeader(okStatus)
		_, err = w.Write(b) // #nosec G705: false positive; no user input
		return err
	}

	return SendJSONResponse(w, okStatus, data)
}

// SendResponse sends an HTTP response with a JSON data.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
//
// Same as SendJSONResponse. It will be removed in the near-future.
// Deprecated.
func SendResponse(w http.ResponseWriter, statusCode int, data any) error {
	return SendJSONResponse(w, statusCode, data)
}

func getOkStatus(w http.ResponseWriter, r *http.Request, data any) int {
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
// If the supplied err is nil, 200/201/204 is sent according to the request and if response data is supplied.
// If err is not nil, a response is sent depending on whether the supplied error is created by NewError and the client supports RFC 7807.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
func SendResp(w http.ResponseWriter, r *http.Request, err error, data any) error {
	if err == nil {
		return sendResponse(w, r, data)
	}

	if errStr := err.Error(); errStr != "" { // In some cases status like 404 does not indicate error, just a plain result. E.g. on a distributed cache query.
		log.Error(errStr)
	}

	body, _ := getJSONBody(data)
	if body == nil {
		return SendProblemDetails(w, r, err)
	}
	w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
	w.WriteHeader(GetErrStatusCode(err))
	_, err = w.Write(body) // #nosec G705: false positive; no user input
	return err
}

// SendEmptyResponse sends an empty HTTP response.
// Caller may set additional headers like `w.Header().Set("Location", "https://me")` before calling this function.
func SendEmptyResponse(w http.ResponseWriter, statusCode int) {
	w.WriteHeader(statusCode)
}

// SendLocationResponse sends an empty "201 Created" HTTP response with Location header.
//
// Looking at the APIs of various bodies, it seems that 201 Created responses usually send back the JSON description of the created resource.
// So, this function is practically never used. Thus, it will be removed in the near-future.
// One can use SendEmptyResponse instead.
// Deprecated.
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

func acceptsMsgPack(r *http.Request) bool {
	accepts := r.Header.Values(AcceptHeader)
	for i := range accepts {
		if isMsgPackContentType(accepts[i]) {
			return true
		}
	}
	return false
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
		_, err = w.Write([]byte(problem)) // #nosec G705
	}
	return
}

func acceptContentType(r *http.Request, contentType string) bool {
	acceptHeaders := r.Header.Values(AcceptHeader)
	if len(acceptHeaders) == 0 {
		return true
	}
	var mainContentType string
	ctParts := strings.SplitN(contentType, "/", 2)
	if len(ctParts) == 2 {
		mainContentType = ctParts[0] + "/*"
	}
	for i := range acceptHeaders {
		baseCT := BaseContentType(acceptHeaders[i])
		if baseCT == contentType || baseCT == mainContentType || baseCT == ContentTypeAny {
			return true
		}
	}
	return false
}

func sendCustomResponse(r *http.Request, w http.ResponseWriter, body []byte, statusCode int, contentType string) (err error) {
	if contentType != "" && acceptContentType(r, contentType) {
		w.Header().Set(ContentTypeHeader, contentType)
		w.WriteHeader(statusCode)
		_, err = w.Write([]byte(body)) // #nosec G705
		return
	}
	SendEmptyResponse(w, statusCode)
	return nil
}

// SendProblemDetails sends a response adding detailed problem description to JSON body, if available. See RFC 7807.
func SendProblemDetails(w http.ResponseWriter, r *http.Request, err error) error {
	if restErr, ok := err.(*restError); ok {
		if len(restErr.body) != 0 {
			return sendCustomResponse(r, w, restErr.body, GetErrStatusCode(restErr), restErr.contentType)
		}
		d := restErr.problemDetails.Detail
		// check in case it is somehow already filled with JSON text...
		if d != "" && d[0] != '{' {
			if restErr.err != nil {
				if embeddedStr := restErr.err.Error(); embeddedStr != "" {
					restErr.problemDetails.Detail += ": " + embeddedStr
				}
			}
			return SendProblemResponse(w, r, GetErrStatusCode(restErr), restErr.problemDetails.String())
		}
	}
	return SendProblemResponse(w, r, GetErrStatusCode(err), err.Error())
}
