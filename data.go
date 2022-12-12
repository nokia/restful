// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/schema"
	log "github.com/sirupsen/logrus"
)

var (
	formDecoder = schema.NewDecoder()
)

func init() {
	formDecoder.IgnoreUnknownKeys(true)
}

// GetDataBytes returns []byte received.
// If maxBytes > 0 then larger body is dropped.
func GetDataBytes(headers http.Header, ioBody io.ReadCloser, maxBytes int) (body []byte, err error) {
	if ioBody == nil { // On using httptest req.Body may be missing.
		return
	}

	if maxBytes > 0 {
		var cl int
		cl, err = strconv.Atoi(headers.Get("Content-length"))
		if err == nil && cl > maxBytes {
			_, _ = io.ReadAll(ioBody)
			_ = ioBody.Close()
			err = fmt.Errorf("too big Content-Length: %d > %d", cl, maxBytes)
			return
		}
	}

	body, err = io.ReadAll(ioBody)
	defer ioBody.Close()
	if err != nil {
		return body, fmt.Errorf("body read error: %s", err.Error())
	}

	if maxBytes > 0 && len(body) > maxBytes {
		err = fmt.Errorf("too long content: %d > %d", len(body), maxBytes)
	}

	return
}

// GetDataBytesForContentType returns []byte received, if Content-Type is matching or empty string.
// If no content then Content-Type is not checked.
// If maxBytes > 0 then larger body is dropped.
func GetDataBytesForContentType(headers http.Header, ioBody io.ReadCloser, maxBytes int, expectedContentType string) (body []byte, err error) {
	body, err = GetDataBytes(headers, ioBody, maxBytes)
	if err != nil {
		return
	}
	if len(body) == 0 || expectedContentType == "" { // No need to check Content-Type
		return
	}

	recvdContentType := GetBaseContentType(headers)
	if recvdContentType != expectedContentType {
		err = fmt.Errorf("unexpected Content-Type: '%s'; Expected: %s", recvdContentType, expectedContentType)
		return
	}
	return
}

func getJSONData(headers http.Header, ioBody io.ReadCloser, maxBytes int, data interface{}, request bool) error {
	if data == nil {
		_ = ioBody.Close()
		return nil
	}

	body, err := GetDataBytes(headers, ioBody, maxBytes)
	if err != nil {
		if request {
			return NewError(err, http.StatusInternalServerError, "Failed to read request")
		}
		return err
	}
	if len(body) == 0 {
		if request {
			return NewError(nil, http.StatusBadRequest, "body expected")
		}
		return nil
	}

	recvdContentType := GetBaseContentType(headers)
	if !isJSONContentType(recvdContentType) {
		err := fmt.Errorf("unexpected Content-Type: '%s'; not JSON", recvdContentType)
		if request {
			return NewError(err, http.StatusBadRequest)
		}
		return err
	}

	if recvdContentType == ContentTypeProblemJSON {
		log.Debug("Problem: ", string(body))
	}

	err = json.Unmarshal(body, data)
	if err != nil && request {
		return NewError(err, http.StatusBadRequest, "Invalid JSON content")
	}
	return err
}

// GetRequestData returns request data from HTTP request.
// Data source depends on Content-Type (CT). JSON, form data or in case of GET w/o CT query parameters are used.
// If maxBytes > 0 it blocks parsing exceedingly huge data, which could be used for DoS or memory overflow attacks.
// If error is returned then suggested HTTP status may be encapsulated in it, available via GetErrStatusCode.
func GetRequestData(req *http.Request, maxBytes int, data interface{}) error {
	ct := GetBaseContentType(req.Header)
	switch ct {
	case "":
		if req.Method == http.MethodGet {
			return formDecoder.Decode(data, req.URL.Query())
		}
		return nil
	case ContentTypeForm:
		if err := req.ParseForm(); err != nil {
			return NewError(err, http.StatusNotAcceptable, "Bad form")
		}
		return formDecoder.Decode(data, req.PostForm)
	case ContentTypeMultipartForm:
		if err := req.ParseMultipartForm(int64(maxBytes)); err != nil {
			return NewError(err, http.StatusNotAcceptable, "Bad form")
		}
		return formDecoder.Decode(data, req.PostForm)
	}
	return getJSONData(req.Header, req.Body, maxBytes, data, true)
}

// GetResponseData returns response data from JSON body of HTTP response.
// If maxBytes > 0 it blocks parsing exceedingly huge JSON data, which could be used for DoS or memory overflow attacks.
func GetResponseData(resp *http.Response, maxBytes int, data interface{}) error {
	return getJSONData(resp.Header, resp.Body, maxBytes, data, false)
}
