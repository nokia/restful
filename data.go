// Copyright 2021-2025 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/schema"
	log "github.com/sirupsen/logrus"
)

var (
	// DisallowUnknownFields is a global setting for JSON decoder.
	// It tells if unknown fields to be ignored silently (false) or to make decoding fail (true).
	// By default unknown fields are ignored.
	// See also JSON schema and OpenAPI Specification `additionalProperties: false`.
	DisallowUnknownFields = false
)

type disallowUnknownFieldsCtxKeyType string

const disallowUnknownFieldsCtxName = disallowUnknownFieldsCtxKeyType("restfulDisUnkFld")

func disallowUnknownFieldsToCtx(w http.ResponseWriter, r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), disallowUnknownFieldsCtxName, true))
}

var (
	formDecoder = schema.NewDecoder()
)

func init() {
	formDecoder.IgnoreUnknownKeys(true)
}

const bufMax = 8192

var (
	// BufIO defines whether to use buffers when reading/writing HTTP body.
	// This may be useful to avoid large memory allocations on each request.
	// However, the data received is capped at 8kB.
	// Default is false.
	//
	// Note: This is an experimental feature and may be removed in future releases without notice.
	BufIO   = false
	bufPool = sync.Pool{
		New: func() any { return make([]byte, bufMax) },
	}
)

func getContentLength(headers http.Header) (int, error) {
	clStr := headers.Get("Content-length")
	if clStr != "" {
		cl, err := strconv.Atoi(clStr)
		if err != nil {
			return 0, fmt.Errorf("invalid Content-Length: %s", clStr)
		}
		return cl, nil
	}
	return 0, nil
}

func checkContentLength(headers http.Header, maxBytes int) error {
	if maxBytes > 0 {
		cl, err := getContentLength(headers)
		if err != nil {
			return err
		}
		if cl > maxBytes {
			return fmt.Errorf("too big Content-Length: %d > %d", cl, maxBytes)
		}
	}
	return nil
}

// GetDataBytes returns []byte received.
// If maxBytes > 0 then larger body is dropped.
func GetDataBytes(headers http.Header, ioBody io.ReadCloser, maxBytes int) (body []byte, err error) {
	if ioBody == nil { // On using httptest req.Body may be missing.
		return
	}

	if err := checkContentLength(headers, maxBytes); err != nil {
		return nil, err
	}

	body, err = io.ReadAll(ioBody)
	_ = ioBody.Close()
	if err != nil {
		return body, fmt.Errorf("body read error: %s", err.Error())
	}

	if maxBytes > 0 && len(body) > maxBytes { // In case of streaming content-length is not known at the beginning.
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
		err = errors.Join(ErrUnexpectedContentType, fmt.Errorf("received: '%s'; expected: %s", recvdContentType, expectedContentType))
		return
	}
	return
}

func getData(ctx context.Context, headers http.Header, ioBody io.ReadCloser, maxBytes int, data any, request bool) error {
	if data == nil {
		_ = ioBody.Close()
		return nil
	}

	if BufIO && checkContentLength(headers, bufMax) == nil {
		if err := checkContentLength(headers, maxBytes); err != nil {
			return err
		}

		recvdContentType := GetBaseContentType(headers)
		if !isJSONContentType(recvdContentType) {
			return NewError(fmt.Errorf("unexpected Content-Type: '%s'; not JSON", recvdContentType), http.StatusBadRequest)
		}
		buf := bufPool.Get()
		defer bufPool.Put(buf)
		bytes := buf.([]byte)
		n, err := ioBody.Read(bytes)
		if err != nil && err != io.EOF {
			return NewError(fmt.Errorf("body read error: %s", err.Error()), http.StatusInternalServerError, "Failed to read request")
		}
		if err := json.Unmarshal(bytes[:n], data); err != nil {
			return NewError(err, http.StatusBadRequest, "Invalid JSON content")
		}
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
		return nil
	}

	recvdContentType := GetBaseContentType(headers)
	return getDataJSON(ctx, body, data, request, recvdContentType)
}

func getDataJSON(ctx context.Context, body []byte, data any, request bool, recvdContentType string) error {
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

	ioBody := io.NopCloser(bytes.NewReader(body))
	d := json.NewDecoder(ioBody)
	if DisallowUnknownFields || ctx.Value(disallowUnknownFieldsCtxName) != nil {
		d.DisallowUnknownFields()
	}
	err := d.Decode(data)
	if err != nil && request {
		return NewError(err, http.StatusBadRequest, "Invalid JSON content")
	}
	return err
}

// GetRequestData returns request data from HTTP request.
// Data source depends on Content-Type (CT). JSON, form data or in case of GET w/o CT query parameters are used.
// If maxBytes > 0 it blocks parsing exceedingly huge data, which could be used for DoS or memory overflow attacks.
// If error is returned then suggested HTTP status may be encapsulated in it, available via GetErrStatusCode.
func GetRequestData(req *http.Request, maxBytes int, data any) error {
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

	return getData(req.Context(), req.Header, req.Body, maxBytes, data, true)
}

// GetResponseData returns response data from JSON body of HTTP response.
// If maxBytes > 0 it blocks parsing exceedingly huge JSON data, which could be used for DoS or memory overflow attacks.
func GetResponseData(resp *http.Response, maxBytes int, data any) error {
	return getData(context.Background(), resp.Header, resp.Body, maxBytes, data, false)
}
