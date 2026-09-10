// Copyright 2021-2025 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/schema"
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
	if data == nil || headers.Get("Content-Length") == "0" {
		if ioBody != nil {
			_, _ = io.Copy(io.Discard, ioBody)
			_ = ioBody.Close()
		}
		return nil
	}
	if ioBody == nil {
		return nil
	}

	return getDataJSON(ctx, headers, ioBody, maxBytes, data, request, GetBaseContentType(headers))
}

func getDataJSON(ctx context.Context, headers http.Header, ioBody io.ReadCloser, maxBytes int, data any, request bool, recvdContentType string) error {
	defer ioBody.Close()

	br := bufio.NewReader(ioBody)
	if _, err := br.Peek(1); errors.Is(err, io.EOF) {
		return nil
	}

	if !isJSONContentType(recvdContentType) {
		_, _ = io.ReadAll(br)
		err := fmt.Errorf("unexpected Content-Type: '%s'; not JSON", recvdContentType)
		if request {
			return NewError(err, http.StatusBadRequest)
		}
		return err
	}

	limitedBody, err := wrapBodyReader(headers, br, maxBytes)
	if err != nil {
		if request {
			return NewError(err, http.StatusInternalServerError, "Failed to read request")
		}
		return err
	}
	br = bufio.NewReader(limitedBody)

	var opts []json.Options
	if DisallowUnknownFields || ctx.Value(disallowUnknownFieldsCtxName) != nil {
		opts = append(opts, json.RejectUnknownMembers(true))
	}
	err = json.UnmarshalRead(br, data, opts...)
	if err != nil {
		if maxBytes > 0 && strings.Contains(err.Error(), "request body too large") {
			readErr := fmt.Errorf("too long content: > %d", maxBytes)
			if request {
				return NewError(readErr, http.StatusInternalServerError, "Failed to read request")
			}
			return readErr
		}
		if request {
			return NewError(err, http.StatusBadRequest, "Invalid JSON content")
		}
	}
	return err
}

func wrapBodyReader(headers http.Header, ioBody io.Reader, maxBytes int) (io.ReadCloser, error) {
	if maxBytes <= 0 {
		return io.NopCloser(ioBody), nil
	}

	cl, err := strconv.Atoi(headers.Get("Content-length"))
	if err == nil && cl > maxBytes {
		_, _ = io.ReadAll(ioBody)
		return nil, fmt.Errorf("too big Content-Length: %d > %d", cl, maxBytes)
	}

	return http.MaxBytesReader(nil, io.NopCloser(ioBody), int64(maxBytes)), nil
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
		if err := req.ParseMultipartForm(int64(maxBytes)); err != nil { // #nosec G120: use maxBytes parameter
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
