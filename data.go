// Copyright 2021-2025 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
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

// JSONOptions is the set of default options for JSON marshaling and unmarshaling for the restful package.
// Similar to the default options of the json package, but prefers "null" instead of "[]" or "{}" for nil slices and maps.
var JSONOptions []json.Options

func init() {
	JSONOptions = []json.Options{
		json.FormatNilMapAsNull(true),
		json.FormatNilSliceAsNull(true),
	}
}

var (
	// DisallowUnknownFields is a global setting for JSON decoder.
	// It tells if unknown fields to be ignored silently (false) or to make decoding fail (true).
	// By default unknown fields are ignored.
	// See also JSON schema and OpenAPI Specification `additionalProperties: false`.
	// This flag is kept for backward compatibility.
	// You are encouraged to append `json.RejectUnknownMembers(true)` to JSONOptions instead.
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
// If the content length is greater than maxBytes then it does not read the whole body.
// That may lead the connection to be closed by the peer.
func GetDataBytes(headers http.Header, ioBody io.ReadCloser, maxBytes int) (body []byte, err error) {
	if ioBody == nil { // On using httptest req.Body may be missing.
		return
	}
	defer ioBody.Close()

	if maxBytes > 0 {
		// Check Content-Length up front so an oversized non-streamed
		// body is dropped without decoding. Streamed bodies (no Content-Length)
		// go to io.ReadAll, capped by MaxBytesReader.
		cl, clErr := strconv.Atoi(headers.Get("Content-length"))
		if clErr == nil && cl > maxBytes {
			err = fmt.Errorf("%w: Content-Length: %d > %d", ErrContentTooLarge, cl, maxBytes)
			return
		}

		// Read one extra byte so an oversized body is detected without storing it.
		body, err = io.ReadAll(io.LimitReader(ioBody, int64(maxBytes)+1))
		if err != nil {
			return nil, fmt.Errorf("body read error: %s", err.Error())
		}
		if len(body) > maxBytes {
			return nil, fmt.Errorf("%w: > %d", ErrContentTooLarge, maxBytes)
		}
		return body, nil
	}

	body, err = io.ReadAll(ioBody)
	if err != nil {
		return body, fmt.Errorf("body read error: %s", err.Error())
	}
	return
}

// GetDataBytesForContentType returns []byte received, if Content-Type is matching or empty string.
// If no content then Content-Type is not checked.
// If maxBytes > 0 then larger body is not processed.
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

func getData(ctx context.Context, w http.ResponseWriter, headers http.Header, ioBody io.ReadCloser, maxBytes int, data any, request bool) error {
	if data == nil || headers.Get("Content-Length") == "0" {
		if ioBody != nil {
			drainLimited(w, ioBody, maxBytes)
			_ = ioBody.Close()
		}
		return nil
	}
	if ioBody == nil {
		return nil
	}

	return getDataJSON(ctx, w, headers, ioBody, maxBytes, data, request, GetBaseContentType(headers))
}

func getDataJSON(ctx context.Context, w http.ResponseWriter, headers http.Header, ioBody io.ReadCloser, maxBytes int, data any, request bool, recvdContentType string) error {
	defer ioBody.Close()

	// Apply the byte limit, so that not to parse huge JSON data.
	limitedBody, err := createLimitedReader(w, headers, ioBody, maxBytes)
	if err != nil {
		if request {
			return NewError(err, http.StatusInternalServerError, "Failed to read request")
		}
		return err
	}

	if !isJSONContentType(recvdContentType) {
		dropBody(limitedBody)
		err := fmt.Errorf("unexpected Content-Type: '%s'; not JSON", recvdContentType)
		if request {
			return NewError(err, http.StatusBadRequest)
		}
		return err
	}

	var opts []json.Options
	opts = append(opts, JSONOptions...)
	if DisallowUnknownFields || ctx.Value(disallowUnknownFieldsCtxName) != nil {
		opts = append(opts, json.RejectUnknownMembers(true))
	}
	err = json.UnmarshalRead(limitedBody, data, opts...)
	if err != nil {
		if maxBytes > 0 && strings.Contains(err.Error(), "request body too large") {
			dropBody(limitedBody)
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

func createLimitedReader(w http.ResponseWriter, headers http.Header, ioBody io.ReadCloser, maxBytes int) (io.ReadCloser, error) {
	if maxBytes <= 0 {
		return ioBody, nil
	}

	limitedBody := http.MaxBytesReader(w, ioBody, int64(maxBytes))

	if cl, err := strconv.Atoi(headers.Get("Content-length")); err == nil && cl > maxBytes {
		dropBody(limitedBody)
		return nil, fmt.Errorf("too big Content-Length: %d > %d", cl, maxBytes)
	}

	return limitedBody, nil
}

// drainLimited discards body bytes without buffering them. When maxBytes > 0 the
// copy stops after that many bytes so a huge or non-JSON body cannot consume excessive I/O.
// If you have a limited reader already, then use dropBody instead.
func drainLimited(w http.ResponseWriter, r io.ReadCloser, maxBytes int) {
	if r == nil {
		return
	}
	if maxBytes > 0 {
		r = http.MaxBytesReader(w, r, int64(maxBytes))
	}
	_, _ = io.Copy(io.Discard, r)
}

// dropBody discards the body bytes without buffering them. Used when the payload is
// over maxBytes so none of it is kept. Unlike drainLimited, it does not limit the I/O.
func dropBody(r io.Reader) {
	if r == nil {
		return
	}
	_, _ = io.Copy(io.Discard, r)
}

// GetRequestData returns request data from HTTP request.
// Data source depends on Content-Type (CT). JSON, form data or in case of GET w/o CT query parameters are used.
// If maxBytes > 0 it blocks parsing exceedingly huge data, which could be used for DoS or memory overflow attacks.
// If error is returned then suggested HTTP status may be encapsulated in it, available via GetErrStatusCode.
func GetRequestData(req *http.Request, maxBytes int, data any) error {
	return getRequestData(nil, req, maxBytes, data)
}

// getRequestData is the same as GetRequestData, but allows to specify the response writer for MaxBytesReader.
func getRequestData(w http.ResponseWriter, req *http.Request, maxBytes int, data any) error {
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
	return getData(req.Context(), w, req.Header, req.Body, maxBytes, data, true)
}

// GetResponseData returns response data from JSON body of HTTP response.
// If maxBytes > 0 it blocks parsing exceedingly huge JSON data, which could be used for DoS or memory overflow attacks.
func GetResponseData(resp *http.Response, maxBytes int, data any) error {
	return getData(context.Background(), nil, resp.Header, resp.Body, maxBytes, data, false)
}
