// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"errors"
	"net/http"
)

// SendRecvListFirst2xxSequential acts similarly to SendRecv2xx, but sends the request to the targets one-by-one, till a positive (2xx) response is received.
// If all the responses are negative, then error is returned.
// You may feed the list to a shuffle function before calling, if order is not defined.
func (c *Client) SendRecvListFirst2xxSequential(ctx context.Context, method string, targets []string, headers http.Header, reqData, respData interface{}) (*http.Response, error) {
	body, err := c.makeBodyBytes(reqData)
	if err != nil {
		return nil, err
	}

	for i := range targets {
		resp, err := c.sendRequestBytes(ctx, method, targets[i], headers, &body, false)
		if err != nil || resp.StatusCode >= 300 { // Errors are silently omitted
			continue
		}
		return resp, GetResponseData(resp, c.maxBytesToParse, respData)
	}
	return nil, errors.New("no positive response")
}

// SendRecvResolveFirst2xxSequential acts similarly to SendRecv2xx, but sends the request to the resolved targets one-by-one, till a positive (2xx) response is received.
// If all the responses are negative, then error is returned.
// You may feed the list to a shuffle function before calling, if order is not defined.
func (c *Client) SendRecvResolveFirst2xxSequential(ctx context.Context, method string, target string, headers http.Header, reqData, respData interface{}) (*http.Response, error) {
	targets, err := c.target2URLs(target)
	if err != nil {
		return nil, err
	}

	return c.SendRecvListFirst2xxSequential(ctx, method, targets, headers, reqData, respData)
}
