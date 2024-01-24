// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
)

func (c *Client) target2URLs(target string) ([]string, error) {
	if len(target) == 0 || target[0] == '/' {
		target = c.rootURL + target
	}

	commonURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	ips, err := net.LookupIP(commonURL.Hostname())
	if err != nil {
		return nil, err
	}

	targets := make([]string, len(ips))
	for i, ip := range ips {
		// replace the host in the target URI, keep original port if given.
		targetURL := commonURL
		if commonURL.Port() == "" {
			targetURL.Host = ip.String()
		} else {
			targetURL.Host = ip.String() + ":" + commonURL.Port()
		}
		targets[i] = targetURL.String()
	}
	return targets, nil
}

// SendRecvListFirst2xxParallel acts similarly to SendRecv2xx, but broadcasts the request to all targets defined.
// The first positive (2xx) response is processed, the rest are cancelled.
// If all the responses are negative, then error is returned.
func (c *Client) SendRecvListFirst2xxParallel(ctx context.Context, method string, targets []string, headers http.Header, reqData, respData interface{}) (*http.Response, error) {
	body, err := c.makeBodyBytes(reqData)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(targets))

	respChan := make(chan *http.Response)
	waitChan := make(chan interface{})

	for i := range targets {
		go func(target string, respChan chan *http.Response) {
			defer wg.Done()
			resp, err := c.sendRequestBytes(ctx, method, target, headers, &body, false)
			if err != nil || resp.StatusCode >= 300 { // Errors are silently omitted
				return
			}
			respChan <- resp
		}(targets[i], respChan)
	}

	go func(chan interface{}) {
		wg.Wait()
		waitChan <- nil
	}(waitChan)

	select {
	case resp := <-respChan:
		return resp, GetResponseData(resp, c.maxBytesToParse, respData)
	case <-waitChan:
		return nil, errors.New("no positive response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SendRecvResolveFirst2xxParallel acts similarly to SendRecv2xx, but broadcasts the request to all resolved servers of the target.
// The first positive (2xx) response is processed, the rest are cancelled.
// If all the responses are negative, then error is returned.
func (c *Client) SendRecvResolveFirst2xxParallel(ctx context.Context, method string, target string, headers http.Header, reqData, respData interface{}) (*http.Response, error) {
	targets, err := c.target2URLs(target)
	if err != nil {
		return nil, err
	}

	return c.SendRecvListFirst2xxParallel(ctx, method, targets, headers, reqData, respData)
}
