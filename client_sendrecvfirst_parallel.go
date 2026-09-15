// Copyright 2021-2026 Nokia
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

func closeHTTPResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	dropBody(resp.Body)
	_ = resp.Body.Close()
}

func drainHTTPResponses(ch <-chan *http.Response) {
	for {
		select {
		case resp := <-ch:
			closeHTTPResponse(resp)
		default:
			return
		}
	}
}

// SendRecvListFirst2xxParallel acts similarly to SendRecv2xx, but broadcasts the request to all targets defined.
// The first positive (2xx) response is processed, the rest are cancelled.
// If all the responses are negative, then error is returned.
func (c *Client) SendRecvListFirst2xxParallel(ctx context.Context, method string, targets []string, headers http.Header, reqData, respData any) (*http.Response, error) {
	body, err := c.makeBodyBytes(reqData)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(targets))

	// Buffer one slot per target so extra 2xx sends never block. Later drainHTTPResponses will close the extra 2xx responses.
	respChan := make(chan *http.Response, len(targets))

	for i := range targets {
		go func(target string) {
			defer wg.Done()
			resp, err := c.sendRequestBytes(ctx, method, target, headers, &body, false)
			if err != nil || resp.StatusCode >= 300 { // Errors are silently omitted
				closeHTTPResponse(resp)
			} else {
				respChan <- resp
			}
		}(targets[i])
	}

	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	first := waitFirst2xx(ctx, respChan, waitChan)

	// Consume the winner body before cancelling the shared request context;
	// net/http may abort an unread body when the request context is done.
	var parseFirstErr error
	if first != nil {
		parseFirstErr = GetResponseData(first, c.maxBytesToParse, respData)
	}

	cancel()
	<-waitChan
	go drainHTTPResponses(respChan)

	if first == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("no positive response")
	}
	return first, parseFirstErr
}

func waitFirst2xx(ctx context.Context, respChan <-chan *http.Response, waitChan <-chan struct{}) *http.Response {
	select {
	case resp := <-respChan: // first response is ready, return it
		return resp
	case <-waitChan: // no more pending responses, no 2xx expected
		return nil
	case <-ctx.Done(): // context cancelled, no 2xx expected
		return nil
	}
}

// SendRecvResolveFirst2xxParallel acts similarly to SendRecv2xx, but broadcasts the request to all resolved servers of the target.
// The first positive (2xx) response is processed, the rest are cancelled.
// If all the responses are negative, then error is returned.
func (c *Client) SendRecvResolveFirst2xxParallel(ctx context.Context, method string, target string, headers http.Header, reqData, respData any) (*http.Response, error) {
	targets, err := c.target2URLs(target)
	if err != nil {
		return nil, err
	}

	return c.SendRecvListFirst2xxParallel(ctx, method, targets, headers, reqData, respData)
}
