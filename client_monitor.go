// Copyright 2021- Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import "net/http"

type clientMonitor struct {
	pre  ClientMonitorFuncPre
	post ClientMonitorFuncPost
}

type clientMonitors []clientMonitor

func (m *clientMonitors) append(pre ClientMonitorFuncPre, post ClientMonitorFuncPost) {
	*m = append(*m, clientMonitor{pre: pre, post: post})
}

// ClientMonitorFuncPost is a type of user defined function to be called after the response is received.
// Response can be modified. If nil is returned, then the input response is retained.
type ClientMonitorFuncPost func(req *http.Request, resp *http.Response, err error) *http.Response

// ClientMonitorFuncPre is a type of user defined function to be called before the request is sent.
// If returns non-nil response or error, then those are returned immediately, without any further processing (e.g. sending) the request.
// Request data can be freely modified.
type ClientMonitorFuncPre func(req *http.Request) (*http.Response, error)

// Monitor adds middleware to the client.
// Functions to call before sending a request (pre), and after receiving the response (post).
func (c *Client) Monitor(pre ClientMonitorFuncPre, post ClientMonitorFuncPost) *Client {
	c.monitor.append(pre, post)
	return c
}
