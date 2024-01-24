// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import "context"

// PingList sends a HTTP GET requests to a list of URLs and expects 2xx responses for each.
// This way one can check liveness components.
func (c *Client) PingList(ctx context.Context, targets []string) error {
	for _, url := range targets {
		err := c.Get(ctx, url, nil)
		if err != nil {
			return DetailError(err, "error checking url "+url)
		}
	}
	return nil
}

// PingList sends a HTTP GET requests to a list of URLs and expects 2xx responses for each.
// This way one can check liveness components.
func PingList(ctx context.Context, targets []string) error {
	return defaultClient.PingList(ctx, targets)
}
