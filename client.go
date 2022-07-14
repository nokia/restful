// Copyright 2021 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

var defaultClient = NewClient()

// Client is an instance of RESTful client.
type Client struct {
	client            *http.Client
	sanitizeJSON      bool
	rootURL           string
	userAgent         string
	username          string
	password          string
	maxBytesToParse   int
	retries           int
	retryBackoffInit  time.Duration
	retryBackoffMax   time.Duration
	acceptProblemJSON bool
}

var h2CTransport = http2.Transport{
	AllowHTTP: true,
	DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		// Skip TLS dial
		return net.DialTimeout(network, addr, 2*time.Second)
	},
}

var h2Transport = http2.Transport{
	DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		cn, err := tls.DialWithDialer(&dialer, network, addr, cfg)
		if err != nil {
			return nil, err
		}
		if err := cn.Handshake(); err != nil {
			return nil, err
		}
		if !cfg.InsecureSkipVerify {
			if err := cn.VerifyHostname(cfg.ServerName); err != nil {
				return nil, err
			}
		}
		state := cn.ConnectionState()
		if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %q; want %q", p, http2.NextProtoTLS)
		}
		return cn, nil
	},
}

// NewClient creates a RESTful client instance.
// The instance has a semi-permanent transport TCP connection.
func NewClient() *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100

	c := &Client{}
	c.client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: t,
	}
	c.acceptProblemJSON = true /* backward compatible */
	return c
}

// NewH2Client creates a RESTful client instance, forced to use HTTP2 with TLS (H2) (a.k.a. prior knowledge).
func NewH2Client() *Client {
	c := &Client{}
	c.client = &http.Client{Transport: &h2Transport}
	return c
}

// NewH2CClient creates a RESTful client instance, forced to use HTTP2 Cleartext (H2C).
func NewH2CClient() *Client {
	c := &Client{}
	c.client = &http.Client{Transport: &h2CTransport}
	return c
}

// UserAgent to be sent as User-Agent HTTP header. If not set then default Go settings are used.
func (c *Client) UserAgent(userAgent string) *Client {
	c.userAgent = userAgent
	return c
}

// CheckRedirect set client CheckRedirect field
// CheckRedirect specifies the policy for handling redirects.
func (c *Client) CheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) *Client {
	c.client.CheckRedirect = checkRedirect
	return c
}

// AcceptProblemJSON sets whether client is to send "Accept: application/problem+json" header.
// I.e. tells the server whether your client wants RFC 7807 answers.
func (c *Client) AcceptProblemJSON(acceptProblemJSON bool) *Client {
	c.acceptProblemJSON = acceptProblemJSON
	return c
}

// Root sets default root URL for client. Returns object instance, just in case you need that.
// You may use it this way: client := New().Root(...) or just client.Root(...)
func (c *Client) Root(rootURL string) *Client {
	c.rootURL = rootURL
	return c
}

// Retry sets the number of times and backoff sleep a client retransmits the request
// if connection failed or gateway returned errors 502, 503 or 504.
//
// Truncated binary exponential backoff is done. I.e. sleep = 2^r * backoffInit,
// where r is the number of retries-1, capped at backoffMax.
// If backoffMax < backoffInit, e.g. 0, then set to 2^7*backoffInit.
//
// Don't set retries or backoff too high.
// You may use it this way: client := New().Retry(3, 500 * time.Millisecond, 2 * time.Second) or just client.Retry(3, 1 * time.Second, 0)
func (c *Client) Retry(retries int, backoffInit time.Duration, backoffMax time.Duration) *Client {
	c.retries = retries
	if backoffMax < backoffInit {
		backoffMax = backoffInit * (1 << 7)
	}
	c.retryBackoffInit = backoffInit
	c.retryBackoffMax = backoffMax
	return c
}

// Timeout sets client timeout.
// Timeout and request context timeout are similar concepts.
// However, Timeout specified here applies to a single attempt, i.e. if Retry is used, then applies to each attempt separately, while context applies to all attempts together.
func (c *Client) Timeout(timeout time.Duration) *Client {
	c.client.Timeout = timeout
	return c
}

// SanitizeJSON enables JSON sanitization.
// See details at SanitizeJSONString.
func (c *Client) SanitizeJSON() *Client {
	c.sanitizeJSON = true
	return c
}

// SetBasicAuth sets Authorization header for each request sent by the client.
// String username:password sent in HTTP header.
//
// Make sure encrypted transport is used, e.g. the link is https.
func (c *Client) SetBasicAuth(username, password string) *Client {
	c.username = username
	c.password = password
	return c
}

// SetJar sets cookie jar for the client.
func (c *Client) SetJar(jar http.CookieJar) *Client {
	c.client.Jar = jar
	return c
}

// Jar gets cookie jar of the client.
func (c *Client) Jar() http.CookieJar {
	return c.client.Jar
}

func errDeadlineOrCancel(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func doSpan(ctx context.Context, req *http.Request) string {
	trace := newTraceFromCtx(ctx)
	span := trace.span()
	if trace.received || log.IsLevelEnabled(log.TraceLevel) {
		span.addHeader(req.Header)
	}
	return span.string()
}

func (c *Client) setUA(req *http.Request) {
	if c.userAgent != "" && req.Header.Get("User-agent") == "" {
		req.Header.Set("User-agent", c.userAgent)
	}
}

func (c *Client) cloneBody(req *http.Request) io.ReadCloser {
	var body io.ReadCloser
	if c.retries > 0 && req.Body != nil {
		body, _ = req.GetBody()
	}
	return body
}

func retryStatus(statusCode int) bool {
	return (statusCode >= 502 && statusCode <= 504)
}

func retryResp(resp *http.Response) bool {
	return resp == nil || retryStatus(resp.StatusCode)
}

// Do sends an HTTP request and returns an HTTP response.
// All the rules of http.Client.Do() applies.
// If URL of req is relative path then root defined at client.Root is added as prefix.
// Do(ctx, req) is somewhat like Do(req.WithContext(ctx)) of http.Client.
// If ctx contains tracing headers of Lambda class then adds them to the request with a new span ID.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)

	if req.Header == nil {
		req.Header = make(http.Header)
	}

	target, err := c.setReqTarget(req)
	if err != nil {
		return nil, err
	}

	c.setUA(req)

	body := c.cloneBody(req)

	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	return c.doLog(ctx, req, body, target)
}

func (c *Client) doWithRetry(req *http.Request, body io.ReadCloser, spanStr, target string) (*http.Response, error) {
	resp, err := c.do(req)

	for retries := 0; retries < c.retries && !errDeadlineOrCancel(err) && retryResp(resp); retries++ { // Gateway error or overload responses.
		if resp != nil {
			_ = resp.Body.Close()
		}

		req.Body = body
		body = c.cloneBody(req)

		time.Sleep(c.calcBackoff(retries))
		log.Debugf("[%s] Send rty(%d): %s %s: err=%v", spanStr, retries, req.Method, target, err)
		resp, err = c.do(req)
	}

	return resp, err
}

func (c *Client) doLog(ctx context.Context, req *http.Request, body io.ReadCloser, target string) (*http.Response, error) {
	spanStr := doSpan(ctx, req)
	log.Debugf("[%s] Sent req: %s %s", spanStr, req.Method, target)
	resp, err := c.doWithRetry(req, body, spanStr, target)
	if err != nil {
		log.Debugf("[%s] Fail req: %s %s", spanStr, req.Method, target)
	} else {
		log.Debugf("[%s] Recv rsp: %s", spanStr, resp.Status)
	}
	return resp, err
}

func (c *Client) setReqTarget(req *http.Request) (target string, err error) {
	target = req.URL.String()
	if len(target) == 0 || target[0] == '/' {
		target = c.rootURL + target
		req.URL, err = url.Parse(target)
	}
	return
}

func (c *Client) do(req *http.Request) (resp *http.Response, err error) {
	resp, err = c.client.Do(req)

	// Workaround for https://github.com/golang/go/issues/36026
	if err, ok := err.(net.Error); ok && err.Timeout() {
		c.client.CloseIdleConnections()
	}

	return
}

func (c *Client) calcBackoff(retry int) time.Duration {
	backoff := (1 << retry) * c.retryBackoffInit
	if backoff > c.retryBackoffMax || backoff == 0 { // Shifting left might result in zero, if int size (e.g. 64 bits) exceeded.
		backoff = c.retryBackoffMax
	}
	return backoff
}

func (c *Client) makeBodyBytes(data interface{}) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	if c.sanitizeJSON {
		body = SanitizeJSONBytes(body)
	}
	if len(body) <= len("{}") {
		return nil, nil
	}

	return body, nil
}

func addCT(req *http.Request, method string, headers http.Header, body []byte) {
	if headers == nil || headers.Get(ContentTypeHeader) == "" {
		if method == http.MethodPatch {
			if len(body) != 0 && body[0] == '[' && bytes.Contains(body, []byte(`"op"`)) {
				req.Header.Set(ContentTypeHeader, ContentTypePatchJSON)
			} else {
				req.Header.Set(ContentTypeHeader, ContentTypeMergeJSON)
			}
		} else {
			req.Header.Set(ContentTypeHeader, ContentTypeApplicationJSON)
		}
	}
}

// SendRequest sends an HTTP request with JSON data.
// Target URL and headers to be added can be defined.
// It is the caller's responsibility to close http.Response.Body.
func (c *Client) SendRequest(ctx context.Context, method string, target string, headers http.Header, data interface{}) (*http.Response, error) {
	body, err := c.makeBodyBytes(data)
	if err != nil {
		return nil, err
	}
	return c.sendRequestBytes(ctx, method, target, headers, body)
}

func (c *Client) sendRequestBytes(ctx context.Context, method string, target string, headers http.Header, body []byte) (*http.Response, error) {
	var req *http.Request
	var err error
	if len(body) > 0 {
		req, err = http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		addCT(req, method, headers, body)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			return nil, err
		}
	}

	for header, values := range headers {
		req.Header[header] = append(req.Header[header], values...)
	}

	if req.Header.Get(AcceptHeader) == "" {
		req.Header.Set(AcceptHeader, ContentTypeApplicationJSON)
		if c.acceptProblemJSON {
			req.Header.Add(AcceptHeader, ContentTypeProblemJSON)
		}
	}

	return c.Do(ctx, req)
}

// SendRecv sends request with given data and returns response data.
// Caller may define headers to be added to the request.
// Received response is returned. E.g. resp.StatusCode.
// If request data is empty then request body is not sent in HTTP request.
// If response data is nil then response body is omitted.
func (c *Client) SendRecv(ctx context.Context, method string, target string, headers http.Header, reqData, respData interface{}) (*http.Response, error) {
	resp, err := c.SendRequest(ctx, method, target, headers, reqData)
	if err != nil {
		return nil, err
	}
	return resp, GetResponseData(resp, c.maxBytesToParse, respData)
}

// SendRecv2xx sends request with given data and returns response data and expects a 2xx response code.
// Caller may define headers to be added to the request.
// Received response is returned. E.g. resp.Header["Location"].
// If request data is nil then request body is not sent in HTTP request.
// If response data is nil then response body is omitted.
func (c *Client) SendRecv2xx(ctx context.Context, method string, target string, headers http.Header, reqData, respData interface{}) (*http.Response, error) {
	resp, err := c.SendRequest(ctx, method, target, headers, reqData)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		detail := ""
		body, err := GetDataBytesForContentType(resp.Header, resp.Body, c.maxBytesToParse, ContentTypeProblemJSON)
		if err == nil {
			detail = string(body)
			if len(detail) > 0 && detail[0] == '{' { // Preserve incoming problem detail
				return nil, NewError(nil, resp.StatusCode, detail)
			}
		}
		return nil, NewError(fmt.Errorf("unexpected response: %s", resp.Status), resp.StatusCode, detail)
	}
	return resp, GetResponseData(resp, c.maxBytesToParse, respData)
}

// BroadcastRequest sends a HTTP request with JSON data to all of the IP addresses received in the DNS response
// for the target URI and expects 2xx responses, returning error in any other case.
// This is meant for sending notifications to headless kubernetes services. Response data is not returned or saved.
func (c *Client) BroadcastRequest(ctx context.Context, method string, target string, headers http.Header, reqData interface{}) error {
	targets, err := c.target2URLs(target)
	if err != nil {
		return err
	}

	for i := range targets {
		resp, err := c.SendRecv2xx(ctx, method, targets[i], headers, reqData, nil)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// PostForm posts data as "application/x-www-form-urlencoded", expects response as "application/json", if any.
// Returns Location URL, if received.
func (c *Client) PostForm(ctx context.Context, target string, reqData url.Values, respData interface{}) (*url.URL, error) {
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(reqData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", ContentTypeForm)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, NewError(err, resp.StatusCode, "")
	}

	if err := GetResponseData(resp, c.maxBytesToParse, respData); err != nil {
		return nil, err
	}

	location, _ := resp.Location() // error is omitted
	return location, nil
}

// Post sends a POST request.
// Primarily designed to create a resource and return its Location. That may be nil.
func (c *Client) Post(ctx context.Context, target string, reqData, respData interface{}) (*url.URL, error) {
	resp, err := c.SendRecv2xx(ctx, http.MethodPost, target, nil, reqData, respData)
	if resp != nil {
		location, _ := resp.Location()
		return location, err
	}
	return nil, err
}

// Post sends a POST request.
// Primarily designed to create a resource and return its Location. That may be nil.
func Post(ctx context.Context, target string, reqData, respData interface{}) (*url.URL, error) {
	return defaultClient.Post(ctx, target, reqData, respData)
}

// Put updates a resource. Might return Location of created resource, otherwise nil.
func (c *Client) Put(ctx context.Context, target string, reqData, respData interface{}) (*url.URL, error) {
	resp, err := c.SendRecv2xx(ctx, http.MethodPut, target, nil, reqData, respData)
	if resp != nil {
		location, _ := resp.Location()
		return location, err
	}
	return nil, err
}

// Put updates a resource. Might return Location of created resource, otherwise nil.
func Put(ctx context.Context, target string, reqData, respData interface{}) (*url.URL, error) {
	return defaultClient.Put(context.Background(), target, reqData, respData)
}

// Patch partially updates a resource.
// Supports RFCs 6902 and 7386 only. Automatically chooses Content-Type header depending on the content itself.
//
// WARNING: The chosen Content-Type header may not be what caller needs.
// One may prefer SendRecv2xx instead.
func (c *Client) Patch(ctx context.Context, target string, reqData, respData interface{}) error {
	_, err := c.SendRecv2xx(ctx, http.MethodPatch, target, nil, reqData, respData)
	return err
}

// Patch partially updates a resource.
func Patch(ctx context.Context, target string, reqData, respData interface{}) error {
	return defaultClient.Patch(ctx, target, reqData, respData)
}

// Get gets a resource.
func (c *Client) Get(ctx context.Context, target string, respData interface{}) error {
	_, err := c.SendRecv2xx(ctx, http.MethodGet, target, nil, nil, respData)
	return err
}

// Get gets a resource.
func Get(ctx context.Context, target string, respData interface{}) error {
	return defaultClient.Get(ctx, target, respData)
}

// Head checks a resource. Returns headers map.
func (c *Client) Head(ctx context.Context, target string) (map[string][]string, error) {
	resp, err := c.SendRecv2xx(ctx, http.MethodHead, target, nil, nil, nil)
	if err == nil && resp != nil {
		return resp.Header, err
	}
	return map[string][]string{}, err
}

// Delete deletes a resource.
func (c *Client) Delete(ctx context.Context, target string) error {
	_, err := c.SendRecv2xx(ctx, http.MethodDelete, target, nil, nil, nil)
	return err
}

// Delete deletes a resource.
func Delete(ctx context.Context, target string) error {
	return defaultClient.Delete(ctx, target)
}

// SetMaxBytesToParse sets a limit on parsing. Setting a value lower the risks of CPU-targeting DoS attack.
func (c *Client) SetMaxBytesToParse(max int) *Client {
	c.maxBytesToParse = max
	return c
}
