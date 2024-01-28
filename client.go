// Copyright 2021-2024 Nokia
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
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nokia/restful/trace/tracecommon"
	"github.com/nokia/restful/trace/tracedata"
	"github.com/nokia/restful/trace/traceotel"
	"github.com/nokia/restful/trace/tracer"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var defaultClient = NewClient()

// TokenClient is an http.Client used to obtain OAuth2 token.
// If not set, a default client is used with 10s timeout.
// The reason for having a separate client is that Authorization Server and Resource Server may support different transport.
//
// If you want to use the same client, try
//
//	restful.TokenClient = myClient.Client
var TokenClient *http.Client = &http.Client{Timeout: 10 * time.Second}

var (
	// ErrNonHTTPSURL means that using non-https URL not allowed.
	ErrNonHTTPSURL = errors.New("non-https URL not allowed")
)

// Kind is a string representation of what kind the client is. Depending on which New() function is called.
const (
	KindBasic = ""
	KindH2    = "h2"
	KindH2C   = "h2c"
)

const (
	GrantClientCredentials   = "client_credentials"
	GrantRefreshToken        = "refresh_token"
	GrantThreeLegged         = "three_legged"
	GrantPasswordCredentials = "password"
	BasicAuth                = "basic"
)

// HTTPSConfig contains some flags that control what kind of URLs to be allowed to be used.
// Don't confuse these with TLS config.
type HTTPSConfig struct {
	// AllowHTTP flag tells whether cleartext HTTP URLs are to be allowed to be used or not.
	AllowHTTP bool
	// AllowLocalhostHTTP flag tells whether to allow cleartext HTTP transport for localhost connections.
	// If AllowHttp is true, then that overrides this flag.
	AllowLocalhostHTTP bool
	// AllowedHTTPHosts lets hostnames defined which are allowed to be accessed by cleartext HTTP.
	// If AllowHttp is true, then this setting is not considered.
	AllowedHTTPHosts []string
}

func (hc *HTTPSConfig) isAllowed(target *url.URL) bool {
	hostname := target.Hostname()
	return hc == nil ||
		target.Scheme == "https" ||
		hc.AllowHTTP ||
		slices.Contains(hc.AllowedHTTPHosts, hostname) ||
		(hc.AllowLocalhostHTTP && isLocalhost(hostname))
}

// Client is an instance of RESTful client.
type Client struct {
	// Client is the http.Client instance used by restful.Client.
	// Do not touch it, unless really necessary.
	Client *http.Client

	// Kind is a string representation of what kind the client is. Depending on which New() function is called.
	// Changing its value does not change client kind.
	Kind string

	httpsCfg          *HTTPSConfig
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
	monitor           clientMonitors
	oauth2Config      *oauth2.Config
	grantType         string
	oauth2Token       oauth2.Token
	oauth2TokenMutex  sync.RWMutex
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
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	t.DialContext = dialer.DialContext

	var rt http.RoundTripper = t
	if isTraced && tracer.GetOTel() {
		rt = otelhttp.NewTransport(t)
	}

	c := &Client{Kind: KindBasic}
	c.Client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: rt,
	}

	c.acceptProblemJSON = true /* backward compatible */
	return c
}

// NewH2Client creates a RESTful client instance, forced to use HTTP2 with TLS (H2) (a.k.a. prior knowledge).
func NewH2Client() *Client {
	c := &Client{Kind: KindH2}
	var rt http.RoundTripper = &h2Transport
	if isTraced && tracer.GetOTel() {
		rt = otelhttp.NewTransport(rt)
	}
	c.Client = &http.Client{Transport: rt}
	return c
}

// NewH2CClient creates a RESTful client instance, forced to use HTTP2 Cleartext (H2C).
func NewH2CClient() *Client {
	c := &Client{Kind: KindH2C}
	var rt http.RoundTripper = &h2CTransport
	if isTraced && tracer.GetOTel() {
		rt = otelhttp.NewTransport(rt)
	}
	c.Client = &http.Client{Transport: rt}
	return c
}

// UserAgent to be sent as User-Agent HTTP header. If not set then default Go client settings are used.
func (c *Client) UserAgent(userAgent string) *Client {
	c.userAgent = userAgent
	return c
}

// CheckRedirect set client CheckRedirect field
// CheckRedirect specifies the policy for handling redirects.
func (c *Client) CheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) *Client {
	c.Client.CheckRedirect = checkRedirect
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

// HTTPS lets you set what kind of URLs are allowed to be used.
// If HTTPS is not called, there are no restrictions applied.
// If HTTPS is called with nil config, then cleartext HTTP is not allowed.
//
//	cLocal := restful.NewClient().Root(peerURL).HTTPS(restful.HTTPSConfig{AllowLocalhostHTTP: true})
//	cTest := restful.NewClient().Root(peerURL).HTTPS(restful.HTTPSConfig{AllowedHTTPHosts: []string{"test"}})
func (c *Client) HTTPS(config *HTTPSConfig) *Client {
	if config == nil {
		c.httpsCfg = &HTTPSConfig{}
	} else {
		c.httpsCfg = config
	}
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
	c.Client.Timeout = timeout
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

// SetOauth2Conf makes client obtain OAuth2 access token for given client credentials.
// Either on first request to be sent or later when the obtained access token is expired.
//
// Make sure encrypted transport is used, e.g. the link is https.
// If client's HTTPS() has been called earlier, then token URL is checked accordingly.
// If token URL does not meet those requirements, then client credentials auth is not activated and error log is printed.
func (c *Client) SetOauth2Conf(config oauth2.Config, grant string) *Client {
	if c.httpsCfg != nil {
		tokenURL, err := url.Parse(config.Endpoint.TokenURL)
		if err == nil {
			if !c.httpsCfg.isAllowed(tokenURL) {
				log.Error("token URL: ", ErrNonHTTPSURL)
				return c
			}
		} else {
			log.Error("token URL is not valid: ", err)
		}
	}
	c.grantType = grant
	c.oauth2Config = &config
	return c
}

// SetJar sets cookie jar for the client.
func (c *Client) SetJar(jar http.CookieJar) *Client {
	c.Client.Jar = jar
	return c
}

// Jar gets cookie jar of the client.
func (c *Client) Jar() http.CookieJar {
	return c.Client.Jar
}

func errDeadlineOrCancel(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func traceFromContext(ctx context.Context) (trace tracedata.TraceData) {
	if l := L(ctx); l != nil {
		trace = l.Trace
	} else if tracer.GetOTel() {
		trace = traceotel.NewFromContext(ctx)
	}
	return
}

func traceFromContextOrRequestOrRandom(req *http.Request) (trace tracedata.TraceData) {
	trace = traceFromContext(req.Context())
	if trace == nil || reflect.ValueOf(trace).IsNil() {
		trace = tracer.NewFromRequestOrRandom(req)
	}
	return
}

func doSpan(req *http.Request) (*http.Request, string) {
	trace := traceFromContextOrRequestOrRandom(req)

	if trace.IsReceived() || isTraced {
		return trace.Span(req)
	}
	return req, tracecommon.NewTraceID()
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

func (c *Client) obtainOauth2Token(ctx context.Context, req *http.Request) error {
	// Release reader lock, obtain writer lock instead. Revert to reader lock when finished.
	c.oauth2TokenMutex.RUnlock()
	c.oauth2TokenMutex.Lock()
	defer func() {
		c.oauth2TokenMutex.Unlock()
		c.oauth2TokenMutex.RLock()
	}()

	// Check if token has been obtained by another instance while waiting for writer lock.
	if !c.oauth2Token.Valid() {
		oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, TokenClient)
		var token *oauth2.Token
		var err error
		switch c.grantType {
		case GrantClientCredentials:
			conf := clientcredentials.Config{ClientID: c.oauth2Config.ClientID, ClientSecret: c.oauth2Config.ClientSecret, TokenURL: c.oauth2Config.Endpoint.TokenURL, Scopes: c.oauth2Config.Scopes}
			token, err = conf.TokenSource(oauthCtx).Token()
			if err != nil {
				return err
			}
		case GrantRefreshToken:
			if c.oauth2Token.RefreshToken == "" {
				t, err := c.oauth2Config.PasswordCredentialsToken(ctx, c.username, c.password)
				if err != nil {
					log.Panic(err)
				}
				c.oauth2Token = *t
				return nil
			}
			token, err = c.oauth2Config.TokenSource(oauthCtx, &c.oauth2Token).Token()
			if err != nil {
				return err
			}
		}
		c.oauth2Token = *token
	}
	return nil
}

func (c *Client) setOauth2Auth(ctx context.Context, req *http.Request) error {
	// Reader lock
	c.oauth2TokenMutex.RLock()
	defer c.oauth2TokenMutex.RUnlock()

	if !c.oauth2Token.Valid() { // Valid adds some extra time for client (10s)
		if err := c.obtainOauth2Token(ctx, req); err != nil {
			return err
		}
	}
	c.oauth2Token.SetAuthHeader(req)
	return nil
}

// Do sends an HTTP request and returns an HTTP response.
// All the rules of http.Client.Do() apply.
// If URL of req is relative path then root defined at client.Root is added as prefix.
// If request context contains tracing headers then adds them to the request with a new span ID.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := ctx.Err(); err != nil { // Do not start the Dial if context cancelled/deadlined already.
		return nil, err
	}

	if req.Header == nil {
		req.Header = make(http.Header)
	}

	target, err := c.setReqTarget(req)
	if err != nil {
		return nil, err
	}

	c.setUA(req)

	body := c.cloneBody(req)

	if c.username != "" && c.oauth2Config == nil {
		req.SetBasicAuth(c.username, c.password)
	}
	if c.oauth2Config != nil {
		if err := c.setOauth2Auth(ctx, req); err != nil {
			return nil, err
		}
	}

	for i := len(c.monitor) - 1; i >= 0; i-- {
		if c.monitor[i].pre != nil {
			resp, err := c.monitor[i].pre(req)
			if resp != nil || err != nil {
				return resp, err
			}
		}
	}

	req, spanStr := doSpan(req)
	resp, err := c.doLog(spanStr, req, body, target)

	for i := 0; i < len(c.monitor); i++ {
		if c.monitor[i].post != nil {
			newResp := c.monitor[i].post(req, resp, err)
			if newResp != nil {
				resp = newResp
			}
		}
	}

	return resp, err
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

func (c *Client) doLog(spanStr string, req *http.Request, body io.ReadCloser, target string) (*http.Response, error) {
	log.Debugf("[%s] Sent req: %s %s", spanStr, req.Method, target)
	resp, err := c.doWithRetry(req, body, spanStr, target)
	if err != nil {
		log.Debugf("[%s] Fail req: %s %s", spanStr, req.Method, target)
	} else {
		log.Debugf("[%s] Recv rsp: %s", spanStr, resp.Status)
	}
	return resp, err
}

func isLocalhost(hostname string) bool {
	ip := net.ParseIP(hostname)
	if ip == nil { // Not IP address
		return strings.ToLower(hostname) == "localhost"
	}
	return ip.IsLoopback()
}

func (c *Client) setReqTarget(req *http.Request) (target string, err error) {
	target = req.URL.String()
	if len(target) == 0 || target[0] == '/' {
		target = c.rootURL + target
		req.URL, err = url.Parse(target)
	}

	if !c.httpsCfg.isAllowed(req.URL) {
		return target, ErrNonHTTPSURL
	}
	return
}

func (c *Client) do(req *http.Request) (resp *http.Response, err error) {
	if ctxErr := req.Context().Err(); ctxErr != nil { // Do not start the Dial if context cancelled/deadlined already.
		err = ctxErr
		return
	}
	resp, err = c.Client.Do(req)

	// Workaround for https://github.com/golang/go/issues/36026
	if err, ok := err.(net.Error); ok && err.Timeout() {
		c.Client.CloseIdleConnections()
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
	return c.sendRequestBytes(ctx, method, target, headers, &body, true)
}

func (c *Client) sendRequestBytes(ctx context.Context, method string, target string, headers http.Header, body *[]byte, freeBody bool) (*http.Response, error) {
	var req *http.Request
	var err error
	if len(*body) > 0 {
		req, err = http.NewRequestWithContext(ctx, method, target, bytes.NewReader(*body))
		if err != nil {
			return nil, err
		}

		addCT(req, method, headers, *body)

		if freeBody {
			*body = nil // Set reference nil, req is the sole owner of the byte slice.
		}
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

	return c.Do(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(reqData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", ContentTypeForm)

	resp, err := c.Do(req)
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
