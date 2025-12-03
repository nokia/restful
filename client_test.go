// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/oauth2"
)

type strType struct {
	Str string `json:"str,omitempty"`
}

type innerStruct struct {
	String string            `json:"string,omitempty"`
	Array  []byte            `json:"array"`
	Map    map[string]string `json:"map"`
	Number int               `json:"number,omitempty"`
}

type structType struct {
	Str    string      `json:"str,omitempty"`
	Struct innerStruct `json:"struct"`
}

func testMsgPackDiscoveryAccepted(t testing.TB, iters int) {
	assert := assert.New(t)

	// Server
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data structType
		err := GetRequestData(r, 0, &data)
		assert.Nil(err)

		switch r.Method {
		case "POST":
			if requestCount == 0 {
				assert.Equal("application/json", r.Header.Get("content-type"))
			} else {
				assert.Equal("application/msgpack", r.Header.Get("content-type")) // In use
			}
			assert.Equal("a", data.Str)
		case "PUT":
			assert.Equal("application/msgpack", r.Header.Get("content-type")) // In use
			assert.Equal("b", data.Str)
		}
		assert.True(acceptsMsgPack(r))

		// Answer
		sendResponse(w, r, data, false)
		requestCount++
	}))
	defer srv.Close()

	respData := structType{}
	ctx := context.Background()
	client := NewClient().Root(srv.URL).MsgPack(true)
	reqData1 := structType{Str: "a", Struct: innerStruct{Number: 1, Array: []byte{1, 2, 3}}}
	reqData2 := structType{Str: "b", Struct: innerStruct{Number: 2, Array: []byte{4, 5, 6}}}

	for i := 0; i < iters; i++ {
		_, err := client.Post(ctx, "/", &reqData1, &respData)
		assert.Nil(err)
		assert.Equal(reqData1, respData)

		_, err = client.Put(ctx, "/", &reqData2, &respData)
		assert.Nil(err)
		assert.Equal(reqData2, respData)
	}
}

func Test_MsgPack_DiscoveryAccepted(t *testing.T) {
	testMsgPackDiscoveryAccepted(t, 1)
}

func Benchmark_MsgPack_DiscoveryAccepted(b *testing.B) {
	testMsgPackDiscoveryAccepted(b, 1000)
}

func testMsgPackDiscoveryRejected(t testing.TB, iters int) {
	assert := assert.New(t)

	// Server
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data structType
		err := GetRequestData(r, 0, &data)
		assert.Nil(err)

		assert.Equal("application/json", r.Header.Get("content-type")) // JSON is used all the time.
		switch r.Method {
		case "POST":
			assert.True(acceptsMsgPack(r) || requestCount > 0) // Discovery
			if requestCount == 0 {
				r.Header.Set("Accept", "application/json")
			}
			assert.Equal("a", data.Str)
		case "PUT":
			assert.False(acceptsMsgPack(r)) // Gave up
			assert.Equal("b", data.Str)
		}

		// Answer
		sendResponse(w, r, data, false)
		requestCount++
	}))
	defer srv.Close()

	respData := structType{}
	ctx := context.Background()
	client := NewClient().Root(srv.URL).MsgPack(true)
	reqData1 := structType{Str: "a", Struct: innerStruct{Number: 1, Array: []byte{1, 2, 3}}}
	reqData2 := structType{Str: "b", Struct: innerStruct{Number: 2, Array: []byte{4, 5, 6}}}

	for i := 0; i < iters; i++ {
		_, err := client.Post(ctx, "/", &reqData1, &respData)
		assert.Nil(err)
		assert.Equal(reqData1, respData)

		_, err = client.Put(ctx, "/", &reqData2, &respData)
		assert.Nil(err)
		assert.Equal(reqData2, respData)
	}
}

func Test_MsgPack_DiscoveryRejected(t *testing.T) {
	testMsgPackDiscoveryRejected(t, 1)
}

func Benchmark_MsgPack_DiscoveryRejected(b *testing.B) {
	testMsgPackDiscoveryRejected(b, 1000)
}

func TestMethods(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a strType
		err := GetRequestData(r, 0, &a)
		assert.Nil(err)

		// Answer
		w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"str":"b"}`))
		case http.MethodHead:
			w.Header().Set("LastModified", "1970-01-01T00:00:00")
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost:
			assert.Equal("b", a.Str)
			w.Header().Set("Location", "/users/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"str":"b"}`))
		default: // PUT / PATCH
			assert.Equal("b", a.Str)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"str":"b"}`))
		}
	}))
	defer srv.Close()

	reqData := strType{Str: "b"}
	respData := strType{}
	ctx := context.Background()
	client := NewClient().Root(srv.URL).SanitizeJSON().HTTPS(&HTTPSConfig{AllowLocalhostHTTP: true})
	location, err := client.Post(ctx, "/users", &reqData, &respData)
	assert.Nil(err)
	locationStr := location.String()
	assert.Equal(srv.URL+"/users/1", locationStr)
	assert.EqualValues(reqData, respData)

	_, err = Post(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	_, err = client.Put(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)
	_, err = Put(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	err = client.Patch(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)
	err = Patch(ctx, locationStr, &reqData, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	err = client.Get(ctx, locationStr, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)
	err = Get(ctx, locationStr, &respData)
	assert.Nil(err)
	assert.EqualValues(reqData, respData)

	headers, err := client.Head(ctx, locationStr)
	assert.Nil(err)
	assert.Equal("1970-01-01T00:00:00", headers["Lastmodified"][0])

	v := url.Values{}
	v.Set("Str", "b")
	_, err = client.PostForm(ctx, "/users", v, &respData)
	assert.NoError(err)
	assert.EqualValues(reqData, respData)

	v = url.Values{}
	v.Set("Str", "b")
	resp, err := client.PostFormWithFullResponse(ctx, "/users", v, nil, nil)
	assert.NoError(err)
	err = GetResponseData(resp, client.maxBytesToParse, &respData)
	assert.NoError(err)
	assert.NotNil(resp)
	assert.EqualValues(reqData, respData)

	err = client.Delete(ctx, locationStr)
	assert.Nil(err)
	err = Delete(ctx, locationStr)
	assert.Nil(err)
}

func TestHttpNotAllowed(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(ErrNonHTTPSURL, NewClient().HTTPS(nil).Root("http://localhost").Get(context.Background(), "/", nil))
	assert.Equal(ErrNonHTTPSURL, NewClient().HTTPS(&HTTPSConfig{}).Root("http://localhost").Get(context.Background(), "/", nil))
	assert.Equal(ErrNonHTTPSURL, NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"remote"}}).Root("http://localhost").Get(context.Background(), "/", nil))
	assert.Equal(ErrNonHTTPSURL, NewClient().HTTPS(&HTTPSConfig{AllowLocalhostHTTP: true}).Root("http://remote").Get(context.Background(), "/", nil))
}

func TestGetTooLongAnswer(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer
		w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"str":"b"}`))
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL)
	client.SetMaxBytesToParse(5) // Small enough
	var empty struct{}
	err := client.Get(context.Background(), "/", &empty)
	assert.NotNil(err)
}

func TestRetry(t *testing.T) {
	assert := assert.New(t)

	// Server: Rejecting with 504 `retries` times.
	reqCount := 0
	retries := 4
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("hello", r.Header.Get("User-Agent"))
		assert.False(acceptsMsgPack(r))

		if r.Method == "POST" {
			body, err := io.ReadAll(r.Body)
			assert.NoError(err)
			assert.Equal(`{"str":"hello"}`, string(body))
		}

		if reqCount < retries { // r * fail
			w.WriteHeader(http.StatusGatewayTimeout) // Retry attempt may be made
			w.Write([]byte(`{"time" :"` + time.Now().String() + `"}`))
		} else {
			w.Header().Set(ContentTypeHeader, ContentTypeApplicationJSON)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"time" :"` + time.Now().String() + `"}`))
		}
		reqCount++
	}))
	defer srv.Close()

	{ // POST: Check if body is sent on all attempts.
		reqData := strType{Str: "hello"}
		respData := strType{}
		client := NewClient().Root(srv.URL).Retry(retries, 10*time.Millisecond, 0).UserAgent("hello")
		_, err := client.Post(context.Background(), "/", &reqData, &respData)
		assert.NoError(err)
		assert.Equal(http.StatusOK, GetErrStatusCode(err))
		assert.Equal(http.StatusOK, GetErrStatusCodeElse(err, 0))
		assert.Equal(retries+1, reqCount)
	}

	{ // GET: Check if non-existing body does not cause any issue.
		reqCount = 0 // reset server's counter
		respData := strType{}
		client := NewClient().Root(srv.URL).Retry(retries, 10*time.Millisecond, 0).UserAgent("hello")
		err := client.Get(context.Background(), "/", &respData)
		assert.NoError(err)
		assert.Equal(http.StatusOK, GetErrStatusCode(err))
		assert.Equal(http.StatusOK, GetErrStatusCodeElse(err, 0))
		assert.Equal(retries+1, reqCount)
	}
}

func TestRetryStatus(t *testing.T) {
	assert.False(t, retryStatus(200))
	assert.False(t, retryStatus(404))
	assert.False(t, retryStatus(429))
	assert.False(t, retryStatus(500))

	assert.True(t, retryStatus(502))
	assert.True(t, retryStatus(503))
	assert.True(t, retryStatus(504))
}

func TestRetryResp(t *testing.T) {
	assert.False(t, retryResp(&http.Response{StatusCode: 200}))

	assert.True(t, retryResp(nil))
	assert.True(t, retryResp(&http.Response{StatusCode: 502}))
}

func TestTimeout(t *testing.T) {
	assert := assert.New(t)

	delay := 10 * time.Millisecond

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
	}))
	defer srv.Close()

	{ // GET - timeout failure
		client := NewClient().Timeout(delay / 10)
		err := client.Get(context.Background(), srv.URL, nil)
		netErr, ok := err.(net.Error)
		assert.True(ok)
		assert.True(netErr.Timeout())
	}

	{ // GET - OK
		client := NewClient().Timeout(delay * 10)
		err := client.Get(context.Background(), srv.URL, nil)
		assert.NoError(err)
	}
}

func TestRetryWithServerForwarding(t *testing.T) {
	assert := assert.New(t)

	// Server the client forwards requests to
	srvCounter := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srvCounter&1 == 0 {
			w.WriteHeader(502)
		} else {
			w.WriteHeader(200)
		}
		srvCounter++
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL).Retry(3, time.Millisecond, time.Second)
	{ // With body
		req, _ := http.NewRequest("POST", "/hello", strings.NewReader(`{"hello": "world"}`))
		req.GetBody = nil // Simulating server behavior
		resp, err := client.Do(req)
		assert.NoError(err)
		assert.Equal(200, resp.StatusCode)
	}

	{ // No body
		req, _ := http.NewRequest("DELETE", "/hello", nil)
		req.GetBody = nil // Simulating server behavior
		resp, err := client.Do(req)
		assert.NoError(err)
		assert.Equal(200, resp.StatusCode)
	}

	assert.Equal(4, srvCounter)
}

func TestMethodsError(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SendProblemResponse(w, r, http.StatusNotFound, "nope")
	}))
	defer srv.Close()

	reqData := strType{Str: "b"}
	respData := strType{}
	ctx := context.Background()
	client := NewClient().Root(srv.URL).SanitizeJSON()
	client.SetMaxBytesToParse(100000)
	location, err := client.Post(ctx, "/users", &reqData, &respData)
	assert.NotNil(err)
	assert.Nil(location)
	locationStr := "/users/1"

	_, err = client.Put(ctx, locationStr, &reqData, &respData)
	assert.NotNil(err)

	err = client.Patch(ctx, locationStr, &reqData, &respData)
	assert.NotNil(err)

	err = client.Get(ctx, locationStr, &respData)
	assert.NotNil(err)

	_, err = client.Head(ctx, locationStr)
	assert.NotNil(err)

	err = client.Delete(ctx, locationStr)
	assert.NotNil(err)
}

func TestClientBasicAuth(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(ok)
		assert.Equal("username", username)
		assert.Equal("password", password)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := NewClient().Root(srv.URL).SetBasicAuth("username", "password")
	err := client.Get(ctx, "/", nil)
	assert.NoError(err)
}

func TestCookieJar(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("token")
		assert.Equal("secret", cookie.Value)
		cookie.Value = "new secret"
		http.SetCookie(w, cookie)
	}))
	srvURL, _ := url.Parse(srv.URL)
	defer srv.Close()

	ctx := context.Background()
	jar, _ := cookiejar.New(nil)
	client := NewClient().Root(srv.URL).SetJar(jar)
	jar.SetCookies(srvURL, []*http.Cookie{{Name: "token", Value: "secret", MaxAge: 10}})
	err := client.Get(ctx, "/", nil)
	assert.NoError(err)
	assert.Equal("new secret", client.Jar().Cookies(srvURL)[0].Value)
}
func TestGetBadURL(t *testing.T) {
	assert := assert.New(t)
	respData := strType{}
	err := NewClient().Retry(3000, time.Second, 0).Get(context.Background(), ":::", &respData)
	assert.NotNil(err)
}

func TestGet500(t *testing.T) {
	assert := assert.New(t)
	const problem = `{"title":"Configuration error"}`

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acc := r.Header["Accept"]
		assert.Equal(2, len(acc)) // json and problem+json
		SendResp(w, r, NewError(nil, 500, problem), nil)
	}))
	defer srv.Close()

	c := NewClient().AcceptProblemJSON(true)
	err := c.Get(context.Background(), srv.URL, nil)
	assert.Error(err)
	assert.NotEmpty(err.Error())
	assert.Equal(problem, err.Error())
	assert.Equal(http.StatusInternalServerError, GetErrStatusCode(err))
	assert.Equal(http.StatusInternalServerError, GetErrStatusCodeElse(err, 0))
}

func TestGet500NoProblemJSON(t *testing.T) {
	assert := assert.New(t)
	const problem = `{"title":"Configuration error"}`

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acc := r.Header["Accept"]
		assert.Equal(1, len(acc)) // json only
		SendResp(w, r, NewError(nil, 500, problem), nil)
	}))
	defer srv.Close()

	c := NewClient().AcceptProblemJSON(false)
	err := c.Get(context.Background(), srv.URL, nil)
	assert.Error(err)
}

func TestGet500Details(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acc := r.Header["Accept"]
		assert.Equal(2, len(acc)) // json and problem+json
		err := NewDetailedError(nil, 500,
			ProblemDetails{
				Title:         "title",
				Detail:        "descr",
				InvalidParams: []InvalidParam{{"param1", "error text"}},
			})

		SendResp(w, r, err, nil)
	}))
	defer srv.Close()

	c := NewClient().AcceptProblemJSON(true)
	err := c.Get(context.Background(), srv.URL, nil)
	assert.Error(err)
	assert.NotEmpty(err.Error())
	assert.Equal(`{"title":"title","detail":"descr","invalidParams":[{"param":"param1","reason":"error text"}]}`, err.Error())
	assert.Equal(http.StatusInternalServerError, GetErrStatusCode(err))
	assert.Equal(http.StatusInternalServerError, GetErrStatusCodeElse(err, 0))
}

func TestSendRecv2xxBadCT(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-type", "nuku")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"str":"b"}`))
	}))
	defer srv.Close()

	var empty struct{}
	_, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, nil, &empty) // Resp body gets parsed.
	assert.NotNil(err)
	assert.Equal(http.StatusInternalServerError, GetErrStatusCode(err)) // Fake error code
	assert.Equal(0, GetErrStatusCodeElse(err, 0))
}

func TestSendRecv2xxNoDataNoCT(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var empty struct{}
	_, err := NewClient().SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, &empty, &empty) // Req and resp body gets parsed, as not nil.
	assert.Nil(err)
}

func TestH2CFailed(t *testing.T) {
	assert := assert.New(t)
	respData := strType{}
	client := NewH2CClient().Root("http://127.0.0.1:0")
	assert.Equal("h2c", client.Kind)
	err := client.Get(context.Background(), "/", &respData)
	assert.NotNil(err)
}

func TestCalcBackoff(t *testing.T) {
	assert := assert.New(t)
	c := NewClient().Retry(255, 1*time.Second, 0)
	assert.Equal((1<<0)*time.Second, c.calcBackoff(0))
	assert.Equal((1<<7)*time.Second, c.calcBackoff(7))
	assert.Equal((1<<7)*time.Second, c.calcBackoff(255))

	c = NewClient().Retry(255, 1*time.Second, 2*time.Second)
	assert.Equal((1<<0)*time.Second, c.calcBackoff(0))
	assert.Equal((1<<1)*time.Second, c.calcBackoff(7))
	assert.Equal((1<<1)*time.Second, c.calcBackoff(255))
}

func TestBroadcastRequest(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient().Root(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.BroadcastRequest(ctx, "GET", "/", nil, nil)
	assert.NoError(err)
}

func TestBroadcastRequestUnknown(t *testing.T) {
	assert := assert.New(t)
	err := NewClient().BroadcastRequest(context.Background(), "GET", "http://", nil, nil)
	assert.Error(err)
}

func TestBroadcastBadURL(t *testing.T) {
	assert := assert.New(t)
	err := NewClient().BroadcastRequest(context.Background(), "GET", ":::-1", nil, nil)
	assert.Error(err)
}

func TestCheckRedirect(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://TemporaryLocation")
		SendResp(w, r, NewError(nil, 307), nil)
	}))
	defer srv.Close()

	c := NewClient().CheckRedirect(func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	})

	var empty struct{}
	resp, err := c.SendRecv(context.Background(), http.MethodGet, srv.URL, nil, nil, &empty)
	assert.NoError(err)
	assert.Equal(http.StatusTemporaryRedirect, resp.StatusCode)

}

func TestCtxCancelBefore(t *testing.T) {
	assert := assert.New(t)

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	{ // GET - timeout failure
		client := NewClient()
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		err := client.Get(ctx, srv.URL, nil)
		assert.True(errDeadlineOrCancel(err))
	}
}

func TestSetClientCredentialAuthDown(t *testing.T) {
	client := NewClient().HTTPS(nil).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: "https://0.0.0.0:1"}}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Get(ctx, "https://127.0.0.1", nil)
	assert.Contains(t, err.Error(), "0.0.0.0:1")
}

func TestSetClientCredentialAuthDownAllowedTarget(t *testing.T) {
	client := NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"0.0.0.0"}}).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: "https://0.0.0.0:1"}}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Get(ctx, "https://127.0.0.1", nil)
	assert.Contains(t, err.Error(), "0.0.0.0:1")
}

func TestSetClientCredentialNotAllowedTarget(t *testing.T) {
	client := NewClient().HTTPS(nil).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: "http://0.0.0.0:1"}}, nil)
	assert.Nil(t, client.oauth2.config)
	assert.NotNil(t, client)
}

func TestOauth2AccessTokenReqs(t *testing.T) {
	accesToken := "yourAccessToken"
	refreshToken := "yourRefreshToken"
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		switch strings.ToLower(r.Form.Get("grant_type")) {
		case "refreshToken":
			assert.NotEqual(t, r.Form.Get("refreshToken"), "")
			assert.True(t, strings.HasPrefix(r.Header.Get("Authorization"), "Basic"))
		case "password":
			assert.NotEqual(t, r.Form.Get("username"), "")
			assert.NotEqual(t, r.Form.Get("password"), "")
		default:
			assert.True(t, strings.HasPrefix(r.Header.Get("Authorization"), "Basic"))
		}
		w.Header().Set("Content-type", "application/json")
		w.Write([]byte(`{"access_token" : "` + accesToken + `", "expires_in": 60, "refresh_Token": "` + refreshToken + `"}`))
	}))
	defer authSrv.Close()
	ctx := context.Background()
	req, _ := http.NewRequest("GET", "http://127.0.0.1", nil)

	// Test client with invalid grant, defaulting to client credentials
	client := NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}}, nil, "garbage")
	err := client.setOauth2Auth(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2.token.AccessToken, accesToken)

	// Test client with password credentials grant
	client = NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}}, nil, GrantPasswordCredentials)
	assert.Equal(t, len(client.oauth2.config.Scopes), 0)
	client.SetBasicAuth("user", "pass")
	err = client.setOauth2Auth(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2.token.AccessToken, accesToken)
	assert.Equal(t, client.oauth2.token.RefreshToken, refreshToken)
	req.Header.Del("Authorization")

	// Test client with refresh token grant
	client = NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}, Scopes: []string{"openid", "profile"}}, nil, GrantRefreshToken)
	assert.Equal(t, len(client.oauth2.config.Scopes), 2)
	client.SetBasicAuth("user", "pass")
	assert.Equal(t, client.oauth2.token.RefreshToken, "")
	err = client.setOauth2Auth(ctx, req) // First try with password credentials grant without refresh_token
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2.token.AccessToken, accesToken)
	assert.Equal(t, client.oauth2.token.RefreshToken, refreshToken)
	req.Header.Del("Authorization")
	client.oauth2.token.AccessToken = "" // Let's make the access token invalid before attempting a second request
	err = client.setOauth2Auth(ctx, req) // Second try with refresh_token grant with refresh_token included
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2.token.AccessToken, accesToken)
	req.Header.Del("Authorization")

	// Test client with default client credentials grant
	client = NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}, Scopes: []string{"openid", "profile"}}, nil)
	assert.Equal(t, len(client.oauth2.config.Scopes), 2)
	err = client.setOauth2Auth(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2.token.AccessToken, accesToken)

	// Test h2 OAuth2 client
	client = NewClient().SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}}, nil).SetOauth2H2()
	err = client.setOauth2Auth(ctx, req)
	assert.Error(t, err) // h2 is not allowed for clear text http URL.
}

func TestGetIPFromInterface(t *testing.T) {
	theUsedInterface := "eth1"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{{Name: "eth0"}, {Name: "eth1"}, {Name: "eth2"}}
		return r, nil
	}

	AddrOther := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(1), byte(1), byte(1), byte(1))}}

	AddrIP := net.IPv4(byte(2), byte(2), byte(2), byte(2))
	AddrIf := []net.Addr{&net.IPNet{IP: AddrIP}}
	AddrTCP := net.TCPAddr{IP: AddrIP}

	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == theUsedInterface {
			return AddrIf, nil
		}
		return AddrOther, nil
	}

	ip := GetIPFromInterface(theUsedInterface)
	theIP := ip
	assert.Equal(t, AddrTCP.String(), theIP.IPv4.String())
}

func TestGetIPFromInterfaceLocalhost(t *testing.T) {
	ip := GetIPFromInterface("lo")
	if ip.IPv4 != nil {
		assert.Equal(t, net.IP{127, 0, 0, 1}, ip.IPv4.IP)
	}
	if ip.IPv6 != nil {
		assert.Equal(t, net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, ip.IPv6.IP)
	}
}

func TestGetIPFromInterfaceNoName(t *testing.T) {
	theUsedInterface := ""
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{{Name: "eth0"}, {Name: "eth1"}, {Name: "eth2"}}
		return r, nil
	}
	Addr := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(1), byte(1), byte(1), byte(1))}}
	Addr2 := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(2), byte(2), byte(2), byte(2))}}

	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == theUsedInterface {
			return Addr2, nil
		}
		return Addr, nil
	}

	ip := GetIPFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestGetIPFromInterfaceErrorAddr(t *testing.T) {
	theUsedInterface := "eth0"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{{Name: "eth0"}, {Name: "eth1"}, {Name: "eth2"}}
		return r, nil
	}

	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		return nil, errors.New("new error")
	}

	ip := GetIPFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestGetIPFromInterfaceError(t *testing.T) {
	theUsedInterface := "eth0"
	netInterfaces = func() ([]net.Interface, error) {
		return nil, errors.New("new error")
	}

	ip := GetIPFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestGetIPFromInterfaceNoInt(t *testing.T) {
	theUsedInterface := "eth0"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{}
		return r, nil
	}

	ip := GetIPFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestCientInterface(t *testing.T) {
	theUsedInterface := "eth2"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{{Name: "eth0"}, {Name: "eth1"}, {Name: "eth2"}}
		return r, nil
	}
	Addr := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(1), byte(1), byte(1), byte(1))}}
	Addr2 := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(2), byte(2), byte(2), byte(2))}}

	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == theUsedInterface {
			return Addr2, nil
		}
		return Addr, nil
	}

	c := NewClientWInterface(theUsedInterface)
	assert.NotNil(t, c)
}

func startH2Server(mux *http.ServeMux, wg *sync.WaitGroup) *http.Server {
	server := &http.Server{
		Addr:    "localhost:8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2"},
		},
	}

	go func() {
		wg.Done()
		if err := server.ListenAndServeTLS("test_certs/tls.crt", "test_certs/tls.key"); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Failed to start server: %v", err)
		}
	}()
	return server
}

func startH2CServer(mux *http.ServeMux, wg *sync.WaitGroup) *http.Server {
	server := &http.Server{
		Addr:    "localhost:8440",
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	go func() {
		wg.Done()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Failed to start server: %v", err)
		}
	}()
	return server
}

func TestClients(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{"message": "Hello, world!"}
		json.NewEncoder(w).Encode(response)
	})
	var wg sync.WaitGroup
	wg.Add(2)
	h2Server := startH2Server(mux, &wg)
	h2cServer := startH2CServer(mux, &wg)
	defer func() {
		h2Server.Close()
		h2cServer.Close()
	}()

	h2Client := NewH2Client().Insecure()
	h2cClient := NewH2CClient()

	wg.Wait()
	time.Sleep(10 * time.Millisecond) // wg does not ensure that servers are ready, only that the listening may be started.

	tests := []struct {
		name      string
		client    *Client
		serverURL string
	}{
		{
			name:      "HTTP/2 Client (H2)",
			client:    h2Client,
			serverURL: "https://localhost:8443", // H2 server
		},
		{
			name:      "HTTP/2 Cleartext Client (H2C)",
			client:    h2cClient,
			serverURL: "http://localhost:8440", // H2C server
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var resp any
			err := test.client.Get(context.Background(), test.serverURL, &resp)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}

			b, _ := json.Marshal(resp)
			if string(b) != "{\"message\":\"Hello, world!\"}" {
				t.Fatalf("Unexpected response: %s", b)
			}
		})
	}
}
func TestEnableLoadBalanceRandom(t *testing.T) {
	client := NewClient()
	assert.False(t, client.LoadBalanceRandom, "LoadBalanceRandom should be false by default")

	client.EnableLoadBalanceRandom(true)
	assert.True(t, client.LoadBalanceRandom, "LoadBalanceRandom should be true after calling EnableLoadBalanceRandom")
}
func TestSetLoadBalanceTarget_NoLoadBalance(t *testing.T) {
	client := NewClient()
	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)
	target := "http://example.com/resource"
	out := client.setLoadBalanceTarget(req, target, req.URL.Hostname())
	assert.Equal(t, target, out)
}

func TestSetLoadBalanceTarget_IPAddressHost(t *testing.T) {
	client := NewClient().EnableLoadBalanceRandom(true)
	req, _ := http.NewRequest("GET", "http://127.0.0.1/resource", nil)
	target := "http://127.0.0.1/resource"
	out := client.setLoadBalanceTarget(req, target, req.URL.Hostname())
	assert.Equal(t, target, out)
}

func TestSetLoadBalanceTarget_ResolveError(t *testing.T) {
	client := NewClient().EnableLoadBalanceRandom(true)
	req, _ := http.NewRequest("GET", "http://nonexistent.invalid/resource", nil)
	target := "http://nonexistent.invalid/resource"

	// Patch net.LookupHost to simulate error
	origLookupHost := netLookupHost
	netLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return nil, errors.New("lookup error")
	}
	defer func() { netLookupHost = origLookupHost }()

	out := client.setLoadBalanceTarget(req, target, req.URL.Hostname())
	assert.Equal(t, target, out)
}

func TestSetLoadBalanceTarget_SingleIP(t *testing.T) {
	client := NewClient().EnableLoadBalanceRandom(true)
	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)
	target := "http://example.com/resource"

	// Patch net.LookupHost to return a single IP
	origLookupHost := netLookupHost
	netLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"192.0.2.1"}, nil
	}
	defer func() { netLookupHost = origLookupHost }()

	out := client.setLoadBalanceTarget(req, target, req.URL.Hostname())
	assert.NotContains(t, out, "->")
	assert.Contains(t, req.URL.Host, "example.com")
	assert.Equal(t, "example.com", req.Host)
}

func TestSetLoadBalanceTarget_DoubleIP(t *testing.T) {
	URL := "http://example-headless.com/resource"
	client := NewClient().EnableLoadBalanceRandom(strings.Contains(URL, "headless"))
	req, _ := http.NewRequest("GET", URL, nil)
	target := "http://example.com/resource"

	// Patch net.LookupHost to return a single IP
	origLookupHost := netLookupHost
	netLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"192.0.2.1", "192.0.2.2"}, nil
	}
	defer func() { netLookupHost = origLookupHost }()

	out := client.setLoadBalanceTarget(req, target, req.URL.Hostname())
	assert.Contains(t, req.URL.Host, "192.0.2.")
	assert.Equal(t, "example-headless.com", req.Host)
	assert.Regexp(t, `\[192\.0\.2\.\d+]`, out, "Expected output to contain one IP in the format '[IP]'")
}
