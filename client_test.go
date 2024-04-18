// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

		if r.Method == "POST" {
			if requestCount == 0 {
				assert.Equal("application/json", r.Header.Get("content-type"))
			} else {
				assert.Equal("application/msgpack", r.Header.Get("content-type")) // In use
			}
			assert.Equal("a", data.Str)
		} else if r.Method == "PUT" {
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
		if r.Method == "POST" {
			assert.True(acceptsMsgPack(r) || requestCount > 0) // Discovery
			if requestCount == 0 {
				r.Header.Set("Accept", "application/json")
			}
			assert.Equal("a", data.Str)
		} else if r.Method == "PUT" {
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
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"str":"b"}`))
		} else if r.Method == http.MethodHead {
			w.Header().Set("LastModified", "1970-01-01T00:00:00")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		} else if r.Method == http.MethodPost {
			assert.Equal("b", a.Str)
			w.Header().Set("Location", "/users/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"str":"b"}`))
		} else { // PUT / PATCH
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
	client := NewClient().HTTPS(nil).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: "https://0.0.0.0:1"}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Get(ctx, "https://127.0.0.1", nil)
	assert.Contains(t, err.Error(), "0.0.0.0:1")
}

func TestSetClientCredentialAuthDownAllowedTarget(t *testing.T) {
	client := NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"0.0.0.0"}}).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: "https://0.0.0.0:1"}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Get(ctx, "https://127.0.0.1", nil)
	assert.Contains(t, err.Error(), "0.0.0.0:1")
}

func TestSetClientCredentialNotAllowedTarget(t *testing.T) {
	client := NewClient().HTTPS(nil).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: "http://0.0.0.0:1"}})
	assert.Nil(t, client.oauth2Config)
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
	client := NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}}, "garbage")
	err := client.setOauth2Auth(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2Token.AccessToken, accesToken)

	// Test client with password credentials grant
	client = NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}}, GrantPasswordCredentials)
	assert.Equal(t, len(client.oauth2Config.Scopes), 0)
	client.SetBasicAuth("user", "pass")
	err = client.setOauth2Auth(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2Token.AccessToken, accesToken)
	assert.Equal(t, client.oauth2Token.RefreshToken, refreshToken)
	req.Header.Del("Authorization")

	// Test client with refresh token grant
	client = NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}, Scopes: []string{"openid", "profile"}}, GrantRefreshToken)
	assert.Equal(t, len(client.oauth2Config.Scopes), 2)
	client.SetBasicAuth("user", "pass")
	assert.Equal(t, client.oauth2Token.RefreshToken, "")
	err = client.setOauth2Auth(ctx, req) // First try with password credentials grant without refresh_token
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2Token.AccessToken, accesToken)
	assert.Equal(t, client.oauth2Token.RefreshToken, refreshToken)
	req.Header.Del("Authorization")
	client.oauth2Token.AccessToken = ""  // Let's make the access token invalid before attempting a second request
	err = client.setOauth2Auth(ctx, req) // Second try with refresh_token grant with refresh_token included
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2Token.AccessToken, accesToken)
	req.Header.Del("Authorization")

	// Test client with default client credentials grant
	client = NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"127.0.0.1"}}).SetOauth2Conf(oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: authSrv.URL}, Scopes: []string{"openid", "profile"}})
	assert.Equal(t, len(client.oauth2Config.Scopes), 2)
	err = client.setOauth2Auth(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.oauth2Token.AccessToken, accesToken)
}

func TestGetIpFromInterface(t *testing.T) {
	theUsedInterface := "eth1"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{net.Interface{Name: "eth0"}, net.Interface{Name: "eth1"}, net.Interface{Name: "eth2"}}
		return r, nil
	}
	AddrTCP := []net.TCPAddr{net.TCPAddr{IP: net.IPv4(byte(2), byte(2), byte(2), byte(2)), Port: 0}}
	Addr := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(1), byte(1), byte(1), byte(1))}}
	Addr2 := []net.Addr{&net.IPAddr{IP: net.IPv4(byte(2), byte(2), byte(2), byte(2))}}

	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == theUsedInterface {
			return Addr2, nil
		}
		return Addr, nil
	}

	ip := getIpFromInterface("eth1")
	theIP := ip
	assert.Equal(t, AddrTCP[0].String(), theIP.IPv4.String())
}

func TestGetIpFromInterfaceNoName(t *testing.T) {
	theUsedInterface := ""
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{net.Interface{Name: "eth0"}, net.Interface{Name: "eth1"}, net.Interface{Name: "eth2"}}
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

	ip := getIpFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestGetIpFromInterfaceErrorAddr(t *testing.T) {
	theUsedInterface := "eth0"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{net.Interface{Name: "eth0"}, net.Interface{Name: "eth1"}, net.Interface{Name: "eth2"}}
		return r, nil
	}

	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		return nil, errors.New("new error")
	}

	ip := getIpFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestGetIpFromInterfaceError(t *testing.T) {
	theUsedInterface := "eth0"
	netInterfaces = func() ([]net.Interface, error) {
		return nil, errors.New("new error")
	}

	ip := getIpFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestGetIpFromInterfaceNoInt(t *testing.T) {
	theUsedInterface := "eth0"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{}
		return r, nil
	}

	ip := getIpFromInterface(theUsedInterface)
	assert.Nil(t, ip.IPv4)
	assert.Nil(t, ip.IPv6)
}

func TestCientInterface(t *testing.T) {
	theUsedInterface := "eth2"
	netInterfaces = func() ([]net.Interface, error) {
		r := []net.Interface{net.Interface{Name: "eth0"}, net.Interface{Name: "eth1"}, net.Interface{Name: "eth2"}}
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
