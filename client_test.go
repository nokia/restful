// Copyright 2021-2024 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package restful

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type strType struct {
	Str string
}

type structType struct {
	Str    string `json:"str,omitempty"`
	Struct struct {
		S string            `json:"s,omitempty"`
		A []byte            `json:"a"`
		M map[string]string `json:"m"`
	}
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

		if r.Method == "POST" {
			body, err := io.ReadAll(r.Body)
			assert.NoError(err)
			assert.Equal(`{"Str":"hello"}`, string(body))
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
	client := NewClient().HTTPS(nil).SetClientCredentialAuth(Oauth2Config{ClientID: "id", ClientSecret: "secret", TokenURL: "https://0.0.0.0:1"})
	assert.Equal(t, len(client.clientCredConfig.Scopes), 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Get(ctx, "https://127.0.0.1", nil)
	assert.Contains(t, err.Error(), "0.0.0.0:1")
}

func TestSetClientCredentialAuthDownAllowedTarget(t *testing.T) {
	client := NewClient().HTTPS(&HTTPSConfig{AllowedHTTPHosts: []string{"0.0.0.0"}}).SetClientCredentialAuth(Oauth2Config{ClientID: "id", ClientSecret: "secret", TokenURL: "https://0.0.0.0:1", Scopes: []string{"openid", "profile"}})
	assert.Equal(t, len(client.clientCredConfig.Scopes), 2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Get(ctx, "https://127.0.0.1", nil)
	assert.Contains(t, err.Error(), "0.0.0.0:1")
}

func TestSetClientCredentialNotAllowedTarget(t *testing.T) {
	client := NewClient().HTTPS(nil).SetClientCredentialAuth(Oauth2Config{ClientID: "id", ClientSecret: "secret", TokenURL: "http://0.0.0.0:1"})
	assert.Nil(t, client.clientCredConfig)
	assert.NotNil(t, client)
}
