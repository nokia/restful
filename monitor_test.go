package restful

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMonitorsWithRouter(t *testing.T) {
	assert := assert.New(t)

	var preCount, postCount int
	pre := func(w http.ResponseWriter, r *http.Request) *http.Request { preCount++; return nil }
	post := func(w http.ResponseWriter, r *http.Request, statusCode int) { postCount++ }
	handlerA := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	handlerB := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }

	mux := NewRouter().Monitor(pre, post).Monitor(pre, post)
	mux.HandleFunc("/a", handlerA)
	mux.HandleFunc("/b", handlerB)

	{
		req, _ := http.NewRequest("GET", "/a", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(200, rr.Code)
	}

	{
		req, _ := http.NewRequest("GET", "/b", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(204, rr.Code)
	}

	assert.Equal(4, preCount)
	assert.Equal(4, postCount)
}

func TestMonitorsWithServer(t *testing.T) {
	assert := assert.New(t)

	var preCount, postCount int
	pre := func(w http.ResponseWriter, r *http.Request) *http.Request { preCount++; return nil }
	post := func(w http.ResponseWriter, r *http.Request, statusCode int) { postCount++ }
	handlerA := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	handlerB := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }

	mux := NewRouter()
	mux.HandleFunc("/a", handlerA)
	mux.HandleFunc("/b", handlerB)

	s := NewServer().Addr(":56789").Monitor(pre, post).Monitor(pre, post).Handler(mux).Monitor(pre, post).Monitor(pre, post)
	go s.ListenAndServe()
	time.Sleep(time.Second)

	{
		resp, _ := http.Get("http://127.0.0.1:56789/a")
		assert.Equal(200, resp.StatusCode)
	}

	{
		resp, _ := http.Get("http://127.0.0.1:56789/b")
		assert.Equal(204, resp.StatusCode)
	}

	s.Shutdown(context.Background())

	assert.Equal(8, preCount)
	assert.Equal(8, postCount)
}
