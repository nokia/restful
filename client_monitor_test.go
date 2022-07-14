package restful

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientMonitorAddHeader(t *testing.T) {
	assert := assert.New(t)

	var preCount, postCount int
	pre := func(req *http.Request) (*http.Response, error) {
		req.Header.Add("X-My-Req-Header", strconv.FormatInt(int64(preCount), 10))
		preCount++
		return nil, nil
	}
	post := func(req *http.Request, resp *http.Response, err error) *http.Response {
		resp.Header.Add("X-My-Resp-Header", strconv.FormatInt(int64(postCount), 10))
		postCount++
		if postCount > 0 {
			return resp // Practically the same as return nil.
		}
		return nil
	}

	// Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal([]string{"0", "1"}, r.Header.Values("X-My-Req-Header"))
	}))
	defer srv.Close()

	client := NewClient().Monitor(pre, post).Monitor(pre, nil).Monitor(nil, post)
	resp, err := client.SendRecv2xx(context.Background(), http.MethodGet, srv.URL, nil, nil, nil)
	assert.NoError(err)
	assert.Equal([]string{"0", "1"}, resp.Header.Values("X-My-Resp-Header"))

	assert.Equal(2, preCount)
	assert.Equal(2, postCount)
}

func TestClientMonitorPreBlocks(t *testing.T) {
	assert := assert.New(t)

	preCount := 0
	pre := func(req *http.Request) (*http.Response, error) {
		preCount++
		return nil, errors.New("blocking")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient().Monitor(pre, nil).Monitor(pre, nil)
	err := client.Get(context.Background(), srv.URL, nil)
	assert.Error(err)
	assert.Equal(1, preCount)
}
