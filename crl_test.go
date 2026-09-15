package restful

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchCRLHTTP_BodyTooLarge(t *testing.T) {
	prev := MaxCRLHTTPBodyBytes
	MaxCRLHTTPBodyBytes = 32
	defer func() { MaxCRLHTTPBodyBytes = prev }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("A"), 2*MaxCRLHTTPBodyBytes))
	}))
	defer srv.Close()

	body, err := fetchCRLHTTP(context.Background(), srv.URL)
	assert.Nil(t, body)
	assert.ErrorIs(t, err, ErrCRLHTTPBodyTooBig)
}

func TestFetchCRLHTTP_ContentLengthTooLarge(t *testing.T) {
	prev := MaxCRLHTTPBodyBytes
	MaxCRLHTTPBodyBytes = 8
	defer func() { MaxCRLHTTPBodyBytes = prev }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, bytes.NewReader(bytes.Repeat([]byte("B"), 2*MaxCRLHTTPBodyBytes)))
	}))
	defer srv.Close()

	body, err := fetchCRLHTTP(context.Background(), srv.URL)
	assert.Nil(t, body)
	assert.ErrorIs(t, err, ErrCRLHTTPBodyTooBig)
}
