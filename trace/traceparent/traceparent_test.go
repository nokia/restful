package traceparent

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParent(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	parent := "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01"
	r.Header.Set("traceparent", parent)
	trace := NewFromRequest(r)
	assert.True(trace.IsReceived())
	assert.Equal(trace.TraceID(), "0af7651916cd43dd8448eb211c80319c")
	assert.Equal(trace.SpanID(), "b9c7c989f97918e1")
	_, span, _ := trace.Span(r)
	assert.NotContains(span, "b9c7c989f97918e1")
	assert.Contains(trace.String(), "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1")

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Equal(parent, headers.Get("traceparent"))
}

func TestEmpty(t *testing.T) {
	assert.Nil(t, NewFromRequest(&http.Request{}))
	assert.Nil(t, NewFromRequest(&http.Request{Header: http.Header{}}))
}

func TestBad(t *testing.T) {
	parent := "hello-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01"
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", parent)
	trace := NewFromRequest(r)
	assert.Nil(t, trace)
}

func TestParentInvalidIDsIgnored(t *testing.T) {
	assert := assert.New(t)

	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b9c7c989f97918e1-01")
	assert.Nil(NewFromRequest(r))

	r, _ = http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd-b9c7c989f97918e1-01") // 16-char trace ID, W3C needs 32
	assert.Nil(NewFromRequest(r))

	r, _ = http.NewRequest("POST", "", nil)
	r.Header["Traceparent"] = []string{"00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01\nX-Injected: 1"}
	assert.Nil(NewFromRequest(r))
}

func TestParentDropsUnsafeTracestate(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01")
	r.Header["Tracestate"] = []string{"vendor=1\nX-Injected: 1"}
	trace := NewFromRequest(r)
	assert.NotNil(trace)

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Empty(headers.Get("tracestate"))

	r, _ = http.NewRequest("POST", "", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01")
	r.Header.Set("tracestate", strings.Repeat("a", 513))
	trace = NewFromRequest(r)
	assert.NotNil(trace)
	headers = http.Header{}
	trace.SetHeader(headers)
	assert.Empty(headers.Get("tracestate"))
}
