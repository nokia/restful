package traceb3

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestB3SingleLine(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	traceB3Str := "0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-1-deadbeef87654321"
	r.Header.Set("b3", traceB3Str)
	trace := NewFromRequest(r)
	assert.True(trace.IsReceived())
	assert.Equal(trace.TraceID(), "0af7651916cd43dd8448eb211c80319c")
	assert.Equal(trace.SpanID(), "b9c7c989f97918e1")
	_, span, _ := trace.Span(r)
	assert.NotContains(span, "b9c7c989f97918e1")
	assert.Contains(trace.String(), "0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1")

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Equal(traceB3Str, headers.Get("b3"))
}

func TestB3MultiLine(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	traceID := "0af7651916cd43dd8448eb211c80319c"
	spanID := "b9c7c989f97918e1"
	r.Header.Set("x-b3-traceid", traceID)
	r.Header.Set("x-b3-spanid", spanID)
	trace := NewFromRequest(r)
	assert.True(trace.IsReceived())
	assert.Equal(trace.TraceID(), "0af7651916cd43dd8448eb211c80319c")
	assert.Equal(trace.SpanID(), "b9c7c989f97918e1")
	_, span, _ := trace.Span(r)
	assert.NotContains(span, "b9c7c989f97918e1")

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Equal(traceID, headers.Get("x-b3-traceid"))
}

func TestRandom(t *testing.T) {
	assert := assert.New(t)
	trace := NewRandom()
	assert.False(trace.IsReceived())
	assert.Len(trace.TraceID(), 32)
	assert.Len(trace.SpanID(), 16)
}

func TestEmpty(t *testing.T) {
	assert.Nil(t, NewFromRequest(&http.Request{}))
	assert.Nil(t, NewFromRequest(&http.Request{Header: http.Header{}}))
}

func TestB3InvalidIDsIgnored(t *testing.T) {
	assert := assert.New(t)

	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("b3", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b9c7c989f97918e1")
	assert.Nil(NewFromRequest(r))

	r, _ = http.NewRequest("POST", "", nil)
	r.Header.Set("x-b3-traceid", "not-a-hex-trace-id")
	r.Header.Set("x-b3-spanid", "b9c7c989f97918e1")
	assert.Nil(NewFromRequest(r))

	r, _ = http.NewRequest("POST", "", nil)
	r.Header.Set("b3", "0af7651916cd43d-b9c7c989f97918e1") // 15-char trace ID
	assert.Nil(NewFromRequest(r))

	r, _ = http.NewRequest("POST", "", nil)
	r.Header["B3"] = []string{"0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1\nX-Injected: 1"}
	assert.Nil(NewFromRequest(r))
}

func TestB3DropsUnsafeForwardedHeaders(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("x-b3-traceid", "0af7651916cd43dd8448eb211c80319c")
	r.Header.Set("x-b3-spanid", "b9c7c989f97918e1")
	r.Header["X-Request-Id"] = []string{"ok\nid"}
	r.Header.Set("x-ot-span-context", strings.Repeat("a", 200))
	trace := NewFromRequest(r)
	assert.NotNil(trace)

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Empty(headers.Get("x-request-id"))
	assert.Empty(headers.Get("x-ot-span-context"))
}

func TestB3ForwardsSafeRequestID(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("POST", "", nil)
	r.Header.Set("x-b3-traceid", "0af7651916cd43dd8448eb211c80319c")
	r.Header.Set("x-b3-spanid", "b9c7c989f97918e1")
	r.Header.Set("x-request-id", "abc-123")
	trace := NewFromRequest(r)
	assert.NotNil(trace)

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Equal("abc-123", headers.Get("x-request-id"))
}
