package traceb3

import (
	"net/http"
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
	assert.NotContains(trace.Span(r), "b9c7c989f97918e1")
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
	assert.NotContains(trace.Span(r), "b9c7c989f97918e1")

	headers := http.Header{}
	trace.SetHeader(headers)
	assert.Equal(traceID, headers.Get("x-b3-traceid"))
}

func TestRandom(t *testing.T) {
	assert := assert.New(t)
	trace := NewRandom()
	assert.False(trace.IsReceived())
	assert.Len(trace.TraceID(), 32)
}

func TestEmpty(t *testing.T) {
	assert.Nil(t, NewFromRequest(&http.Request{}))
	assert.Nil(t, NewFromRequest(&http.Request{Header: http.Header{}}))
}
