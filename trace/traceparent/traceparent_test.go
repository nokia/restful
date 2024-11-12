package traceparent

import (
	"net/http"
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
	_, span := trace.Span(r)
	assert.NotContains(span.String(), "b9c7c989f97918e1")
	assert.Contains(trace.String(), "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1")

	headers := http.Header{}
	trace.setHeader(headers)
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
