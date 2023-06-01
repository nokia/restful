package tracer

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotReceived(t *testing.T) {
	tracer := NewFromRequestOrRandom(&http.Request{})
	assert.False(t, tracer.IsReceived())
}
