package tracecommon

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandom(t *testing.T) {
	assert.Equal(t, 16, len(NewSpanID()))
	assert.Equal(t, 32, len(NewTraceID()))
}

func TestSetHeader(t *testing.T) {
	headers := make(http.Header)
	SetHeaderStr(headers, "x", "y")
	assert.Equal(t, "y", headers.Get("x"))
}

func TestSetHeaderNoValue(t *testing.T) {
	var headers http.Header
	SetHeaderStr(headers, "x", "")
	_, ok := headers["X"]
	assert.False(t, ok)
	assert.Equal(t, "", headers.Get("x"))
}
