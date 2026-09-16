package tracecommon

import (
	"net/http"
	"strings"
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

func TestIsHexID(t *testing.T) {
	assert := assert.New(t)
	assert.True(IsHexID("0af7651916cd43dd", 16, 32))
	assert.True(IsHexID("0AF7651916CD43DD8448EB211C80319C", 32))
	assert.False(IsHexID("0af7651916cd43dd", 32))
	assert.False(IsHexID("not-hex-atallxxxx", 16))
	assert.False(IsHexID("", 16))
	assert.False(IsHexID("0af7651916cd43d", 16))
}

func TestSafeHeaderValue(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("abc-123", SafeHeaderValue("abc-123", 128))
	assert.Equal("", SafeHeaderValue("", 128))
	assert.Equal("", SafeHeaderValue("ok\nid", 128))
	assert.Equal("", SafeHeaderValue("ok\rid", 128))
	assert.Equal("", SafeHeaderValue(strings.Repeat("a", 129), 128))
	assert.Equal("", SafeHeaderValue(strings.Repeat("a", 129), 0))
	assert.Equal(strings.Repeat("a", 128), SafeHeaderValue(strings.Repeat("a", 128), 0))
}
