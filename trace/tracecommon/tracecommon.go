package tracecommon

import (
	"fmt"
	"math/rand"
	"net/http"
)

func randStr16() string {
	return fmt.Sprintf("%016x", rand.Uint64()) // #nosec random is weak intentionally
}

func randStr32() string {
	return randStr16() + randStr16()
}

// NewSpanID generates a semi-random span ID.
func NewSpanID() string {
	return randStr16()
}

// NewTraceID generates a semi-random trace ID.
func NewTraceID() string {
	return randStr32()
}

// SetHeaderStr sets header for given header set, if given value is not empty.
// Input headers object must not be nil.
func SetHeaderStr(headers http.Header, header, value string) {
	if headers == nil {
		return
	}
	if value != "" {
		headers.Set(header, value)
	}
}
