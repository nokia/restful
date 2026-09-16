package tracecommon

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"unicode"
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

// IsHexID reports whether s is hexadecimal of one of the allowed lengths.
func IsHexID(s string, allowedLen ...int) bool {
	for _, n := range allowedLen {
		if len(s) != n {
			continue
		}
		_, err := hex.DecodeString(s)
		return err == nil
	}
	return false
}

const maxForwardedIDLen = 128

// SafeHeaderValue returns s if it is safe to copy into an outgoing header, otherwise it returns an empty string.
// Empty, overly long, or values with control characters (including CR/LF) are dropped.
func SafeHeaderValue(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = maxForwardedIDLen
	}
	if len(s) == 0 || len(s) > maxLen {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return ""
		}
	}
	return s
}
