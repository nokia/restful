package lambda

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRequestBodyQueryParameters_FormURLEncoded(t *testing.T) {
	body := "foo=bar&num=123&multi=a&multi=b"

	req, err := http.NewRequest(http.MethodPost, "http://example.com/test", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header = make(http.Header)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	l := newLambda(newTestFakeWriter(), req, nil)
	values := l.RequestBodyQueryParameters()
	if values == nil {
		t.Fatalf("expected non-nil values")
	}

	if got := values.Get("foo"); got != "bar" {
		t.Fatalf("foo: got %q, want %q", got, "bar")
	}
	if got := values.Get("num"); got != "123" {
		t.Fatalf("num: got %q, want %q", got, "123")
	}

	multi := values["multi"]
	if len(multi) != 2 || multi[0] != "a" || multi[1] != "b" {
		t.Fatalf("multi: got %#v, want []string{\"a\",\"b\"}", multi)
	}
}
