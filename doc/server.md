# RESTful Server

## Introduction

The Server class is designed to receive HTTP requests and send responses.
Tries to mimic the default http module, with the difference of strong JSON support.

For more advanced request serving, check out [Lambda Server](lambda.md).

## Using built-in http package

```go
func userHandler(w http.ResponseWriter, r *http.Request) {
    type user struct{ Name, Address string }
    switch r.Method {
    case http.MethodGet:
        joe := user{Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
        restful.SendJSONResponse(w, 200, &joe, true)
    case http.MethodPost:
        var who user
        restful.GetRequestData(r, 0, &who)
        _ = restful.SendLocationResponse(w, "http://me:8080/user/joe")
    case http.MethodDelete:
        restful.SendEmptyResponse(w, http.StatusNoContent)
    default:
        restful.SendProblemResponse(w, r, http.StatusMethodNotAllowed, "Leave me alone!")
    }
}

func main() {
    http.HandleFunc("/user", userHandler)
    restful.ListenAndServe(":8080", http.DefaultServeMux) // Like http.ListenAndServe(), but logs and handles K8s liveness probe, too.
    panic("Server crashed when printing this line")
}
```

## Using Gorilla/Mux

```go
import "github.com/gorilla/mux"

func getUserHandler(w http.ResponseWriter, r *http.Request) {...}

func main() {
    handler := mux.NewRouter()
    handler.HandleFunc("/user", getUserHandler).Methods(http.MethodGet)
    restful.ListenAndServe(":8080", handler) // Works with Gorilla/Mux, too.
}
```

## Server-Client Trace Example

This tiny example shows how incoming request data are saved to the context.
Headers may contain Zipkin/Jaeger X-B3-* and OpenTracing `traceparent` and `tracestate`.
If the incoming request contained those, then the client generates new span IDs for each request.

```go
func userHandler(w http.ResponseWriter, r *http.Request) {
    ctx := restful.NewRequestCtx(w, r)
    var whatever struct{}
    _ = restful.Get(ctx, "https://example0.com/", &whatever)
    _, _ = restful.Put(ctx, "https://example1.com/", &whatever, nil)
}
```

You see nothing, just `ctx`. The rest is automated. Check network traffic. If debug logs are on, then you see the incoming parent as well as the 2 distinct span IDs in the logs, too. If tracing headers are not received, debug logs still contain random IDs, so that you can match requests and responses.

## HTTPS

```go
// TLS non-OOP way
restful.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
restful.ListenAndServeTLS(":8443", "/etc/own-tls/tls.crt", "/etc/own-tls/tls.crt", nil)

// TLS OOP way
handler := restful.NewRouter()
handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
srv := restful.NewServer().Addr(":8443").Handler(handler).TLSServerCert("/etc/own-tls/tls.crt", "/etc/own-tls/tls.crt")
srv.ListenAndServe()
```

Mutual TLS is very similar, just client CAs are provided.
Client CA can be a PEM file or a directory containing PEM files case-insensitively matching `*.crt` or `*.pem`.

```go
// MTLS non-OOP way
restful.ListenAndServeMTLS(":8443", "/etc/own-tls/tls.crt", "/etc/own-tls/tls.crt", "/etc/clientcas", false, nil)

// MTLS OOP way
srv := restful.NewServer().Addr(":8443").Handler(handler).TLSServerCert("/etc/own-tls/tls.crt", "/etc/own-tls/tls.crt").TLSClientCert("/etc/clientcas", false)
srv.ListenAndServe()
```

❗ Note that once the key and certs are loaded, they are in the memory.
Any update (e.g., cert-manager.io) will not affect that.
You may restart your app, or in the cloud, you may issue `kubectl rollout restart deploy/xxx`.
