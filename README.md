# RESTful

## Quick introduction

This Go package is a powerful extension of standard Go HTTP server and client libraries.
It lets you handle HTTP+JSON without any extra code.

### Lambda server

You receive and respond with data structures.

```go
type reqData struct{...}
type respData struct{...}

func create(ctx context.Context, req *reqData) (*respData, error) {...}

func main() {
    restful.HandleFunc("/user/v1", create).Methods(http.MethodPost)
    restful.Start()
}
```

### RESTful client

You send and receive data structures.

```go
location, err := restful.Post(ctx, "https://example.com", &reqData, &respData)
```

## Details

* [Lambda server](doc/lambda.md) Focus on business logic. It is a modern variant of an HTTP server.
* [RESTful server](doc/server.md) An underlying HTTP server of Lambda. An HTTP server with goodies.
  Besides helper functions for receiving and sending JSON data, it can do logging, and provides `Monitor` hooks for whatever you need, such as adding Prometheus counters without littering your code.
* [RESTful client](doc/client.md) Such as sending GET, POST (and receiving Location), PUT, PATCH or DELETE requests and receiving their responses.
  And numerous other helper functions.
* Context is received in Lambda and used in client request.
  That is highly important, as some tracing headers should propagate from service to service (with some changes).
  That is all done without any extra coding on your side.
* Error is used by Lambda, Server and Client classes. It contains HTTP status code besides traditional error.

Context and error are the glue between Lambda and Client.

## Principles

* Simple, intuitive, Go-ish.
* Similar to Go's built-in http packange and the famous [Gorilla/Mux](https://github.com/gorilla/mux).
* Powerful HTTP+JSON framework reducing development costs while improving quality.
* Have quite many goodies needed on developing complex applications.
