# RESTful

## Quick introduction

This Go package is a powerful extension of standard Go HTTP server and client libraries.
It lets you handle HTTP+JSON without any extra code.

[Reference.](https://pkg.go.dev/github.com/nokia/restful)

### Lambda server

You receive and respond with data structures.

```go
type reqData struct{...}
type respData struct{...}

func create(ctx context.Context, req *reqData) (*respData, error) {
    ... // You use data structures directly, without marshalling and unmarshalling.
}

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
  Besides helper functions for receiving and sending JSON data and it can do logging.
  Router is based on [Gorilla/Mux](https://github.com/gorilla/mux), offering similar services.
* [RESTful client](doc/client.md) Sending GET, POST (and receiving Location), PUT, PATCH or DELETE requests and receiving their responses.
  And numerous other helper functions.
* [Tracing](doc/tracing.md) information is propagated in context, received in Lambda and used in client request.
  That is all done without any extra coding on your side.
  Based on [OpenTelemetry](https://opentelemetry.io/).
* [Monitor](doc/monitor.md) is a middleware that can pre-process requests and post-process responses.
  Pre and post hooks can be used for whatever you want, such as adding Prometheus counters on router level, without littering your business logic.
* [Error](doc/error.md) is a Go error object containing HTTP status code besides traditional error.

Trace context and error are the glue between Lambda and Client.
That is why they form a module together.

## Principles

* Simple, intuitive, Go-ish.
* Similar to Go's built-in http package, with some advanced router inherited from [Gorilla/Mux](https://github.com/gorilla/mux) project.
* Powerful HTTP+JSON framework reducing development costs while improving quality.
* Have quite many goodies needed on developing complex applications.
