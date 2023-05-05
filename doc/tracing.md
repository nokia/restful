# Tracing

## Introduction

Tracing is a very good tool to see how trace how request processing happens in the system.
There are various tools to visualize components and delays. Such as [Jaeger](https://www.jaegertracing.io/) or [Zipkin](https://zipkin.io/).

## How it works

When you use RESTful, you do not need to write a single line of code for tracing to work.

* When a request is received, Server/Lambda handler puts tracing header information to context parameter.
  Generates new trace ID if not received any.
* When sending a request, Client functions read tracing information from the context and make a new span.
* Send/receive logs contain compact tracing information. The exact behavior depends on Logrus log level.

An example, tracing data propagated in variable `ctx`.

```go
func handle(ctx context.Context, data struct{}) error {
    _, err := restful.NewClient().Post(ctx, "https://example.com", &data, nil)
    return err
}
```

## Headers

RESTful's tracing supports 2 kinds of headers:

* `B3` and `X-B3-*` headers: See [Open Zipkin documentation](https://github.com/openzipkin/b3-propagation).
* `traceparent`: See [W3C recommendation](https://www.w3.org/TR/trace-context/).
