# Tracing

Tracing is a very good tool to see how trace how request processing happens in the system.
There are various tools to visualize components and delays. Such as [Jaeger](https://www.jaegertracing.io/) or [Zipkin](https://zipkin.io/).

When you use RESTful, you do not need to write a single line of code for tracing to work.

* When a request is received, Lambda handler puts tracing header information to context parameter.
* When sending a request, Client functions read tracing information from the context and make a new span.
* Send/receive logs contain compact tracing information. The exact behavior depends on Logrus log level.
  If log level = trace, then a new trace information is initiated, if nothing is received.

An example, tracing data propagated in variable `ctx`.

```go
func handle(ctx context.Context, data struct{}) error {
    _, err := restful.NewClient().Post(ctx, "https://example.com", &data, nil)
    return err
}
```

See [W3C](https://www.w3.org/TR/trace-context/). [OpenTelemetry](https://opentelemetry.io/) behaves somewhat similarly.
