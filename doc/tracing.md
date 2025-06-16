# Tracing

## Introduction

Tracing is a very good tool to see how request processing happens in the system.
There are various tools to visualize components and delays, such as [Jaeger](https://www.jaegertracing.io/) or [Zipkin](https://zipkin.io/).

## How it works

When you use RESTful, you do not need to write a single line of code for tracing to work.

* When a request is received, Server/Lambda handler puts tracing header information into the context parameter.
  Generates a new trace ID if none is received.
* When sending a request, Client functions read tracing information from the context and make a new span.
* Send/receive logs contain compact tracing information. The exact behavior depends on the Logrus log level.
* If `SetOTel(true, tracerProvider)` or `SetOTelGrpc("host:4317", 0.01)` are called, tracing is based on the industry-standard [OpenTelemetry](https://github.com/open-telemetry/) project.
  The main difference between the default and OTel is that for OTel you may define an exporter which sends traces to a collector.
  While the default one just propagates the headers and relies on a service mesh to report to a collector in a timely manner.

OTel can be activated using environment variables `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
instead of using `SetOTel` functions.
Sampling is then set by `OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG` variables.
E.g. `OTEL_TRACES_SAMPLER=parentbased_traceidratio` and `OTEL_TRACES_SAMPLER_ARG=0.01`,
meaning that 1% of the traffic is sampled, unless the incoming request indicates that sampling is required.
See Otel documentation for details.

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
