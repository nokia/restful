# Trace

There are several tracing components here:

* `tracer` contains common tracing functions to be used by the client and server components
* `tracedata` contains a common interface definition for the various tracer solutions
* `traceb3` and `traceparent` are two propagation-only packages, with some common functions at `tracecommon`
* `traceotel` containing OpenTelemetry-based solution
