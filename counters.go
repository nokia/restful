package restful

import "github.com/prometheus/client_golang/prometheus"

var (
	httpRequestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "restful_http_request_latency_ms",
			Help:    "Latency of HTTP requests in milliseconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	totalRequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "restful_http_request_total_count",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "endpoint"},
	)

	totalRequestLatencyMs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "restful_http_request_total_latency_ms",
			Help: "Total latency of HTTP requests in milliseconds.",
		},
		[]string{"method", "endpoint"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestLatency)
	prometheus.MustRegister(totalRequestCount)
	prometheus.MustRegister(totalRequestLatencyMs)
}

// RecordRequestLatency records the latency of an HTTP request.
func RecordRequestLatency(method, endpoint string, duration float64) {
	httpRequestLatency.WithLabelValues(method, endpoint).Observe(duration)
}
