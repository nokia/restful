package restful

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpRequestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "restful_http_request_latency_ms",
			Help:    "Latency of HTTP requests in milliseconds.",
			Buckets: []float64{1, 2, 5, 10, 100, 250, 500, 1000, 2000},
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

// RecordTotalRequestMetrics records the total request count and latency metrics for an HTTP request.
func (c *Client) RecordTotalRequestMetrics(req *http.Request, start time.Time) {
	if !c.CountersEnabled {
		return
	}
	duration := time.Since(start).Milliseconds()
	endpoint := req.Host
	if endpoint == "" {
		endpoint = req.URL.Hostname() + ":" + req.URL.Port()
	}
	RecordRequestLatency(req.Method, endpoint, float64(duration))
	totalRequestCount.WithLabelValues(req.Method, endpoint).Inc()
	totalRequestLatencyMs.WithLabelValues(req.Method, endpoint).Add(float64(duration))

	return
}
