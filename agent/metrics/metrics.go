package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yarra/ebpf-netmon/agent/collector"
)

type Metrics struct {
	bytesSent      *prometheus.CounterVec
	bytesRecv      *prometheus.CounterVec
	retransmits    *prometheus.CounterVec
	connectLatency *prometheus.GaugeVec
	registry       *prometheus.Registry
}

func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	factory := promauto.With(registry)

	return &Metrics{
		registry: registry,
		bytesSent: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "netmon_bytes_sent_total",
			Help: "Total bytes sent over TCP, by process, since the last scrape interval.",
		}, []string{"process"}),
		bytesRecv: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "netmon_bytes_received_total",
			Help: "Total bytes received over TCP, by process, since the last scrape interval.",
		}, []string{"process"}),
		retransmits: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "netmon_retransmits_total",
			Help: "Total TCP retransmissions, by process, since the last scrape interval.",
		}, []string{"process"}),
		connectLatency: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netmon_connect_latency_seconds",
			Help: "Max observed TCP connect latency, by process, in the last scrape interval.",
		}, []string{"process"}),
	}
}

// Update adds each aggregate's counters to the running totals for its
// process label. Counters, not gauges, because the collector hands us
// per-interval deltas (it resets the underlying BPF map after each read).
func (m *Metrics) Update(aggs []collector.Aggregate) {
	for _, a := range aggs {
		m.bytesSent.WithLabelValues(a.Process).Add(float64(a.BytesSent))
		m.bytesRecv.WithLabelValues(a.Process).Add(float64(a.BytesRecv))
		m.retransmits.WithLabelValues(a.Process).Add(float64(a.Retransmits))
		m.connectLatency.WithLabelValues(a.Process).Set(float64(a.ConnectLatencyNs) / 1e9)
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
