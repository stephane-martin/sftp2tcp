package main

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

type metricsKeyType struct{}

var metricsKey metricsKeyType

type metrics struct {
	nbClientConnections  *prometheus.CounterVec
	nbConnectionsRefused *prometheus.CounterVec
	nbWriteErrors        *prometheus.CounterVec
	nbBytesWritten       *prometheus.CounterVec
	nbFilesUploaded      *prometheus.CounterVec
	nbFailedHealthChecks *prometheus.CounterVec
	uploadRateSummary    prometheus.Summary
	registry             *prometheus.Registry
}

func newMetrics() *metrics {
	m := new(metrics)
	m.nbClientConnections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "client_connections_total",
			Help: "Number of client connections.",
		},
		[]string{"client"},
	)
	m.nbConnectionsRefused = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "connections_refused_total",
			Help: "Number of TCP connections refused",
		},
		[]string{"address"},
	)
	m.nbWriteErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "write_errors_total",
			Help: "Number of TCP write errors",
		},
		[]string{"address"},
	)
	m.nbBytesWritten = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bytes_written_total",
			Help: "Total number of bytes sent to TCP services",
		},
		[]string{"address"},
	)
	m.nbFilesUploaded = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "uploaded_files_total",
			Help: "Number of files successfully transfered to TCP services",
		},
		[]string{"address"},
	)
	m.nbFailedHealthChecks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "failed_health_checks_total",
			Help: "Total number of failed health checks",
		},
		[]string{"host"},
	)
	m.uploadRateSummary = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name:       "upload_rate_summary",
			Help:       "Summary of upload rate to the TCP services",
			MaxAge:     prometheus.DefMaxAge,
			AgeBuckets: prometheus.DefAgeBuckets,
			BufCap:     prometheus.DefBufCap,
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
	)

	m.registry = prometheus.NewRegistry()
	m.registry.MustRegister(
		m.nbClientConnections,
		m.nbConnectionsRefused,
		m.nbWriteErrors,
		m.nbBytesWritten,
		m.nbFilesUploaded,
		m.nbFailedHealthChecks,
		m.uploadRateSummary,
	)
	return m
}

func getMetrics(ctx context.Context) *metrics {
	return ctx.Value(metricsKey).(*metrics)
}
