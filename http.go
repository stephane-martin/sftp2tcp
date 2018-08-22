package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	health "github.com/InVisionApp/go-health"
	"github.com/InVisionApp/go-health/handlers"
	"github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func startHTTP(ctx context.Context, listenaddr string, httpport int, m *metrics, h *health.Health, logger log15.Logger) {
	if httpport <= 0 {
		return
	}
	muxer := http.NewServeMux()
	muxer.Handle(
		"/metrics",
		promhttp.HandlerFor(
			m.registry,
			promhttp.HandlerOpts{
				DisableCompression:  true,
				ErrorLog:            adaptPromLogger(logger),
				ErrorHandling:       promhttp.HTTPErrorOnError,
				MaxRequestsInFlight: -1,
				Timeout:             -1,
			},
		),
	)
	muxer.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	muxer.Handle(
		"/healthcheck",
		handlers.NewJSONHandlerFunc(h, nil),
	)
	httpserver := &http.Server{
		Addr:    net.JoinHostPort(listenaddr, fmt.Sprintf("%d", httpport)),
		Handler: muxer,
	}
	go func() {
		httpserver.ListenAndServe()
		go func() {
			<-ctx.Done()
			httpserver.Close()
		}()
	}()

}
