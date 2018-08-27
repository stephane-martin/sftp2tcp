package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	health "github.com/InVisionApp/go-health"
	"github.com/InVisionApp/go-health/checkers"
	"github.com/inconshreveable/log15"
	"golang.org/x/sync/errgroup"
)

func newHealth(host string, port int, logger log15.Logger) *health.Health {
	h := health.New()
	h.Logger = adaptInLogger(logger)
	checker, _ := checkers.NewReachableChecker(&checkers.ReachableConfig{
		URL: &url.URL{
			Host: net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		},
	})
	h.AddCheck(&health.Config{
		Name:     "tcp_destination_is_alive",
		Interval: 5 * time.Second,
		Checker:  checker,
	})
	return h
}

func startHealthChecker(ctx context.Context, g *errgroup.Group, h *health.Health) error {
	err := h.Start()
	if err != nil {
		return err
	}
	g.Go(func() error {
		<-ctx.Done()
		h.Stop()
		return context.Canceled
	})
	return nil
}

// HealthCheckFailed is triggered when a health check fails the first time
func (sl *HealthCheckStatusListener) HealthCheckFailed(entry *health.State) {
	sl.m.nbFailedHealthChecks.WithLabelValues(sl.desthost).Inc()
	sl.logger.Info("failed health check", "name", entry.Name, "nb_failures", entry.ContiguousFailures, "error", entry.Err)
	if sl.cancel != nil {
		sl.cancel()
	}
}

// HealthCheckRecovered is triggered when a health check recovers
func (sl *HealthCheckStatusListener) HealthCheckRecovered(entry *health.State, recordedFailures int64, failureDurationSeconds float64) {
	if entry == nil {
		sl.logger.Info("Intialize SSH listener")
	} else {
		sl.logger.Info(
			"Recovering from errors",
			"nb_failures", recordedFailures,
			"failure_duration", time.Duration(int64(float64(time.Second)*failureDurationSeconds)),
		)
	}
	var ctx context.Context
	ctx, sl.cancel = context.WithCancel(sl.parentCtx)
	sl.restart(ctx)
}
