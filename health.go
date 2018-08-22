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
