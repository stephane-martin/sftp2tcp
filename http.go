package main

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	health "github.com/InVisionApp/go-health"
	"github.com/InVisionApp/go-health/handlers"
	"github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/html/charset"
)

func startHTTP(ctx context.Context, listenaddr string, httpport int, dest *tcpDestination, m *metrics, h *health.Health, stopChan chan os.Signal, logger log15.Logger) {
	if httpport <= 0 {
		return
	}
	var once sync.Once

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

	muxer.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		once.Do(func() {
			stopChan <- syscall.SIGTERM
		})
	})

	muxer.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" && r.Method != "PUT" {
			w.WriteHeader(400)
			return
		}
		typ, params, err := mime.ParseMediaType(r.Header.Get("Content-type"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		first := typ
		if strings.HasPrefix(typ, "/") {
			first = strings.Split(typ, "/")[0]
		}
		switch first {
		case "text":
			inCharset := params["charset"]
			if inCharset == "" {
				inCharset = "utf-8"
			}
			encoding, _ := charset.Lookup(inCharset)
			if encoding == nil {
				logger.Warn("Unknown encoding", "name", inCharset)
				w.WriteHeader(500)
				return
			}
			err = uploadHTTP2TCP(encoding.NewDecoder().Reader(r.Body), dest, m, logger)
		case "multipart":
			reader, _ := r.MultipartReader()
			for {
				part, err2 := reader.NextPart()
				if err2 != nil {
					break
				}
				filename := part.FileName()
				if len(filename) > 0 {
					err = uploadHTTP2TCP(part, dest, m, logger)
					break
				}
			}
		default:
			err = uploadHTTP2TCP(r.Body, dest, m, logger)
		}
		if err != nil {
			c := cause(err)
			logger.Error("Error happened writing to TCP destination",
				"error", err,
				"type", fmt.Sprintf("%T", err),
				"cause", c,
				"causetype", fmt.Sprintf("%T", c),
			)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	})

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

func uploadHTTP2TCP(reader io.Reader, dest *tcpDestination, m *metrics, logger log15.Logger) error {
	conn, err := dest.getConn()
	if err != nil {
		return err
	}
	defer dest.releaseConn(conn)
	start := time.Now()
	written, err := io.Copy(conn, reader)
	m.nbBytesWritten.WithLabelValues(conn.RemoteAddr().String()).Add(float64(written))
	if err != nil {
		return err
	}
	m.uploadRateSummary.Observe(float64(written) / time.Now().Sub(start).Seconds())
	return nil
}
