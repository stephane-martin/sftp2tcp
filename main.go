// An example SFTP server implementation using the golang SSH package.
// Serves the whole filesystem visible to the user, and has a hard-coded username and password,
// so not for real use!
package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	health "github.com/InVisionApp/go-health"
	"github.com/InVisionApp/go-health/checkers"
	"github.com/InVisionApp/go-health/handlers"
	inlogger "github.com/InVisionApp/go-logger"
	"github.com/inconshreveable/log15"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/sftp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	cli "gopkg.in/urfave/cli.v1"
)

var Version string
var GitCommit string

func getLogger(level string, toSyslog bool) log15.Logger {
	lvl, _ := log15.LvlFromString(level)
	logger := log15.New()
	if toSyslog {
		logger.SetHandler(
			log15.LvlFilterHandler(
				lvl,
				log15.Must.SyslogHandler(
					syslog.LOG_INFO|syslog.LOG_DAEMON,
					"sftp2tcp",
					log15.JsonFormat(),
				),
			),
		)
	} else {
		logger.SetHandler(
			log15.LvlFilterHandler(
				lvl,
				log15.StreamHandler(
					os.Stderr,
					log15.LogfmtFormat(),
				),
			),
		)
	}
	return logger
}

func makeApp() *cli.App {
	app := cli.NewApp()
	app.Name = "sftp2tcp"
	app.Authors = []cli.Author{
		cli.Author{
			Email: "stephane.martin_github@vesperal.eu",
			Name:  "Stephane Martin",
		},
	}
	app.Copyright = "Apache 2 licence"
	app.Usage = "Proxy files received by SFTP to a TCP service"
	app.Version = Version

	app.Flags = []cli.Flag{
		// TODO: support multiple hosts for round-robin
		// TODO: make an explicit DNS query
		cli.StringFlag{
			Name:   "desthost, d",
			Value:  "127.0.0.1",
			Usage:  "the destination host",
			EnvVar: "SFTP2TCP_HOST",
		},
		cli.IntFlag{
			Name:   "destport, p",
			Value:  4444,
			Usage:  "the destination port",
			EnvVar: "SFTP2TCP_PORT",
		},
		cli.StringFlag{
			Name:   "listenaddr, l",
			Value:  "0.0.0.0",
			Usage:  "the listen address for the SFTP service",
			EnvVar: "SFTP2TCP_LISTENADDR",
		},
		cli.UintFlag{
			Name:   "listenport, q",
			Value:  3333,
			Usage:  "the listen port for the SFTP service",
			EnvVar: "SFTP2TCP_LISTENPORT",
		},
		cli.StringFlag{
			Name:   "username, u",
			Value:  "testuser",
			Usage:  "the username that the SFTP client is expected to use",
			EnvVar: "SFTP2TCP_USERNAME",
		},
		cli.StringFlag{
			Name:   "password, w",
			Value:  "testpassword",
			Usage:  "the password that the SFTP client is expected to use",
			EnvVar: "SFTP2TCP_PASSWORD",
		},
		cli.StringFlag{
			Name:   "privatekey",
			Value:  "~/.ssh/id_rsa",
			Usage:  "the file path for the private RSA key used to setup the SFTP service",
			EnvVar: "SFTP2TCP_PRIVATEKEY",
		},
		cli.BoolFlag{
			Name:   "syslog",
			Usage:  "write logs to syslog instead of stderr",
			EnvVar: "SFTP2TCP_SYSLOG",
		},
		cli.StringFlag{
			Name:   "loglevel",
			Value:  "info",
			Usage:  "logging level",
			EnvVar: "SFTP2TCP_LOGLEVEL",
		},
		cli.UintFlag{
			Name:   "maxinputconns",
			Value:  12,
			Usage:  "Maximum number of concurrent input connections",
			EnvVar: "SFTP2TCP_MAXINPUTCONNS",
		},
		cli.UintFlag{
			Name:   "maxuploads",
			Value:  1,
			Usage:  "Maximum number of concurrent file uploads",
			EnvVar: "SFTP2TCP_MAXUPLOADS",
		},
		cli.Uint64Flag{
			Name:   "maxuploadrate",
			Value:  0,
			Usage:  "Maximum upload rate per upload, in megabits/sec (0 for unlimited)",
			EnvVar: "SFTP2TCP_MAXRATE",
		},
		cli.IntFlag{
			Name:   "httpport",
			Value:  8080,
			Usage:  "If positive, sftp2tcp sets up a HTTP service for status information",
			EnvVar: "SFTP2TCP_HTTPPORT",
		},
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:   "proxy",
			Usage:  "start listening on SFTP and proxy received files",
			Action: cli.ActionFunc(proxy),
		},
		cli.Command{
			Name:   "testtcp",
			Usage:  "test connection to the destination TCP server",
			Action: cli.ActionFunc(testTCPConnection),
		},
	}
	return app
}

func exitError(msg string, err error) *cli.ExitError {
	if len(msg) == 0 && err == nil {
		return nil
	}
	if len(msg) == 0 {
		return cli.NewExitError(err.Error(), 1)
	}
	if err == nil {
		return cli.NewExitError(msg, 1)
	}
	return cli.NewExitError(fmt.Sprintf("%s => %s", msg, err.Error()), 1)
}

func testTCPConnection(c *cli.Context) error {
	host := strings.TrimSpace(c.GlobalString("desthost"))
	port := c.GlobalUint("destport")
	if len(host) == 0 {
		return exitError("Empty destination host", nil)
	}
	if port == 0 {
		return exitError("Destination port is zero", nil)
	}
	hostport := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", hostport)
	if err != nil {
		return exitError(fmt.Sprintf("Failed to connect to '%s'", hostport), err)
	}
	conn.Close()
	fmt.Fprintln(os.Stderr, "Connection OK")
	return nil
}

type metricsKeyType struct{}

var metricsKey metricsKeyType

type metrics struct {
	nbClientConnections *prometheus.CounterVec
	registry            *prometheus.Registry
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
	m.registry = prometheus.NewRegistry()
	m.registry.MustRegister(m.nbClientConnections)
	return m
}

func getMetrics(ctx context.Context) *metrics {
	return ctx.Value(metricsKey).(*metrics)
}

type adaptedPromLogger struct {
	logger log15.Logger
}

func (a *adaptedPromLogger) Println(v ...interface{}) {
	a.logger.Error(fmt.Sprintln(v...))
}

func adaptPromLogger(logger log15.Logger) promhttp.Logger {
	return &adaptedPromLogger{
		logger: logger,
	}
}

type adaptedInLogger struct {
	logger log15.Logger
}

func (a *adaptedInLogger) Debug(msg ...interface{}) {
	a.logger.Debug(fmt.Sprint(msg...))
}

func (a *adaptedInLogger) Info(msg ...interface{}) {
	a.logger.Info(fmt.Sprint(msg...))
}

func (a *adaptedInLogger) Warn(msg ...interface{}) {
	a.logger.Warn(fmt.Sprint(msg...))
}

func (a *adaptedInLogger) Error(msg ...interface{}) {
	a.logger.Error(fmt.Sprint(msg...))
}

func (a *adaptedInLogger) Debugln(msg ...interface{}) {
	a.logger.Debug(fmt.Sprintln(msg...))
}

func (a *adaptedInLogger) Infoln(msg ...interface{}) {
	a.logger.Info(fmt.Sprintln(msg...))
}

func (a *adaptedInLogger) Warnln(msg ...interface{}) {
	a.logger.Warn(fmt.Sprintln(msg...))
}

func (a *adaptedInLogger) Errorln(msg ...interface{}) {
	a.logger.Error(fmt.Sprintln(msg...))
}

func (a *adaptedInLogger) Debugf(format string, args ...interface{}) {
	a.logger.Debug(fmt.Sprintf(format, args...))
}

func (a *adaptedInLogger) Infof(format string, args ...interface{}) {
	a.logger.Info(fmt.Sprintf(format, args...))
}

func (a *adaptedInLogger) Warnf(format string, args ...interface{}) {
	a.logger.Warn(fmt.Sprintf(format, args...))
}

func (a *adaptedInLogger) Errorf(format string, args ...interface{}) {
	a.logger.Error(fmt.Sprintf(format, args...))
}

func (a *adaptedInLogger) WithFields(fields inlogger.Fields) inlogger.Logger {
	vars := make([]interface{}, 0, 2*len(fields))
	for k, v := range fields {
		vars = append(vars, k)
		vars = append(vars, v)
	}
	return adaptInLogger(a.logger.New(vars...))
}

func adaptInLogger(logger log15.Logger) inlogger.Logger {
	return &adaptedInLogger{logger}
}

func proxy(c *cli.Context) (err error) {
	host := strings.TrimSpace(c.GlobalString("desthost"))
	port := c.GlobalInt("destport")
	listenaddr := strings.TrimSpace(c.GlobalString("listenaddr"))
	listenport := c.GlobalUint("listenport")
	username := strings.TrimSpace(c.GlobalString("username"))
	password := strings.TrimSpace(c.GlobalString("password"))
	privateKeyPath := strings.TrimSpace(c.GlobalString("privatekey"))
	loglevel := strings.TrimSpace(c.GlobalString("loglevel"))
	toSyslog := c.GlobalBool("syslog")
	maxUploads := c.GlobalUint("maxuploads")
	maxInputConns := c.GlobalUint("maxinputconns")
	rate := c.GlobalUint64("maxuploadrate")
	httpport := c.GlobalInt("httpport")

	if len(host) == 0 {
		return exitError("Empty destination host", nil)
	}
	if port <= 0 {
		return exitError("Destination port is 0 or negative", nil)
	}

	if len(listenaddr) == 0 {
		return exitError("Empty listen address", nil)
	}

	if listenport == 0 {
		return exitError("Listen port is 0", nil)
	}

	listenhostport := fmt.Sprintf("%s:%d", listenaddr, listenport)

	if len(username) == 0 {
		return exitError("Empty username", nil)
	}

	if len(password) == 0 {
		return exitError("Empty password", nil)
	}

	if len(privateKeyPath) == 0 {
		return exitError("Empty private key path", nil)
	}

	if len(loglevel) == 0 {
		loglevel = "info"
	}

	privateKeyPath, err = homedir.Expand(privateKeyPath)
	if err != nil {
		return exitError("Error expanding private key path", err)
	}

	pkey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return exitError("Failed to read the private key", err)
	}

	logger := getLogger(loglevel, toSyslog)

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(ctx ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			logger.Info("Login", "user", ctx.User())
			if ctx.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", ctx.User())
		},
	}

	private, err := ssh.ParsePrivateKey(pkey)
	if err != nil {
		return exitError("failed to parse the private key", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", listenhostport)
	if err != nil {
		return exitError("failed to create listener", err)
	}
	logger.Info("Listening", "address", listener.Addr())

	ctx, cancel := context.WithCancel(context.Background())
	m := newMetrics()
	g, lctx := errgroup.WithContext(
		context.WithValue(ctx, metricsKey, m),
	)

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
	h.Start()

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
	if httpport > 0 {
		go func() {
			httpserver.ListenAndServe()
		}()
	}

	go func() {
		// close the listener when the context is canceled
		// that makes acceptLoop return
		<-lctx.Done()
		httpserver.Close()
		h.Stop()
		listener.Close()
	}()

	sigChan := make(chan os.Signal, 5)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		// cancel the context when a signal is received
		<-sigChan
		cancel()
	}()

	g.Go(func() error {
		return acceptLoop(lctx, g, listener, config, host, port, maxInputConns, maxUploads, rate, logger)
	})
	_ = g.Wait()
	return nil
}

func acceptLoop(ctx context.Context, g *errgroup.Group, listnr net.Listener, cfg *ssh.ServerConfig, dhost string, port int, maxConns uint, maxUps uint, r uint64, l log15.Logger) error {
	conns := make(chan struct{}, maxConns)
	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case conns <- struct{}{}:
		}
		conn, err := listnr.Accept()
		if err != nil {
			l.Debug("Close Accept()", "error", err)
			<-conns
			return err
		}
		go func() {
			<-ctx.Done()
			conn.Close()
		}()
		g.Go(func() error {
			err := handleConnection(ctx, g, conn, cfg, dhost, port, maxUps, r, l)
			if err != nil {
				l.Warn("Handle connection error", "error", err)
			}
			<-conns
			return nil
		})
	}
}

func handleConnection(ctx context.Context, g *errgroup.Group, nConn net.Conn, config *ssh.ServerConfig, dhost string, dport int, maxUps uint, r uint64, logger log15.Logger) error {
	h, _, _ := net.SplitHostPort(nConn.RemoteAddr().String())
	getMetrics(ctx).nbClientConnections.WithLabelValues(h).Inc()
	logger.Debug("Handle connection", "remote", nConn.RemoteAddr())
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Before use, a handshake must be performed on the incoming net.Conn.
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return fmt.Errorf("Handshake failed: %s", err)
	}
	logger.Debug("Handshake done")
	go func() {
		<-lctx.Done()
		sconn.Close()
	}()

	// The incoming Request channel must be serviced.
	g.Go(func() error {
		for {
			select {
			case req, more := <-reqs:
				if !more {
					return nil
				}
				logger.Debug("Incoming request", "type", req.Type)
				if req != nil && req.WantReply {
					req.Reply(false, nil)
				}
			case <-lctx.Done():
				return nil
			}
		}
	})

	// Service the incoming Channel channel.
IncomingChannel:
	for {
		select {
		case <-lctx.Done():
			return nil
		case newChannel, more := <-chans:
			if !more {
				return nil
			}

			// Channels have a type, depending on the application level
			// protocol intended. In the case of an SFTP session, this is "subsystem"
			// with a payload string of "<length=4>sftp"
			logger.Debug("Incoming channel", "type", newChannel.ChannelType())
			if newChannel.ChannelType() != "session" {
				logger.Warn("Unknown channel type", "type", newChannel.ChannelType())
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue IncomingChannel
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return fmt.Errorf("Could not accept channel: %s", err)
			}
			logger.Debug("Channel accepted")
			go func() {
				<-lctx.Done()
				logger.Debug("Channel closed")
				channel.Close()
			}()

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "subsystem" request.
			g.Go(func() error {
				for {
					select {
					case <-lctx.Done():
						return nil
					case req, more := <-requests:
						if !more {
							return nil
						}
						logger.Debug("Incoming request", "type", req.Type)
						ok := false
						switch req.Type {
						case "subsystem":
							subs := string(req.Payload[4:])
							logger.Debug("Incoming request", "type", req.Type, "subsystem", subs)
							if subs == "sftp" {
								ok = true
							}
						}
						req.Reply(ok, nil)
					}
				}
			})
			dest, err := newDestination(lctx.Done(), dhost, dport, maxUps, logger)
			if err != nil {
				return fmt.Errorf("Could not setup the destination: %s", err)
			}
			root := SFTP2TCPHandler(dest, r, lctx.Done(), logger)
			server := sftp.NewRequestServer(channel, root)
			go func() {
				// close the server when the context is canceled
				// makes server.Serve() return
				<-lctx.Done()
				logger.Debug("server.Close() called")
				server.Close()
			}()
			logger.Debug("Serve()")
			errServe := server.Serve()
			logger.Debug("Serve() returned")
			if errServe == io.EOF {
				server.Close()
				logger.Info("SFTP client has left")
			} else if errServe != nil {
				logger.Warn("SFTP serve completed with error", "error", errServe)
			} else {
				logger.Info("SFTP serve completed without error")
			}
		}
	}
}

func main() {
	makeApp().Run(os.Args)
}
