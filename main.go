package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/inconshreveable/log15"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/sftp"
	"github.com/storozhukBM/verifier"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	cli "gopkg.in/urfave/cli.v1"
)

var Version string

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

// HealthCheckStatusListener is the implementation of the IStatusListener interface
type HealthCheckStatusListener struct {
	parentCtx context.Context
	cancel    context.CancelFunc
	logger    log15.Logger
	restart   func(context.Context)
	desthost  string
	m         *metrics
}

func proxy(c *cli.Context) error {
	host := strings.TrimSpace(c.GlobalString("desthost"))
	port := c.GlobalInt("destport")
	listenaddr := strings.TrimSpace(c.GlobalString("listenaddr"))
	listenport := c.GlobalInt("listenport")
	username := strings.TrimSpace(c.GlobalString("username"))
	password := strings.TrimSpace(c.GlobalString("password"))
	privateKeyPath := strings.TrimSpace(c.GlobalString("privatekey"))
	loglevel := strings.TrimSpace(c.GlobalString("loglevel"))
	toSyslog := c.GlobalBool("syslog")
	maxUploads := c.GlobalUint("maxuploads")
	maxInputConns := c.GlobalUint("maxinputconns")
	rate := c.GlobalUint64("maxuploadrate")
	httpport := c.GlobalInt("httpport")
	doHealthCheck := !c.GlobalBool("nohealthcheck")

	verify := verifier.New()
	verify.
		That(len(host) > 0, "Empty destination host").
		That(port > 0, "Destination port is not positive").
		That(len(listenaddr) > 0, "Empty listen address").
		That(listenport > 0, "Listen port is not positive").
		That(len(username) > 0, "Empty SSH username").
		That(len(password) > 0, "Empty SSH password").
		That(len(privateKeyPath) > 0, "Empty private key path")
	err := verify.GetError()
	if err != nil {
		return exitError("Arguments validation failed", err)
	}

	if len(loglevel) == 0 {
		loglevel = "info"
	}
	logger := getLogger(loglevel, toSyslog)

	privateKeyPath, err = homedir.Expand(privateKeyPath)
	if err != nil {
		return exitError("Error expanding private key path", err)
	}

	pkey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return exitError("Failed to read the private key", err)
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			logger.Info("Login", "user", meta.User())
			if meta.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", meta.User())
		},
	}

	private, err := ssh.ParsePrivateKey(pkey)
	if err != nil {
		return exitError("failed to parse the private key", err)
	}

	config.AddHostKey(private)

	m := newMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	g, lctx := errgroup.WithContext(
		context.WithValue(ctx, metricsKey, m),
	)

	dest, err := newDestination(lctx.Done(), host, port, maxUploads, m, logger)
	if err != nil {
		cancel()
		return fmt.Errorf("Could not setup the destination: %s", err)
	}

	healthCheckListener := &HealthCheckStatusListener{
		logger:    logger,
		parentCtx: lctx,
		m:         m,
		desthost:  host,
		restart: func(socketContext context.Context) {
			g.Go(func() error {
				err := startListening(lctx, socketContext, g, dest, listenaddr, listenport, host, port, maxInputConns, maxUploads, rate, config, logger)
				if err != nil {
					logger.Error("SSH listening error", "error", err)
				}
				return err
			})
		},
	}

	h := newHealth(host, port, logger)
	h.StatusListener = healthCheckListener
	h.StatusListener.HealthCheckRecovered(nil, 0, 0)
	if doHealthCheck {
		err := startHealthChecker(lctx, g, h)
		if err != nil {
			cancel()
			g.Wait()
			return exitError("Failed to start health checker", err)
		}
	}

	stopChan := make(chan os.Signal, 5)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	startHTTP(lctx, listenaddr, httpport, dest, m, h, stopChan, logger)

	go func() {
		// cancel the context when a signal is received
		<-stopChan
		cancel()
	}()

	_ = g.Wait()
	return nil
}

func startListening(ctx context.Context, socketCtx context.Context, g *errgroup.Group, dest *tcpDestination, host string, port int, dhost string, dport int, maxConns uint, maxUps uint, rate uint64, sshCfg *ssh.ServerConfig, l log15.Logger) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return err
	}
	l.Info("Listening for SSH connextions", "address", listener.Addr())
	err = acceptLoop(ctx, socketCtx, g, dest, listener, sshCfg, dhost, dport, maxConns, maxUps, rate, l)
	listener.Close()
	if err == context.Canceled {
		return nil
	}
	return err
}

func acceptLoop(ctx context.Context, socketCtx context.Context, g *errgroup.Group, dest *tcpDestination, listnr net.Listener, cfg *ssh.ServerConfig, dhost string, dport int, maxConns uint, maxUps uint, r uint64, l log15.Logger) error {
	conns := make(chan struct{}, maxConns)

	go func() {
		<-socketCtx.Done()
		listnr.Close()
	}()

	for {
		select {
		case <-socketCtx.Done():
			return context.Canceled
		case conns <- struct{}{}:
		}
		conn, err := listnr.Accept()
		if err != nil {
			<-conns
			select {
			case <-socketCtx.Done():
				return context.Canceled
			default:
				l.Debug("Close Accept()", "error", err)
				return err
			}
		}
		go func() {
			<-ctx.Done()
			conn.Close()
		}()
		g.Go(func() error {
			err := handleConnection(ctx, g, dest, conn, cfg, dhost, dport, maxUps, r, l)
			if err != nil && err != context.Canceled {
				l.Warn("Handle connection error", "error", err)
			}
			<-conns
			return nil
		})
	}
}

func handleConnection(ctx context.Context, g *errgroup.Group, dest *tcpDestination, nConn net.Conn, config *ssh.ServerConfig, dhost string, dport int, maxUps uint, r uint64, logger log15.Logger) error {
	h, _, _ := net.SplitHostPort(nConn.RemoteAddr().String())
	m := getMetrics(ctx)
	m.nbClientConnections.WithLabelValues(h).Inc()
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

			root := SFTP2TCPHandler(dest, r, lctx.Done(), m, logger)
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
