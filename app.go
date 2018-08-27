package main

import (
	"fmt"

	cli "gopkg.in/urfave/cli.v1"
)

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
		cli.IntFlag{
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
		cli.BoolFlag{
			Name:   "nohealthcheck",
			Usage:  "Do not perform regular health checks about the remote TCP service",
			EnvVar: "SFTP2TCP_NOHEALTCHECK",
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
