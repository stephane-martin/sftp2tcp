package main

import (
	"log/syslog"
	"os"

	"github.com/inconshreveable/log15"
)

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
