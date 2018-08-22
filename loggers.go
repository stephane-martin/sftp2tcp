package main

import (
	"fmt"

	inlogger "github.com/InVisionApp/go-logger"
	"github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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
