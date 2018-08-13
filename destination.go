package main

import (
	"context"
	"net"
	"sync"

	"github.com/inconshreveable/log15"
)

type tcpDestination struct {
	hostport    string
	maxUploads  uint
	uploads     chan struct{}
	done        <-chan struct{}
	connections map[net.Conn]bool
	logger      log15.Logger
	sync.Mutex
}

// TODO: support round-robin list of hostports?
func newDestination(done <-chan struct{}, hostport string, maxUps uint, logger log15.Logger) *tcpDestination {
	d := &tcpDestination{
		hostport:    hostport,
		maxUploads:  maxUps,
		uploads:     make(chan struct{}, maxUps),
		done:        done,
		connections: make(map[net.Conn]bool),
		logger:      logger,
	}
	go func() {
		<-done
		d.logger.Debug("releaseAllConns")
		d.Lock()
		for c := range d.connections {
			d.logger.Debug("releaseAllConns: release one connection")
			c.Close()
			delete(d.connections, c)
			<-d.uploads
		}
		d.Unlock()
	}()
	return d
}

func (d *tcpDestination) getConn() (net.Conn, error) {
	d.logger.Debug("getConn")
	select {
	case <-d.done:
		return nil, context.Canceled
	case d.uploads <- struct{}{}:
	}
	c, err := net.Dial("tcp", d.hostport)
	if err != nil {
		<-d.uploads
		return nil, err
	}
	d.Lock()
	d.connections[c] = true
	d.Unlock()
	return c, nil
}

func (d *tcpDestination) releaseConn(c net.Conn) error {
	d.logger.Debug("releaseConn")
	if c == nil {
		return nil
	}
	var err error
	d.Lock()
	if _, ok := d.connections[c]; ok {
		err = c.Close()
		delete(d.connections, c)
		<-d.uploads
	}
	d.Unlock()
	return err
}
