package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/inconshreveable/log15"
)

type roundrobin struct {
	hosts   []string
	current int32
	size    int
}

func newRoundRobin(name string) (*roundrobin, error) {
	try := net.ParseIP(name)
	if try != nil {
		return &roundrobin{
			hosts: []string{name},
			size:  1,
		}, nil
	}
	lookups, err := net.LookupIP(name)
	if err != nil {
		return nil, err
	}
	if len(lookups) == 0 {
		return nil, fmt.Errorf("DNS resolution returned no result")
	}
	hosts := make([]string, 0, len(lookups))
	for _, ip := range lookups {
		hosts = append(hosts, ip.String())
	}
	return &roundrobin{
		hosts: hosts,
		size:  len(hosts),
	}, nil
}

func (r *roundrobin) next() string {
	idx := int(atomic.AddInt32(&r.current, 1)) % r.size
	return r.hosts[idx]
}

type tcpDestination struct {
	round       *roundrobin
	port        int
	maxUploads  uint
	uploads     chan struct{}
	done        <-chan struct{}
	connections map[net.Conn]bool
	logger      log15.Logger
	sync.Mutex
}

func newDestination(done <-chan struct{}, host string, port int, maxUps uint, logger log15.Logger) (*tcpDestination, error) {
	round, err := newRoundRobin(host)
	if err != nil {
		return nil, err
	}
	d := &tcpDestination{
		round:       round,
		port:        port,
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
	return d, nil
}

func (d *tcpDestination) getConn() (net.Conn, error) {
	d.logger.Debug("getConn")
	select {
	case <-d.done:
		return nil, context.Canceled
	case d.uploads <- struct{}{}:
	}
	hostport := net.JoinHostPort(d.round.next(), fmt.Sprintf("%d", d.port))
	d.logger.Debug("Outgoing connection", "hostport", hostport)
	c, err := net.Dial("tcp", hostport)
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
