package main

import (
	"context"
	"fmt"
	"net"
	"os"
)

type tcpDestination struct {
	hostport   string
	maxUploads uint
	uploads    chan struct{}
	done       <-chan struct{}
}

// TODO: support round-robin list of hostports?
func newDestination(done <-chan struct{}, hostport string, maxUps uint) *tcpDestination {
	return &tcpDestination{
		hostport:   hostport,
		maxUploads: maxUps,
		uploads:    make(chan struct{}, maxUps),
		done:       done,
	}
}

func (d *tcpDestination) getConn() (net.Conn, error) {
	select {
	case <-d.done:
		return nil, context.Canceled
	case d.uploads <- struct{}{}:
		fmt.Fprintln(os.Stderr, "take conn!")
	}
	c, err := net.Dial("tcp", d.hostport)
	if err != nil {
		<-d.uploads
		fmt.Fprintln(os.Stderr, "release conn!")
		return nil, err
	}
	return c, nil
}

func (d *tcpDestination) releaseConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	err := conn.Close()
	<-d.uploads
	fmt.Fprintln(os.Stderr, "release conn!")
	return err
}
