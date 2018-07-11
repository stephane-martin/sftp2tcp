package main

import "net"

type tcpDestination struct {
	hostport string
}

func newDestination(hostport string) *tcpDestination {
	return &tcpDestination{
		hostport: hostport,
	}
}

func (d *tcpDestination) getConn() (net.Conn, error) {
	c, err := net.Dial("tcp", d.hostport)
	if err != nil {
		return nil, err
	}
	return c, nil
}
