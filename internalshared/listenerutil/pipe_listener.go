package listenerutil

import (
	"errors"
	"net"
	"sync/atomic"
)

type PipeListener struct {
	connections   chan net.Conn
	state         chan int
	isStateClosed uint32
}

func NewPipeListener() *PipeListener {
	pl := &PipeListener{}
	pl.connections = make(chan net.Conn)
	return pl
}

func (pl *PipeListener) Accept() (net.Conn, error) {
	select {
	case newConnection := <-pl.connections:
		return newConnection, nil
	case <-pl.state:
		return nil, errors.New("listener closed")
	}
}

func (pl *PipeListener) Close() error {
	if atomic.CompareAndSwapUint32(&pl.isStateClosed, 0, 1) {
		close(pl.state)
	}
	return nil
}

func (pl *PipeListener) Dial(network, addr string) (net.Conn, error) {
	select {
	case <-pl.state:
		return nil, errors.New("listener closed")
	default:
	}
	// Create an in memory transport
	serverSide, clientSide := net.Pipe()
	// Pass half to the server
	pl.connections <- serverSide
	// Return the other half to the client
	return clientSide, nil
}

type pipeAddr int

func (pipeAddr) Network() string {
	return "pipe"
}

func (pipeAddr) String() string {
	return "local"
}

func (pl *PipeListener) Addr() net.Addr {
	return pipeAddr(0)
}
